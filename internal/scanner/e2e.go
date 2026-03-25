package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DnsttMTU caps the upstream DNS query payload size (dnstt-client -mtu flag).
// 0 means use dnstt-client's default (maximum capacity).
var DnsttMTU int

// SOCKS5Opts holds optional SOCKS5 authentication credentials and the
// target host:port used for the CONNECT probe.
type SOCKS5Opts struct {
	User        string // empty = no-auth (method 0x00)
	Pass        string
	ConnectAddr string // default "example.com:80"; use "host:22" for SSH probe
}

// socks5Handshake performs SOCKS5 auth negotiation on conn.
// If opts.User is empty, uses no-auth (0x00).
// If opts.User is set, uses username/password auth (0x02, RFC 1929).
func socks5Handshake(conn net.Conn, opts SOCKS5Opts) error {
	if opts.User != "" {
		// Offer username/password method (0x02)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			return err
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return err
		}
		if resp[0] != 0x05 || resp[1] != 0x02 {
			return fmt.Errorf("socks5: server rejected username/password method")
		}
		// RFC 1929 sub-negotiation: VER=0x01, ULEN, USER, PLEN, PASS
		authReq := make([]byte, 0, 3+len(opts.User)+len(opts.Pass))
		authReq = append(authReq, 0x01)
		authReq = append(authReq, byte(len(opts.User)))
		authReq = append(authReq, []byte(opts.User)...)
		authReq = append(authReq, byte(len(opts.Pass)))
		authReq = append(authReq, []byte(opts.Pass)...)
		if _, err := conn.Write(authReq); err != nil {
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5: authentication failed (status %d)", authResp[1])
		}
		return nil
	}
	// No-auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: invalid server version %d", resp[0])
	}
	return nil
}

// socks5Connect sends a SOCKS5 CONNECT request to the given host:port.
func socks5Connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03) // VER, CMD=connect, RSV, ATYP=domain
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	_, err = conn.Write(req)
	return err
}

func PortPool(base, count int) chan int {
	ch := make(chan int, count)
	for i := 0; i < count; i++ {
		ch <- base + i
	}
	return ch
}

func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// e2eDiag stores the first e2e failure diagnostic message so both CLI and
// TUI can display it. Only the first failure is captured (via sync.Once).
var e2eDiag struct {
	mu  sync.Mutex
	msg string
}

// E2EDiagnostic returns the first e2e failure diagnostic, or "".
func E2EDiagnostic() string {
	e2eDiag.mu.Lock()
	defer e2eDiag.mu.Unlock()
	return e2eDiag.msg
}

// ResetE2EDiagnostic clears the stored diagnostic so a fresh scan starts clean.
func ResetE2EDiagnostic() {
	e2eDiag.mu.Lock()
	e2eDiag.msg = ""
	e2eDiag.mu.Unlock()
}

func setDiag(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e2eDiag.mu.Lock()
	if e2eDiag.msg == "" {
		e2eDiag.msg = msg
	}
	e2eDiag.mu.Unlock()
}

// DnsttCheckBin verifies the dnstt Noise handshake completes through a resolver.
func DnsttCheckBin(bin, domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	return dnsttCheck(bin, domain, pubkey, ports, opts)
}

func DnsttCheck(domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	return dnsttCheck("dnstt-client", domain, pubkey, ports, opts)
}

func dnsttCheck(bin, domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}

		start := time.Now()

		var stderrBuf bytes.Buffer
		args := []string{
			"-udp", net.JoinHostPort(ip, "53"),
			"-pubkey", pubkey,
		}
		if DnsttMTU > 0 {
			args = append(args, "-mtu", strconv.Itoa(DnsttMTU))
		}
		args = append(args, domain, fmt.Sprintf("127.0.0.1:%d", port))
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			ports <- port
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/dnstt: cannot start %s: %v", bin, err)
			}
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			time.Sleep(300 * time.Millisecond)
			ports <- port
		}()

		// Wait for SOCKS port to open, then do a SOCKS5 handshake through
		// the tunnel. This is much faster than spawning curl — we just need
		// to verify that data flows bidirectionally through the DNS tunnel.
		if !waitAndTestSOCKS5Connect(ctx, port, exited, opts) {
			if diagOnce.CompareAndSwap(false, true) {
				processExitedEarly := false
				select {
				case <-exited:
					processExitedEarly = true
				default:
				}
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("e2e/dnstt first failure (ip=%s): dnstt-client stderr: %s", ip, truncate(stderr, 300))
				} else if processExitedEarly {
					setDiag("e2e/dnstt first failure (ip=%s): dnstt-client exited early with no stderr", ip)
				} else {
					setDiag("e2e/dnstt first failure (ip=%s): SOCKS5 handshake through tunnel timed out within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}

// waitAndTestSOCKS5Connect waits for the SOCKS port to open, performs a
// SOCKS5 auth handshake, then sends a SOCKS5 CONNECT request to a remote
// host. The CONNECT request travels through the DNS tunnel:
//
//	client → dnstt-client → DNS tunnel → resolver → dnstt-server → connect attempt → reply back
//
// Getting ANY SOCKS5 reply (even a failure code like 0x01) proves
// bidirectional data flow through the DNS tunnel. We don't require 0x00
// (success) because the server may not have internet access — but the
// reply itself proves the tunnel carried data both ways.
func waitAndTestSOCKS5Connect(ctx context.Context, port int, exited <-chan struct{}, opts SOCKS5Opts) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	connectAddr := opts.ConnectAddr
	if connectAddr == "" {
		connectAddr = "example.com:80"
	}

	for {
		select {
		case <-ctx.Done():
			return false
		case <-exited:
			return false
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			select {
			case <-ctx.Done():
				return false
			case <-exited:
				return false
			case <-time.After(300 * time.Millisecond):
			}
			continue
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}

		// Step 1: SOCKS5 auth (supports no-auth and username/password)
		if err = socks5Handshake(conn, opts); err != nil {
			conn.Close()
			return false
		}

		// Step 2: SOCKS5 CONNECT — goes through the DNS tunnel
		if err = socks5Connect(conn, connectAddr); err != nil {
			conn.Close()
			return false
		}

		// Step 3: Read SOCKS5 CONNECT reply (at least 4 bytes: VER, REP, RSV, ATYP)
		// Any valid SOCKS5 reply proves the tunnel works — even failure codes
		// like 0x01 (general failure) mean data traveled through the tunnel.
		connectResp := make([]byte, 4)
		if _, err = io.ReadFull(conn, connectResp); err != nil {
			conn.Close()
			return false
		}
		if connectResp[0] != 0x05 {
			conn.Close()
			return false
		}

		// For SSH targets (port 22): read and verify the SSH banner
		_, portStr, _ := net.SplitHostPort(connectAddr)
		if portStr == "22" && connectResp[1] == 0x00 {
			// Drain CONNECT reply address
			drainSOCKS5Addr(conn, connectResp[3])
			// Read SSH banner (e.g. "SSH-2.0-OpenSSH_8.9")
			banner := make([]byte, 32)
			n, _ := conn.Read(banner)
			conn.Close()
			return n >= 4 && string(banner[:4]) == "SSH-"
		}

		conn.Close()
		return true
	}
}

// drainSOCKS5Addr reads and discards the address portion of a SOCKS5 reply.
func drainSOCKS5Addr(conn net.Conn, atyp byte) {
	switch atyp {
	case 0x01:
		io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err == nil {
			io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
		}
	case 0x04:
		io.ReadFull(conn, make([]byte, 18))
	}
}

// SlipstreamCheckBin is like SlipstreamCheck but uses an explicit binary path.
func SlipstreamCheckBin(bin, domain, certPath string, ports chan int, opts SOCKS5Opts) CheckFunc {
	return slipstreamCheck(bin, domain, certPath, ports, opts)
}

func SlipstreamCheck(domain, certPath string, ports chan int, opts SOCKS5Opts) CheckFunc {
	return slipstreamCheck("slipstream-client", domain, certPath, ports, opts)
}

func slipstreamCheck(bin, domain, certPath string, ports chan int, opts SOCKS5Opts) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}

		start := time.Now()

		args := []string{
			"-d", domain,
			"-r", net.JoinHostPort(ip, "53"),
			"-l", fmt.Sprintf("%d", port),
		}
		if certPath != "" {
			args = append(args, "--cert", certPath)
		}
		var stderrBuf bytes.Buffer
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			ports <- port
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/slipstream: cannot start %s: %v", bin, err)
			}
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			time.Sleep(300 * time.Millisecond)
			ports <- port
		}()

		if !waitAndTestSOCKS5Connect(ctx, port, exited, opts) {
			if diagOnce.CompareAndSwap(false, true) {
				processExitedEarly := false
				select {
				case <-exited:
					processExitedEarly = true
				default:
				}
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("e2e/slipstream first failure (ip=%s): stderr: %s", ip, truncate(stderr, 300))
				} else if processExitedEarly {
					setDiag("e2e/slipstream first failure (ip=%s): process exited early with no stderr", ip)
				} else {
					setDiag("e2e/slipstream first failure (ip=%s): SOCKS5 handshake through tunnel timed out within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}


// ThroughputCheckBin tests actual data transfer through the DNS tunnel by
// performing an HTTP GET request via the SOCKS5 proxy. This goes beyond the
// e2e handshake test — it verifies that meaningful payload (1-2KB+) flows
// bidirectionally through the tunnel.
func ThroughputCheckBin(bin, domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}

		start := time.Now()

		var stderrBuf bytes.Buffer
		args := []string{
			"-udp", net.JoinHostPort(ip, "53"),
			"-pubkey", pubkey,
		}
		if DnsttMTU > 0 {
			args = append(args, "-mtu", strconv.Itoa(DnsttMTU))
		}
		args = append(args, domain, fmt.Sprintf("127.0.0.1:%d", port))
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			ports <- port
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			time.Sleep(300 * time.Millisecond)
			ports <- port
		}()

		transferred, ok := waitAndTestThroughput(ctx, port, exited, opts)
		if !ok {
			if diagOnce.CompareAndSwap(false, true) {
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("throughput first failure (ip=%s): %s", ip, truncate(stderr, 300))
				} else {
					setDiag("throughput first failure (ip=%s): could not transfer data within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{
			"throughput_bytes": float64(transferred),
			"throughput_ms":   ms,
		}
	}
}

// waitAndTestThroughput waits for the SOCKS port to open, performs a full
// SOCKS5 CONNECT to example.com:80, sends an HTTP GET request, and reads
// the response. This proves that real data (not just a handshake) can flow
// through the DNS tunnel.
func waitAndTestThroughput(ctx context.Context, port int, exited <-chan struct{}, opts SOCKS5Opts) (int, bool) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	for {
		select {
		case <-ctx.Done():
			return 0, false
		case <-exited:
			return 0, false
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			select {
			case <-ctx.Done():
				return 0, false
			case <-exited:
				return 0, false
			case <-time.After(300 * time.Millisecond):
			}
			continue
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}

		// Step 1: SOCKS5 auth (supports no-auth and username/password)
		if err = socks5Handshake(conn, opts); err != nil {
			conn.Close()
			return 0, false
		}

		// Step 2: SOCKS5 CONNECT to example.com:80
		if err = socks5Connect(conn, "example.com:80"); err != nil {
			conn.Close()
			return 0, false
		}

		// Step 3: Read SOCKS5 CONNECT reply header
		hdr := make([]byte, 4)
		if _, err = io.ReadFull(conn, hdr); err != nil {
			conn.Close()
			return 0, false
		}
		if hdr[0] != 0x05 || hdr[1] != 0x00 {
			conn.Close()
			return 0, false
		}
		drainSOCKS5Addr(conn, hdr[3])

		// Step 4: Send HTTP GET request through the tunnel
		httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
		if _, err = conn.Write([]byte(httpReq)); err != nil {
			conn.Close()
			return 0, false
		}

		// Step 5: Read HTTP response
		buf := make([]byte, 65536)
		totalRead := 0
		for {
			n, readErr := conn.Read(buf[totalRead:])
			totalRead += n
			if readErr != nil || totalRead >= len(buf) {
				break
			}
		}
		conn.Close()

		if totalRead < 100 {
			return totalRead, false
		}
		return totalRead, true
	}
}

func truncate(s string, maxLen int) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

