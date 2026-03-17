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
func DnsttCheckBin(bin, domain, pubkey string, ports chan int) CheckFunc {
	return dnsttCheck(bin, domain, pubkey, ports)
}

func DnsttCheck(domain, pubkey string, ports chan int) CheckFunc {
	return dnsttCheck("dnstt-client", domain, pubkey, ports)
}

func dnsttCheck(bin, domain, pubkey string, ports chan int) CheckFunc {
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
		if !waitAndTestSOCKS5Auth(ctx, port, exited) {
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

// waitAndTestSOCKS5Auth waits for the SOCKS port to open, then performs a
// SOCKS5 auth handshake. In dnstt, the SOCKS protocol is handled by a proxy
// on the server side — so the auth bytes travel through the DNS tunnel and
// the reply comes back through it. Getting the 2-byte auth reply proves
// bidirectional data flow through the DNS tunnel. This is the minimum
// possible test: 3 bytes up, 2 bytes back, one tunnel round-trip.
func waitAndTestSOCKS5Auth(ctx context.Context, port int, exited <-chan struct{}) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Wait for SOCKS port to start listening.
	for {
		select {
		case <-ctx.Done():
			return false
		case <-exited:
			return false
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-exited:
			return false
		case <-time.After(300 * time.Millisecond):
		}
	}

	// Send SOCKS5 auth and wait for reply through the tunnel.
	// Single attempt — the DNS tunnel round-trip at MTU 50 can take
	// 5-10 seconds, so retrying wastes the timeout budget.
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// SOCKS5 auth: version=5, 1 method, no-auth(0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return false
	}
	// Any valid SOCKS5 reply (0x05, 0x00) proves the tunnel works.
	return authResp[0] == 0x05
}

// SlipstreamCheckBin is like SlipstreamCheck but uses an explicit binary path.
func SlipstreamCheckBin(bin, domain, certPath string, ports chan int) CheckFunc {
	return slipstreamCheck(bin, domain, certPath, ports)
}

func SlipstreamCheck(domain, certPath string, ports chan int) CheckFunc {
	return slipstreamCheck("slipstream-client", domain, certPath, ports)
}

func slipstreamCheck(bin, domain, certPath string, ports chan int) CheckFunc {
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

		if !waitAndTestSOCKS5Auth(ctx, port, exited) {
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
					setDiag("e2e/slipstream first failure (ip=%s): curl could not get HTTP 200 through SOCKS within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}

// DnsttSOCKSCheckBin is a fast e2e check: it only verifies that dnstt-client
// opens the SOCKS port (i.e. the Noise handshake completes). No curl/HTTP test.
// This is much faster than the full e2e check and suitable for testing all resolvers.
func DnsttSOCKSCheckBin(bin, domain, pubkey string, ports chan int) CheckFunc {
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
				setDiag("e2e/socks: cannot start %s: %v", bin, err)
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

		// Just wait for SOCKS port to accept a TCP connection
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		for {
			select {
			case <-ctx.Done():
				if diagOnce.CompareAndSwap(false, true) {
					cmd.Process.Kill()
					select {
					case <-exited:
					case <-time.After(2 * time.Second):
					}
					stderr := strings.TrimSpace(stderrBuf.String())
					if stderr != "" {
						setDiag("e2e/socks first failure (ip=%s): dnstt-client stderr: %s", ip, truncate(stderr, 300))
					} else {
						setDiag("e2e/socks first failure (ip=%s): SOCKS port did not open within %v", ip, timeout)
					}
				}
				return false, nil
			case <-exited:
				if diagOnce.CompareAndSwap(false, true) {
					stderr := strings.TrimSpace(stderrBuf.String())
					if stderr != "" {
						setDiag("e2e/socks first failure (ip=%s): dnstt-client exited early: %s", ip, truncate(stderr, 300))
					} else {
						setDiag("e2e/socks first failure (ip=%s): dnstt-client exited early with no stderr", ip)
					}
				}
				return false, nil
			default:
			}
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
				return true, Metrics{"socks_ms": ms}
			}
			select {
			case <-ctx.Done():
				return false, nil
			case <-exited:
				return false, nil
			case <-time.After(300 * time.Millisecond):
			}
		}
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

