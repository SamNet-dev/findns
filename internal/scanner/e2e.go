package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultTestURL = "http://httpbin.org/ip"

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

func effectiveTestURL(testURL string) string {
	if testURL == "" {
		return defaultTestURL
	}
	return testURL
}

// DnsttCheckBin is like DnsttCheck but uses an explicit binary path.
func DnsttCheckBin(bin, domain, pubkey, testURL, proxyAuth string, ports chan int) CheckFunc {
	return dnsttCheck(bin, domain, pubkey, testURL, proxyAuth, ports)
}

func DnsttCheck(domain, pubkey, testURL string, ports chan int) CheckFunc {
	return dnsttCheck("dnstt-client", domain, pubkey, testURL, "", ports)
}

func dnsttCheck(bin, domain, pubkey, testURL, proxyAuth string, ports chan int) CheckFunc {
	testURL = effectiveTestURL(testURL)
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
		cmd := execCommandContext(ctx, bin,
			"-udp", net.JoinHostPort(ip, "53"),
			"-pubkey", pubkey,
			domain,
			fmt.Sprintf("127.0.0.1:%d", port))
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

		if !waitAndTestSOCKS(ctx, port, testURL, proxyAuth, exited, timeout) {
			if diagOnce.CompareAndSwap(false, true) {
				// Check if process exited on its own before we kill it
				processExitedEarly := false
				select {
				case <-exited:
					processExitedEarly = true
				default:
				}
				// Kill and wait so stderr pipe is fully closed before reading
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
					setDiag("e2e/dnstt first failure (ip=%s): curl could not get HTTP 200 through SOCKS within %v (test-url=%s)", ip, timeout, testURL)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}

// SlipstreamCheckBin is like SlipstreamCheck but uses an explicit binary path.
func SlipstreamCheckBin(bin, domain, certPath, testURL, proxyAuth string, ports chan int) CheckFunc {
	return slipstreamCheck(bin, domain, certPath, testURL, proxyAuth, ports)
}

func SlipstreamCheck(domain, certPath, testURL string, ports chan int) CheckFunc {
	return slipstreamCheck("slipstream-client", domain, certPath, testURL, "", ports)
}

func slipstreamCheck(bin, domain, certPath, testURL, proxyAuth string, ports chan int) CheckFunc {
	testURL = effectiveTestURL(testURL)
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

		if !waitAndTestSOCKS(ctx, port, testURL, proxyAuth, exited, timeout) {
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

func nullDevice() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

// waitAndTestSOCKS waits for the SOCKS port to accept connections, then
// retries the HTTP test via curl until it succeeds or the context expires.
// The exited channel signals that the tunnel process has died early.
// totalTimeout is used to compute per-attempt curl timeouts so that
// multiple retries fit within the budget.
func waitAndTestSOCKS(ctx context.Context, port int, testURL, proxyAuth string, exited <-chan struct{}, totalTimeout time.Duration) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Compute per-attempt curl timeout: aim for 3 attempts minimum.
	// Reserve ~2s for Phase 1, then divide the rest by 3.
	totalSec := int(totalTimeout.Seconds())
	curlMaxTime := (totalSec - 2) / 3
	if curlMaxTime < 3 {
		curlMaxTime = 3
	}
	if curlMaxTime > 8 {
		curlMaxTime = 8
	}
	// Never exceed the total timeout budget
	if curlMaxTime > totalSec {
		curlMaxTime = totalSec
	}
	// connect-timeout should be less than max-time
	curlConnTimeout := curlMaxTime - 1
	if curlConnTimeout < 2 {
		curlConnTimeout = 2
	}

	// Phase 1: wait for SOCKS port to start listening (poll every 300ms).
	// Also bail if the tunnel process dies — no point waiting for a dead process.
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

	// Phase 2: port is open — retry curl until success or timeout.
	// The port may be listening before the tunnel is fully negotiated, so
	// the first curl attempt often fails with a SOCKS error.
	for {
		select {
		case <-exited:
			return false
		default:
		}
		if testSOCKS(ctx, port, testURL, proxyAuth, curlConnTimeout, curlMaxTime) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-exited:
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func testSOCKS(ctx context.Context, port int, testURL, proxyAuth string, connTimeout, maxTime int) bool {
	args := []string{
		"-x", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"--connect-timeout", strconv.Itoa(connTimeout),
		"--max-time", strconv.Itoa(maxTime),
		"-L", // follow redirects
		"-s", "-o", nullDevice(), "-w", "%{http_code}",
	}
	if proxyAuth != "" {
		args = append(args, "--proxy-user", proxyAuth)
	}
	args = append(args, testURL)
	cmd := execCommandContext(ctx, "curl", args...)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	code := strings.TrimSpace(string(output))
	// Accept any 2xx status — not just 200
	if len(code) == 3 && code[0] == '2' {
		return true
	}
	return false
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

// preflightResolvers are tried in order for the e2e preflight check.
// Uses the same list as nsResolvers in dns.go for maximum coverage.
var preflightResolvers = []string{
	"8.8.8.8",         // Google
	"1.1.1.1",         // Cloudflare
	"9.9.9.9",         // Quad9
	"208.67.222.222",  // OpenDNS
	"76.76.2.0",       // ControlD
	"94.140.14.14",    // AdGuard
	"185.228.168.9",   // CleanBrowsing
	"76.76.19.19",     // Alternate DNS
	"149.112.112.112", // Quad9 secondary
	"8.26.56.26",      // Comodo Secure
	"156.154.70.1",    // Neustar/UltraDNS
	"178.22.122.100",  // Shecan (Iran)
	"185.51.200.2",    // DNS.sb (anycast)
	"195.175.39.39",   // Turk Telekom (Turkey)
	"80.80.80.80",     // Freenom/Level3 (Turkey/EU)
	"217.218.127.127", // TCI (Iran)
	"85.132.75.12",    // AzOnline (Azerbaijan)
	"213.42.20.20",    // Etisalat DNS (UAE)
}

// PreflightE2EResult holds the outcome of a preflight e2e test.
type PreflightE2EResult struct {
	OK       bool
	Resolver string // which resolver worked (or last tried)
	Stderr   string // dnstt-client stderr on failure
	Err      string // human-readable error
}

// PreflightE2E runs e2e tunnel tests against multiple resolvers in parallel.
// Returns as soon as any one resolver succeeds. If all fail within the timeout,
// returns an error. This handles blocked resolvers (e.g. Google in Iran) by
// racing them — whichever resolver is reachable responds first.
func PreflightE2E(bin, domain, pubkey, testURL, proxyAuth string, timeout time.Duration) PreflightE2EResult {
	return PreflightE2EContext(context.Background(), bin, domain, pubkey, testURL, proxyAuth, timeout)
}

// PreflightE2EContext is like PreflightE2E but accepts a parent context for cancellation.
func PreflightE2EContext(parent context.Context, bin, domain, pubkey, testURL, proxyAuth string, timeout time.Duration) PreflightE2EResult {
	if testURL == "" {
		testURL = defaultTestURL
	}

	// Each parallel test needs its own port
	basePort := 29900
	results := make(chan PreflightE2EResult, len(preflightResolvers))

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	for i, resolver := range preflightResolvers {
		go func(res string, port int) {
			r := preflightSingle(ctx, bin, res, domain, pubkey, testURL, proxyAuth, port, timeout)
			results <- r
		}(resolver, basePort+i)
	}

	// Wait for first success or all failures
	failures := 0
	for {
		select {
		case r := <-results:
			if r.OK {
				cancel() // stop remaining goroutines
				return r
			}
			failures++
			if failures >= len(preflightResolvers) {
				return PreflightE2EResult{
					OK:  false,
					Err: "tunnel test failed via all resolvers — dnstt-server may not be running, or all resolvers are blocked in your region",
				}
			}
		case <-ctx.Done():
			return PreflightE2EResult{
				OK:  false,
				Err: "tunnel preflight timed out — dnstt-server may not be running, or resolvers are blocked in your region",
			}
		}
	}
}

func preflightSingle(parent context.Context, bin, resolver, domain, pubkey, testURL, proxyAuth string, port int, timeout time.Duration) PreflightE2EResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var stderrBuf bytes.Buffer
	cmd := execCommandContext(ctx, bin,
		"-udp", net.JoinHostPort(resolver, "53"),
		"-pubkey", pubkey,
		domain,
		fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return PreflightE2EResult{Resolver: resolver, Err: fmt.Sprintf("cannot start %s: %v", bin, err)}
	}

	exited := make(chan struct{})
	go func() {
		cmd.Wait()
		close(exited)
	}()

	// cleanup: kill process and wait for exit before returning
	cleanup := func() {
		cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}

	if waitAndTestSOCKS(ctx, port, testURL, proxyAuth, exited, timeout) {
		cleanup()
		return PreflightE2EResult{OK: true, Resolver: resolver}
	}

	// Kill and wait to safely read stderr
	cleanup()
	stderr := strings.TrimSpace(stderrBuf.String())
	if stderr != "" {
		return PreflightE2EResult{Resolver: resolver, Stderr: truncate(stderr, 300), Err: "dnstt-client error: " + truncate(stderr, 200)}
	}
	return PreflightE2EResult{Resolver: resolver, Err: fmt.Sprintf("tunnel via %s: no HTTP response within %v", resolver, timeout)}
}
