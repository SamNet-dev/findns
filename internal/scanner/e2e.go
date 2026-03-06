package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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

// DnsttCheckBin is like DnsttCheck but uses an explicit binary path.
func DnsttCheckBin(bin, domain, pubkey, testURL, proxyAuth string, ports chan int) CheckFunc {
	return dnsttCheck(bin, domain, pubkey, testURL, proxyAuth, ports)
}

func DnsttCheck(domain, pubkey, testURL string, ports chan int) CheckFunc {
	return dnsttCheck("dnstt-client", domain, pubkey, testURL, "", ports)
}

func dnsttCheck(bin, domain, pubkey, testURL, proxyAuth string, ports chan int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}
		defer func() { ports <- port }()

		start := time.Now()

		cmd := execCommandContext(ctx, bin,
			"-udp", net.JoinHostPort(ip, "53"),
			"-pubkey", pubkey,
			domain,
			fmt.Sprintf("127.0.0.1:%d", port))
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return false, nil
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
			// Brief pause so OS can release the port before it's reused
			time.Sleep(100 * time.Millisecond)
		}()

		// Wait for subprocess to start, but cap at 1/3 of timeout
		startupWait := timeout / 3
		if startupWait > 2*time.Second {
			startupWait = 2 * time.Second
		}
		select {
		case <-time.After(startupWait):
		case <-ctx.Done():
			return false, nil
		}

		if !testSOCKS(ctx, port, testURL, proxyAuth) {
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
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}
		defer func() { ports <- port }()

		start := time.Now()

		args := []string{
			"-d", domain,
			"-r", net.JoinHostPort(ip, "53"),
			"-l", fmt.Sprintf("%d", port),
		}
		if certPath != "" {
			args = append(args, "--cert", certPath)
		}
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return false, nil
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
			time.Sleep(100 * time.Millisecond)
		}()

		// Wait for subprocess to start, but cap at 1/3 of timeout
		startupWait := timeout / 3
		if startupWait > 2*time.Second {
			startupWait = 2 * time.Second
		}
		select {
		case <-time.After(startupWait):
		case <-ctx.Done():
			return false, nil
		}

		if !testSOCKS(ctx, port, testURL, proxyAuth) {
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

func testSOCKS(ctx context.Context, port int, testURL, proxyAuth string) bool {
	args := []string{
		"-x", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
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
	return strings.TrimSpace(string(output)) == "200"
}
