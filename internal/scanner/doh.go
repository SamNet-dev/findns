package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var dohHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	},
}

// queryDoHRaw sends a DNS query to a DoH resolver and returns the response
// regardless of Rcode, so callers can inspect Authority section.
func queryDoHRaw(resolverURL, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	packed, err := m.Pack()
	if err != nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", resolverURL, bytes.NewReader(packed))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, false
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, false
	}

	return reply, true
}

// QueryDoH sends a DNS query to a DoH resolver URL and returns the response.
func QueryDoH(resolverURL, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	r, ok := queryDoHRaw(resolverURL, domain, qtype, timeout)
	if !ok || r.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	return r, true
}

// QueryDoHA tests if a DoH resolver can resolve an A record.
func QueryDoHA(resolverURL, domain string, timeout time.Duration) bool {
	r, ok := QueryDoH(resolverURL, domain, dns.TypeA, timeout)
	if !ok {
		return false
	}
	return len(r.Answer) > 0
}

// QueryDoHNS queries NS records via DoH.
func QueryDoHNS(resolverURL, domain string, timeout time.Duration) ([]string, bool) {
	r, ok := queryDoHRaw(resolverURL, domain, dns.TypeNS, timeout)
	if !ok {
		return nil, false
	}
	var hosts []string
	// Check Answer section first
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			hosts = append(hosts, ns.Ns)
		}
	}
	// For subdomain delegations, NS records are often in the Authority section
	if len(hosts) == 0 {
		for _, ans := range r.Ns {
			if ns, ok := ans.(*dns.NS); ok {
				hosts = append(hosts, ns.Ns)
			}
		}
	}
	if len(hosts) == 0 {
		return nil, false
	}
	return hosts, true
}

// DoHResolveCheck tests if a DoH resolver URL can resolve a domain.
func DoHResolveCheck(domain string, count int) CheckFunc {
	return func(url string, timeout time.Duration) (bool, Metrics) {
		var successes []float64

		for i := 0; i < count; i++ {
			start := time.Now()
			if QueryDoHA(url, domain, timeout) {
				ms := float64(time.Since(start).Microseconds()) / 1000.0
				successes = append(successes, ms)
			}
		}

		if len(successes) == 0 {
			return false, nil
		}

		var sum float64
		for _, v := range successes {
			sum += v
		}
		return true, Metrics{"resolve_ms": roundMs(sum / float64(len(successes)))}
	}
}

// DoHTunnelCheck tests if a DoH resolver can forward queries to the tunnel domain.
func DoHTunnelCheck(domain string, count int) CheckFunc {
	return func(url string, timeout time.Duration) (bool, Metrics) {
		var successes []float64

		for i := 0; i < count; i++ {
			start := time.Now()

			// Query a random subdomain TXT record — same as what dnstt-client does.
			qname := fmt.Sprintf("tun-%s.%s", randLabel(8), domain)
			r, ok := queryDoHRaw(url, qname, dns.TypeTXT, timeout)
			if !ok || r == nil {
				continue
			}
			if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
				continue
			}

			ms := float64(time.Since(start).Microseconds()) / 1000.0
			successes = append(successes, ms)
		}

		if len(successes) == 0 {
			return false, nil
		}

		var sum float64
		for _, v := range successes {
			sum += v
		}
		return true, Metrics{"resolve_ms": roundMs(sum / float64(len(successes)))}
	}
}

// DoHDnsttCheckBin is like DoHDnsttCheck but uses an explicit binary path.
func DoHDnsttCheckBin(bin, domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	return dohDnsttCheck(bin, domain, pubkey, ports, opts)
}

// DoHDnsttCheck runs an e2e test using dnstt-client in DoH mode.
func DoHDnsttCheck(domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	return dohDnsttCheck("dnstt-client", domain, pubkey, ports, opts)
}

func dohDnsttCheck(bin, domain, pubkey string, ports chan int, opts SOCKS5Opts) CheckFunc {
	var diagOnce atomic.Bool

	return func(url string, timeout time.Duration) (bool, Metrics) {
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
			"-doh", url,
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
				setDiag("doh/e2e: cannot start %s: %v", bin, err)
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
					setDiag("doh/e2e first failure (url=%s): dnstt-client stderr: %s", url, truncate(stderr, 300))
				} else if processExitedEarly {
					setDiag("doh/e2e first failure (url=%s): dnstt-client exited early with no stderr", url)
				} else {
					setDiag("doh/e2e first failure (url=%s): SOCKS5 handshake through tunnel timed out within %v", url, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}
