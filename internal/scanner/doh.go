package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

var dohHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	},
}

// QueryDoH sends a DNS query to a DoH resolver URL and returns the response.
func QueryDoH(resolverURL, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
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

	if reply.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	return reply, true
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
	r, ok := QueryDoH(resolverURL, domain, dns.TypeNS, timeout)
	if !ok {
		return nil, false
	}
	var hosts []string
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			hosts = append(hosts, ns.Ns)
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
		var consecFail int

		for i := 0; i < count; i++ {
			start := time.Now()
			if QueryDoHA(url, domain, timeout) {
				ms := float64(time.Since(start).Microseconds()) / 1000.0
				successes = append(successes, ms)
				consecFail = 0
			} else {
				consecFail++
				if consecFail >= maxConsecFail {
					return false, nil
				}
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

// DoHTunnelCheck tests NS delegation via DoH resolver.
func DoHTunnelCheck(domain string, count int) CheckFunc {
	return func(url string, timeout time.Duration) (bool, Metrics) {
		var successes []float64
		var consecFail int

		for i := 0; i < count; i++ {
			start := time.Now()

			hosts, ok := QueryDoHNS(url, domain, timeout)
			if !ok || len(hosts) == 0 {
				consecFail++
				if consecFail >= maxConsecFail {
					return false, nil
				}
				continue
			}

			// Verify glue record via same DoH resolver
			nsHost := hosts[0]
			if last := len(nsHost) - 1; last >= 0 && nsHost[last] == '.' {
				nsHost = nsHost[:last]
			}
			if !QueryDoHA(url, nsHost, timeout) {
				consecFail++
				if consecFail >= maxConsecFail {
					return false, nil
				}
				continue
			}

			ms := float64(time.Since(start).Microseconds()) / 1000.0
			successes = append(successes, ms)
			consecFail = 0
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

// DoHDnsttCheck runs an e2e test using dnstt-client in DoH mode.
func DoHDnsttCheck(domain, pubkey, testURL string, ports chan int) CheckFunc {
	return func(url string, timeout time.Duration) (bool, Metrics) {
		port := <-ports
		defer func() { ports <- port }()

		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := execCommandContext(ctx, "dnstt-client",
			"-doh", url,
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
		}()

		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return false, nil
		}

		if !testSOCKS(ctx, port, testURL) {
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}
