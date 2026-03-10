package scanner

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// queryRaw sends a DNS query and handles EDNS0 + TCP fallback on truncation.
// Returns the response regardless of Rcode, so callers can inspect Authority section.
func queryRaw(resolver, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)

	addr := net.JoinHostPort(resolver, "53")

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout

	// Use a deadline so all retries share a generous overall budget
	deadline := time.Now().Add(timeout * 2)

	remaining := func() time.Duration {
		d := time.Until(deadline)
		if d < 500*time.Millisecond {
			return 500 * time.Millisecond
		}
		return d
	}

	ctx, cancel := context.WithTimeout(context.Background(), remaining())
	r, _, err := c.ExchangeContext(ctx, m, addr)
	cancel()

	// ednsRetry strips the EDNS0 OPT record and retries the query.
	// Returns true if the retry produced a better response.
	ednsRetry := func() bool {
		savedExtra := m.Extra
		m.Extra = nil
		ctx, cancel = context.WithTimeout(context.Background(), remaining())
		r2, _, err2 := c.ExchangeContext(ctx, m, addr)
		cancel()
		if err2 == nil && r2 != nil {
			r, err = r2, nil
			return true // EDNS0 was the problem; keep it stripped
		}
		m.Extra = savedExtra // retry didn't help; restore
		return false
	}

	// If EDNS0 caused an error response, retry without it.
	// Some servers (e.g. dnstm) return NXDOMAIN instead of FORMERR
	// when they don't understand the OPT record.
	if err == nil && r != nil && r.Rcode != dns.RcodeSuccess {
		ednsRetry()
	}

	// If UDP failed entirely, try TCP before giving up
	if err != nil || r == nil {
		c.Net = "tcp"
		ctx, cancel = context.WithTimeout(context.Background(), remaining())
		r, _, err = c.ExchangeContext(ctx, m, addr)
		cancel()
		if err != nil || r == nil {
			// TCP with EDNS0 also failed; last resort: TCP without EDNS0
			m.Extra = nil
			ctx, cancel = context.WithTimeout(context.Background(), remaining())
			r, _, err = c.ExchangeContext(ctx, m, addr)
			cancel()
			if err != nil || r == nil {
				return nil, false
			}
		}
		// TCP succeeded but got error Rcode; try without EDNS0
		// Skip if EDNS0 was already stripped (m.Extra is nil from line 71)
		if r != nil && r.Rcode != dns.RcodeSuccess && len(m.Extra) > 0 {
			ednsRetry()
		}
	}

	// Retry over TCP if response was truncated
	if r.Truncated {
		c.Net = "tcp"
		ctx, cancel = context.WithTimeout(context.Background(), remaining())
		r, _, err = c.ExchangeContext(ctx, m, addr)
		cancel()
		if err != nil || r == nil {
			return nil, false
		}
	}

	return r, true
}

func query(resolver, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	r, ok := queryRaw(resolver, domain, qtype, timeout)
	if !ok || r.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	return r, true
}

func QueryA(resolver, domain string, timeout time.Duration) bool {
	r, ok := query(resolver, domain, dns.TypeA, timeout)
	if !ok {
		return false
	}
	return len(r.Answer) > 0
}

// nsResolvers is the list of public DNS resolvers used for NS delegation checks.
// Multiple are needed because some may be blocked or unreachable in certain regions.
var nsResolvers = []string{
	// Global providers
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
	// Regional (Middle East / Central Asia)
	"178.22.122.100",  // Shecan (Iran)
	"185.51.200.2",    // DNS.sb (anycast, good in ME)
	"195.175.39.39",   // Turk Telekom (Turkey)
	"80.80.80.80",     // Freenom/Level3 (Turkey/EU)
	"217.218.127.127", // TCI (Iran)
	// Regional (Caucasus / nearby)
	"85.132.75.12",    // AzOnline (Azerbaijan)
	"213.42.20.20",    // Etisalat DNS (UAE)
}

// QueryNSMulti tries multiple public resolvers to verify NS delegation.
// Returns on the first successful response.
func QueryNSMulti(domain string, timeout time.Duration) ([]string, bool) {
	for _, resolver := range nsResolvers {
		hosts, ok := QueryNS(resolver, domain, timeout)
		if ok && len(hosts) > 0 {
			return hosts, true
		}
	}
	return nil, false
}

func QueryNS(resolver, domain string, timeout time.Duration) ([]string, bool) {
	r, ok := queryRaw(resolver, domain, dns.TypeNS, timeout)
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
