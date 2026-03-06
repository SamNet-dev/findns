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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil || r == nil {
		return nil, false
	}

	// Retry over TCP if response was truncated
	if r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, m, addr)
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
