package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// EDNSCheck tests which EDNS payload sizes a resolver supports.
// This is critical for DNSTT — larger payloads = faster tunnel.
// Tests sizes 512, 900, 1232 and reports the largest that works.
func EDNSCheck(domain string, count int) CheckFunc {
	payloads := []int{512, 900, 1232}

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		bestPayload := 0

		for _, payload := range payloads {
			ok := testEDNSPayload(ip, domain, uint16(payload), timeout, count)
			if ok {
				bestPayload = payload
			}
		}

		if bestPayload == 0 {
			return false, nil
		}

		return true, Metrics{"edns_max": float64(bestPayload)}
	}
}

func testEDNSPayload(resolver, domain string, payload uint16, timeout time.Duration, tries int) bool {
	successes := 0

	for i := 0; i < tries; i++ {
		// Use a random subdomain to avoid caching
		qname := fmt.Sprintf("edns-%s.%s", randLabel(8), domain)

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
		m.RecursionDesired = true

		// Set EDNS0 with specified payload size
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(payload)
		m.Extra = append(m.Extra, o)

		c := new(dns.Client)
		c.Net = "udp"
		c.Timeout = timeout

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		r, _, err := c.ExchangeContext(ctx, m, resolver+":53")
		cancel()

		if err != nil || r == nil {
			continue
		}

		// NOERROR or NXDOMAIN both count as "resolver handled it"
		if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
			successes++
		}
	}

	return successes >= max(1, tries/2)
}
