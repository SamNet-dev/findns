package scanner

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/miekg/dns"
)

func randLabel(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// NXDomainCheck tests whether a resolver returns proper NXDOMAIN for non-existent domains.
// Hijacking resolvers return NOERROR with spoofed answers instead.
func NXDomainCheck(count int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		nxCount := 0

		for i := 0; i < count; i++ {
			fqdn := fmt.Sprintf("nxd-%s.invalid", randLabel(12))

			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
			m.RecursionDesired = true

			c := new(dns.Client)
			c.Net = "udp"
			c.Timeout = timeout

			r, _, err := c.Exchange(m, net.JoinHostPort(ip, "53"))
			if err != nil || r == nil {
				continue
			}

			if r.Rcode == dns.RcodeNameError {
				nxCount++
			}
			// NOERROR with answers = hijack
		}

		ok := nxCount >= max(1, count*3/4)
		if !ok {
			return false, nil
		}
		return true, Metrics{"nxdomain_ok": float64(nxCount), "hijack": 0}
	}
}
