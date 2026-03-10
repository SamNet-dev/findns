package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorWhite  = "\033[37m"
)

var stepDescriptions = map[string]string{
	"ping":               "Testing ICMP reachability of resolvers",
	"resolve":            "Checking if resolvers can resolve standard domains",
	"nxdomain":           "Detecting DNS hijacking on non-existent domains",
	"edns":               "Testing EDNS0 support and buffer sizes",
	"resolve/tunnel":     "Verifying resolvers forward queries to your tunnel domain",
	"e2e/dnstt":          "Full tunnel connectivity test via DNSTT",
	"e2e/slipstream":     "Full tunnel connectivity test via Slipstream",
	"doh/resolve":        "Checking DoH resolver connectivity",
	"doh/resolve/tunnel": "Verifying DoH resolvers forward to your tunnel domain",
	"doh/e2e":            "Full DoH tunnel connectivity test via DNSTT",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Full scan pipeline: ping -> resolve -> nxdomain -> tunnel -> e2e (use --edns to add EDNS check)",
	Long: `Run a complete resolver scan with all checks in sequence.
This is the recommended way to find working resolvers for DNS tunneling.

For UDP resolvers:
  scanner scan -i resolvers.txt -o results.json --domain t.example.com

With e2e DNSTT test:
  scanner scan -i resolvers.txt -o results.json --domain t.example.com --pubkey <key>

For DoH resolvers:
  scanner scan -i doh-resolvers.txt -o results.json --domain t.example.com --doh`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().String("domain", "", "tunnel domain (required for tunnel/edns/e2e steps)")
	scanCmd.Flags().String("pubkey", "", "DNSTT public key (enables e2e test)")
	scanCmd.Flags().String("cert", "", "Slipstream cert path (enables slipstream e2e test)")
	scanCmd.Flags().String("test-url", "https://httpbin.org/ip", "URL to test through tunnel")
	scanCmd.Flags().String("proxy-auth", "", "SOCKS proxy auth as user:pass (for e2e tests)")
	scanCmd.Flags().Bool("doh", false, "scan DoH resolvers instead of UDP")
	scanCmd.Flags().Bool("skip-ping", false, "skip ICMP ping step")
	scanCmd.Flags().Bool("skip-nxdomain", false, "skip NXDOMAIN hijack check")
	scanCmd.Flags().Bool("edns", false, "include EDNS payload size check (filters resolvers that don't support EDNS)")
	scanCmd.Flags().Int("top", 10, "number of top results to display")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	certPath, _ := cmd.Flags().GetString("cert")
	testURL, _ := cmd.Flags().GetString("test-url")
	proxyAuth, _ := cmd.Flags().GetString("proxy-auth")
	dohMode, _ := cmd.Flags().GetBool("doh")
	skipPing, _ := cmd.Flags().GetBool("skip-ping")
	skipNXD, _ := cmd.Flags().GetBool("skip-nxdomain")
	ednsMode, _ := cmd.Flags().GetBool("edns")
	topN, _ := cmd.Flags().GetInt("top")

	if outputFile == "" {
		return fmt.Errorf("--output / -o flag is required")
	}

	ips, err := loadInput()
	if err != nil {
		return err
	}

	// Pre-flight: verify required binaries before wasting time scanning
	var dnsttBin, slipstreamBin string
	if pubkey != "" {
		bin, err := findBinary("dnstt-client")
		if err != nil {
			return fmt.Errorf("--pubkey requires dnstt-client: %w", err)
		}
		dnsttBin = bin
	}
	if certPath != "" {
		bin, err := findBinary("slipstream-client")
		if err != nil {
			return fmt.Errorf("--cert requires slipstream-client: %w", err)
		}
		slipstreamBin = bin
	}
	if pubkey != "" || certPath != "" {
		if _, err := findBinary("curl"); err != nil {
			return fmt.Errorf("e2e tests require curl in PATH (not found)")
		}
	}

	dur := time.Duration(timeout) * time.Second
	needE2E := pubkey != "" || certPath != ""
	var ports chan int
	if needE2E {
		ports = scanner.PortPool(30000, workers)
	}

	var steps []scanner.Step

	if dohMode {
		steps = append(steps, scanner.Step{
			Name: "doh/resolve", Timeout: dur,
			Check: scanner.DoHResolveCheck("google.com", count), SortBy: "resolve_ms",
		})
		if domain != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/resolve/tunnel", Timeout: dur,
				Check: scanner.DoHTunnelCheck(domain, count), SortBy: "resolve_ms",
			})
		}
		if domain != "" && pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/e2e", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.DoHDnsttCheckBin(dnsttBin, domain, pubkey, testURL, proxyAuth, ports), SortBy: "e2e_ms",
			})
		}
	} else {
		if !skipPing {
			steps = append(steps, scanner.Step{
				Name: "ping", Timeout: dur,
				Check: scanner.PingCheck(count), SortBy: "ping_ms",
			})
		}
		steps = append(steps, scanner.Step{
			Name: "resolve", Timeout: dur,
			Check: scanner.ResolveCheck("google.com", count), SortBy: "resolve_ms",
		})
		if !skipNXD {
			steps = append(steps, scanner.Step{
				Name: "nxdomain", Timeout: dur,
				Check: scanner.NXDomainCheck(count), SortBy: "hijack",
			})
		}
		if domain != "" {
			if ednsMode {
				steps = append(steps, scanner.Step{
					Name: "edns", Timeout: dur,
					Check: scanner.EDNSCheck(domain, count), SortBy: "edns_max",
				})
			}
			steps = append(steps, scanner.Step{
				Name: "resolve/tunnel", Timeout: dur,
				Check: scanner.TunnelCheck(domain, count), SortBy: "resolve_ms",
			})
		}
		if domain != "" && pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/dnstt", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.DnsttCheckBin(dnsttBin, domain, pubkey, testURL, proxyAuth, ports), SortBy: "e2e_ms",
			})
		}
		if domain != "" && certPath != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/slipstream", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.SlipstreamCheckBin(slipstreamBin, domain, certPath, testURL, proxyAuth, ports), SortBy: "e2e_ms",
			})
		}
	}

	if len(steps) == 0 {
		return fmt.Errorf("no scan steps configured")
	}

	printBanner(len(ips), dohMode, domain, steps)
	printPreFlight(len(ips), domain, dnsttBin, slipstreamBin, steps)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	scanner.ResetE2EDiagnostic()
	scanStart := time.Now()
	report := scanner.RunChainQuietCtx(ctx, ips, workers, steps, newScanProgressFactory(len(steps), stepDescriptions))
	totalTime := time.Since(scanStart)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n\n  %s⚠ Interrupted — saving partial results to %s%s\n", colorYellow, outputFile, colorReset)
	}

	printSummary(report, topN, totalTime, domain)

	return scanner.WriteChainReport(report, outputFile)
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func hline(left, fill, right string, width int) string {
	return left + strings.Repeat(fill, width) + right
}

func printPreFlight(ipCount int, domain, dnsttBin, slipstreamBin string, steps []scanner.Step) {
	if !isTTY() {
		return
	}
	w := os.Stderr
	fmt.Fprintf(w, "  %sPre-flight:%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "    %s\u2714%s %d resolvers loaded\n", colorGreen, colorReset, ipCount)
	fmt.Fprintf(w, "    %s\u2714%s %d workers\n", colorGreen, colorReset, workers)
	fmt.Fprintf(w, "    %s\u2714%s %d scan steps configured\n", colorGreen, colorReset, len(steps))
	if dnsttBin != "" {
		fmt.Fprintf(w, "    %s\u2714%s dnstt-client: %s%s%s\n", colorGreen, colorReset, colorDim, dnsttBin, colorReset)
	}
	if slipstreamBin != "" {
		fmt.Fprintf(w, "    %s\u2714%s slipstream-client: %s%s%s\n", colorGreen, colorReset, colorDim, slipstreamBin, colorReset)
	}
	if domain != "" {
		nsHosts, nsOK := scanner.QueryNSMulti(domain, 5*time.Second)
		if nsOK && len(nsHosts) > 0 {
			fmt.Fprintf(w, "    %s\u2714%s Domain: %s%s%s — NS delegation verified\n",
				colorGreen, colorReset, colorCyan, domain, colorReset)
			for _, ns := range nsHosts {
				fmt.Fprintf(w, "        %s%s%s\n", colorDim, ns, colorReset)
			}
		} else {
			fmt.Fprintf(w, "    %s\u2718%s Domain: %s%s%s — %sNS delegation NOT found!%s\n",
				colorRed, colorReset, colorCyan, domain, colorReset, colorRed, colorReset)
			fmt.Fprintf(w, "      %sTunnel/e2e steps will likely fail. Verify your DNS setup:%s\n", colorDim, colorReset)
			fmt.Fprintf(w, "      %snslookup -type=NS %s 8.8.8.8%s\n", colorDim, domain, colorReset)
		}
	}
	fmt.Fprintf(w, "\n")
}

func printBanner(count int, doh bool, domain string, steps []scanner.Step) {
	mode := "UDP"
	if doh {
		mode = "DoH"
	}

	// Dynamic box width: at least 38, wider if domain is long
	inner := 38
	if domain != "" && len(domain)+15 > inner {
		inner = len(domain) + 17
	}
	w := os.Stderr
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, hline("\u250c", "\u2500", "\u2510", inner), colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  %s%s%-*s%s%s\u2502%s\n", colorDim, colorReset, colorBold, colorCyan, inner-4, "findns", colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  %s%-*s%s%s\u2502%s\n", colorDim, colorReset, colorDim, inner-4, "DNS Tunnel Resolver Scanner", colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, hline("\u251c", "\u2500", "\u2524", inner), colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  Mode:      %s%s%s%s\u2502%s\n", colorDim, colorReset, colorWhite, pad(mode, inner-15), colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  Resolvers: %s%s%s%s\u2502%s\n", colorDim, colorReset, colorWhite, pad(fmt.Sprintf("%d", count), inner-15), colorReset, colorDim, colorReset)
	if domain != "" {
		fmt.Fprintf(w, "  %s\u2502%s  Domain:    %s%s%s%s\u2502%s\n", colorDim, colorReset, colorCyan, pad(domain, inner-15), colorReset, colorDim, colorReset)
	}
	fmt.Fprintf(w, "  %s\u2502%s  Workers:   %s%s%s%s\u2502%s\n", colorDim, colorReset, colorWhite, pad(fmt.Sprintf("%d", workers), inner-15), colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, hline("\u2514", "\u2500", "\u2518", inner), colorReset)

	// Step plan
	fmt.Fprintf(w, "\n  %sPipeline:%s ", colorBold, colorReset)
	for i, s := range steps {
		if i > 0 {
			fmt.Fprintf(w, " %s\u2192%s ", colorDim, colorReset)
		}
		fmt.Fprintf(w, "%s%s%s", colorCyan, s.Name, colorReset)
	}
	fmt.Fprintf(w, "\n\n")
}

func printSummary(report scanner.ChainReport, topN int, totalTime time.Duration, domain string) {
	w := os.Stderr

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  %s%s\u2550\u2550\u2550 RESULTS \u2550\u2550\u2550%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "\n")

	// Step breakdown
	for _, step := range report.Steps {
		pct := 0
		if step.Tested > 0 {
			pct = step.Passed * 100 / step.Tested
		}

		// Color based on pass rate
		color := colorGreen
		icon := "\u2714" // checkmark
		if pct < 50 {
			color = colorYellow
			icon = "\u26a0" // warning
		}
		if pct < 20 {
			color = colorRed
			icon = "\u2718" // cross
		}

		// Mini bar for each step
		miniBar := miniProgressBar(pct, 10)
		fmt.Fprintf(w, "  %s%s%s %-18s %s  %s%4d/%-4d%s  %s(%d%%)%s  %s%.1fs%s\n",
			color, icon, colorReset,
			step.Name,
			miniBar,
			color, step.Passed, step.Tested, colorReset,
			colorDim, pct, colorReset,
			colorDim, step.Seconds, colorReset)
	}

	// Total time
	fmt.Fprintf(w, "\n  %sTotal time: %s%s\n", colorDim, totalTime.Truncate(time.Millisecond), colorReset)

	// Divider
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, strings.Repeat("\u2500", 50), colorReset)

	if len(report.Passed) == 0 {
		fmt.Fprintf(w, "\n  %s\u2718 No resolvers passed all steps%s\n", colorRed, colorReset)
		// Print diagnostic hints for common failure patterns
		for _, step := range report.Steps {
			if step.Passed == 0 && step.Tested > 0 {
				switch step.Name {
				case "resolve/tunnel", "doh/resolve/tunnel":
					fmt.Fprintf(w, "\n  %s\u26a0 Hint: resolve/tunnel had 0%% pass rate.%s\n", colorYellow, colorReset)
					fmt.Fprintf(w, "  %sPossible causes:%s\n", colorDim, colorReset)
					fmt.Fprintf(w, "  %s  1. NS delegation not set up: nslookup -type=NS <your-domain> 8.8.8.8%s\n", colorDim, colorReset)
					fmt.Fprintf(w, "  %s     You need NS + glue A records pointing to your server.%s\n", colorDim, colorReset)
					fmt.Fprintf(w, "  %s  2. Server returns NXDOMAIN: delegation works but dnstt-server/dnstm is misconfigured.%s\n", colorDim, colorReset)
					fmt.Fprintf(w, "  %s     Check: cat /etc/dnstm/config.json  |  journalctl -u dnstm-dnsrouter -n 20%s\n", colorDim, colorReset)
					fmt.Fprintf(w, "  %sSee: https://github.com/SamNet-dev/findns/blob/main/GUIDE.md#-تنظیم-دامنه-تانل-مهم--قبل-از-اسکن-بخوانید%s\n", colorDim, colorReset)
				case "ping":
					fmt.Fprintf(w, "\n  %s\u26a0 Hint: ping had 0%% pass rate. Try --skip-ping (ICMP may be blocked).%s\n", colorYellow, colorReset)
				case "e2e/dnstt", "e2e/slipstream", "doh/e2e":
					fmt.Fprintf(w, "\n  %s\u26a0 Hint: e2e had 0%% pass rate. Make sure your tunnel server is running.%s\n", colorYellow, colorReset)
					if diag := scanner.E2EDiagnostic(); diag != "" {
						fmt.Fprintf(w, "  %s  Diagnostic: %s%s\n", colorDim, diag, colorReset)
					}
				}
				break // Only show hint for the first failing step
			}
		}
		fmt.Fprintf(w, "\n  %sSee full guide: https://github.com/SamNet-dev/findns/blob/main/GUIDE.md%s\n", colorDim, colorReset)
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintf(w, "\n  %s\u2714 %d resolvers passed all steps%s\n", colorGreen, len(report.Passed), colorReset)

	// Top N results table
	limit := topN
	if len(report.Passed) < limit {
		limit = len(report.Passed)
	}

	fmt.Fprintf(w, "\n  %s\u250c%s\u2510%s\n", colorDim, strings.Repeat("\u2500", 60), colorReset)
	fmt.Fprintf(w, "  %s\u2502%s %sTop %d Resolvers%s%s%s\u2502%s\n",
		colorDim, colorReset, colorBold, limit, colorReset,
		strings.Repeat(" ", max(0, 60-17-digitCount(limit))), colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u251c%s\u2524%s\n", colorDim, strings.Repeat("\u2500", 60), colorReset)

	for i := 0; i < limit; i++ {
		r := report.Passed[i]

		// Build metrics string with sorted keys
		var metricParts []string
		if r.Metrics != nil {
			keys := make([]string, 0, len(r.Metrics))
			for k := range r.Metrics {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := r.Metrics[k]
				metricParts = append(metricParts, fmt.Sprintf("%s%s=%s%s", colorDim, k, formatMetric(v), colorReset))
			}
		}

		metrics := strings.Join(metricParts, "  ")
		fmt.Fprintf(w, "  %s\u2502%s %s%2d.%s %s%s%-15s%s  %s %s\u2502%s\n",
			colorDim, colorReset,
			colorDim, i+1, colorReset,
			colorBold, colorCyan, r.IP, colorReset,
			metrics,
			// Padding is hard without knowing actual widths, so just close the box
			colorDim, colorReset)
	}

	fmt.Fprintf(w, "  %s\u2514%s\u2518%s\n", colorDim, strings.Repeat("\u2500", 60), colorReset)

	if len(report.Passed) > limit {
		fmt.Fprintf(w, "  %s... and %d more in %s%s\n", colorDim, len(report.Passed)-limit, outputFile, colorReset)
	}

	// Next steps guidance
	fmt.Fprintf(w, "\n  %sNext steps:%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "    %s\u2022%s Results saved to %s%s%s\n", colorDim, colorReset, colorCyan, outputFile, colorReset)
	if domain != "" && len(report.Passed) > 0 {
		topIP := report.Passed[0].IP
		fmt.Fprintf(w, "    %s\u2022%s Test top resolver: %snslookup %s %s%s\n",
			colorDim, colorReset, colorDim, domain, topIP, colorReset)
	}
	// Check if e2e was in pipeline
	hasE2E := false
	hasTunnel := false
	for _, s := range report.Steps {
		if strings.Contains(s.Name, "e2e") {
			hasE2E = true
		}
		if strings.Contains(s.Name, "tunnel") {
			hasTunnel = true
		}
	}
	if hasTunnel && !hasE2E && len(report.Passed) > 0 {
		fmt.Fprintf(w, "    %s\u2022%s Run with --pubkey to test full tunnel connectivity (e2e)\n", colorDim, colorReset)
	}
	fmt.Fprintln(w)
}

func miniProgressBar(pct, width int) string {
	filled := pct * width / 100
	bar := make([]rune, width)
	for i := range bar {
		if i < filled {
			bar[i] = '\u2588' // █
		} else {
			bar[i] = '\u2591' // ░
		}
	}
	return string(bar)
}

func formatMetric(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d", int(v))
	}
	return fmt.Sprintf("%.1f", v)
}

func digitCount(n int) int {
	return len(fmt.Sprintf("%d", n))
}
