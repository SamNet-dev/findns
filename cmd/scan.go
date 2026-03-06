package main

import (
	"fmt"
	"os"
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

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Full scan pipeline: ping -> resolve -> nxdomain -> tunnel -> e2e",
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
	scanCmd.Flags().Bool("doh", false, "scan DoH resolvers instead of UDP")
	scanCmd.Flags().Bool("skip-ping", false, "skip ICMP ping step")
	scanCmd.Flags().Bool("skip-nxdomain", false, "skip NXDOMAIN hijack check")
	scanCmd.Flags().Int("top", 10, "number of top results to display")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	certPath, _ := cmd.Flags().GetString("cert")
	testURL, _ := cmd.Flags().GetString("test-url")
	dohMode, _ := cmd.Flags().GetBool("doh")
	skipPing, _ := cmd.Flags().GetBool("skip-ping")
	skipNXD, _ := cmd.Flags().GetBool("skip-nxdomain")
	topN, _ := cmd.Flags().GetInt("top")

	if outputFile == "" {
		return fmt.Errorf("--output / -o flag is required")
	}

	ips, err := loadInput()
	if err != nil {
		return err
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
				Check: scanner.DoHDnsttCheck(domain, pubkey, testURL, ports), SortBy: "e2e_ms",
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
			steps = append(steps, scanner.Step{
				Name: "edns", Timeout: dur,
				Check: scanner.EDNSCheck(domain, count), SortBy: "edns_max",
			})
			steps = append(steps, scanner.Step{
				Name: "resolve/tunnel", Timeout: dur,
				Check: scanner.TunnelCheck(domain, count), SortBy: "resolve_ms",
			})
		}
		if domain != "" && pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/dnstt", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.DnsttCheck(domain, pubkey, testURL, ports), SortBy: "e2e_ms",
			})
		}
		if domain != "" && certPath != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/slipstream", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.SlipstreamCheck(domain, certPath, testURL, ports), SortBy: "e2e_ms",
			})
		}
	}

	if len(steps) == 0 {
		return fmt.Errorf("no scan steps configured")
	}

	printBanner(len(ips), dohMode, domain, steps)

	scanStart := time.Now()
	report := scanner.RunChainQuiet(ips, workers, steps, newProgressFactoryWithTotal(len(steps)))
	totalTime := time.Since(scanStart)

	printSummary(report, topN, totalTime)

	return scanner.WriteChainReport(report, outputFile)
}

func printBanner(count int, doh bool, domain string, steps []scanner.Step) {
	mode := "UDP"
	if doh {
		mode = "DoH"
	}

	w := os.Stderr
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  %s\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510%s\n", colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  %s%sfindns%s                       %s\u2502%s\n", colorDim, colorReset, colorBold, colorCyan, colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  %sDNS Tunnel Resolver Scanner%s          %s\u2502%s\n", colorDim, colorReset, colorDim, colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524%s\n", colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  Mode:      %s%-25s%s%s\u2502%s\n", colorDim, colorReset, colorWhite, mode, colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2502%s  Resolvers: %s%-25d%s%s\u2502%s\n", colorDim, colorReset, colorWhite, count, colorReset, colorDim, colorReset)
	if domain != "" {
		fmt.Fprintf(w, "  %s\u2502%s  Domain:    %s%-25s%s%s\u2502%s\n", colorDim, colorReset, colorCyan, domain, colorReset, colorDim, colorReset)
	}
	fmt.Fprintf(w, "  %s\u2502%s  Workers:   %s%-25d%s%s\u2502%s\n", colorDim, colorReset, colorWhite, workers, colorReset, colorDim, colorReset)
	fmt.Fprintf(w, "  %s\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518%s\n", colorDim, colorReset)

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

func printSummary(report scanner.ChainReport, topN int, totalTime time.Duration) {
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
		fmt.Fprintf(w, "\n  %s\u2718 No resolvers passed all steps%s\n\n", colorRed, colorReset)
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
		strings.Repeat(" ", 60-17-digitCount(limit)), colorDim, colorReset)
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
