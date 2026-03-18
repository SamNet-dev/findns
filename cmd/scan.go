package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/SamNet-dev/findns/internal/data"
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
	"e2e/dnstt":          "End-to-end DNSTT tunnel test (Noise handshake through resolver)",
	"e2e/slipstream":     "Full tunnel connectivity test via Slipstream",
	"throughput/dnstt":   "Testing real payload transfer through DNSTT tunnel",
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
	scanCmd.Flags().Bool("doh", false, "scan DoH resolvers instead of UDP")
	scanCmd.Flags().Bool("skip-ping", false, "skip ICMP ping step")
	scanCmd.Flags().Bool("skip-nxdomain", false, "skip NXDOMAIN hijack check")
	scanCmd.Flags().Bool("edns", false, "include EDNS payload size check (filters resolvers that don't support EDNS)")
	scanCmd.Flags().Int("edns-size", 1232, "EDNS0 UDP payload size in bytes (default 1232, lower if fragmented)")
	scanCmd.Flags().Int("query-size", 50, "cap dnstt-client upstream query size in bytes (default 50, use 0 for max)")
	scanCmd.Flags().StringSlice("cidr", nil, "CIDR range(s) to scan (e.g. --cidr 5.52.0.0/16)")
	scanCmd.Flags().String("cidr-file", "", "text file with one CIDR range per line to scan")
	scanCmd.Flags().String("output-ips", "", "write plain IP list (one per line) to this file")
	scanCmd.Flags().Int("top", 10, "number of top results to display")
	scanCmd.Flags().Int("batch", 0, "scan N resolvers at a time, saving after each batch (0 = all at once)")
	scanCmd.Flags().Bool("resume", false, "skip IPs already in the output file (resume a previous scan)")
	scanCmd.Flags().Bool("discover", false, "auto-discover neighbor /24 subnets when IPs pass all steps")
	scanCmd.Flags().Int("discover-rounds", 3, "max neighbor discovery rounds (default 3)")
	scanCmd.Flags().Bool("throughput", false, "include payload transfer test after e2e (requires --pubkey)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	certPath, _ := cmd.Flags().GetString("cert")
	dohMode, _ := cmd.Flags().GetBool("doh")
	skipPing, _ := cmd.Flags().GetBool("skip-ping")
	skipNXD, _ := cmd.Flags().GetBool("skip-nxdomain")
	ednsMode, _ := cmd.Flags().GetBool("edns")
	topN, _ := cmd.Flags().GetInt("top")
	outputIPs, _ := cmd.Flags().GetString("output-ips")
	batchSize, _ := cmd.Flags().GetInt("batch")
	resume, _ := cmd.Flags().GetBool("resume")

	ednsSize, _ := cmd.Flags().GetInt("edns-size")
	querySize, _ := cmd.Flags().GetInt("query-size")
	cidrRanges, _ := cmd.Flags().GetStringSlice("cidr")
	cidrFile, _ := cmd.Flags().GetString("cidr-file")
	discover, _ := cmd.Flags().GetBool("discover")
	discoverRounds, _ := cmd.Flags().GetInt("discover-rounds")
	throughput, _ := cmd.Flags().GetBool("throughput")

	// Load additional CIDRs from file if provided
	if cidrFile != "" {
		raw, err := os.ReadFile(cidrFile)
		if err != nil {
			return fmt.Errorf("reading --cidr-file %q: %w", cidrFile, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			cidrRanges = append(cidrRanges, line)
		}
	}

	// Apply query size (dnstt-client MTU); 0 = use max
	if querySize < 0 {
		return fmt.Errorf("--query-size must be >= 0 (got %d)", querySize)
	}
	scanner.DnsttMTU = querySize

	// Apply EDNS buffer size
	if ednsSize > 0 && ednsSize <= 65535 {
		scanner.EDNSBufSize = uint16(ednsSize)
	} else if ednsSize > 65535 {
		return fmt.Errorf("--edns-size must be <= 65535 (got %d)", ednsSize)
	}

	if outputFile == "" {
		outputFile = "results.json"
		fmt.Fprintf(os.Stderr, "  no -o flag — results will be saved to %s\n", outputFile)
	}

	var ips []string
	if len(cidrRanges) > 0 {
		if inputFile != "" {
			fmt.Fprintf(os.Stderr, "  warning: --cidr overrides -i flag — ignoring %s\n", inputFile)
		}
		// Check total size before expanding to prevent OOM on huge ranges
		totalUsable, err := data.TotalUsableIPs(cidrRanges)
		if err != nil {
			return fmt.Errorf("expanding CIDR ranges: %w", err)
		}
		const maxCIDRExpand = 1_000_000
		if totalUsable > maxCIDRExpand {
			return fmt.Errorf("--cidr expands to %d IPs (max %d) — use 'findns local --discover' for large ranges", totalUsable, maxCIDRExpand)
		}
		expanded, err := data.ExpandCIDRsSampled(cidrRanges, 0) // 0 = all IPs
		if err != nil {
			return fmt.Errorf("expanding CIDR ranges: %w", err)
		}
		if len(expanded) == 0 {
			return fmt.Errorf("CIDR range(s) produced no usable IPs")
		}
		src := "--cidr"
		if cidrFile != "" {
			src = "--cidr-file"
		}
		fmt.Fprintf(os.Stderr, "  %s: expanded %d range(s) to %d IPs\n", src, len(cidrRanges), len(expanded))
		ips = expanded
	} else {
		var err error
		ips, err = loadInput()
		if err != nil {
			return err
		}
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
	dur := time.Duration(timeout) * time.Second
	needE2E := pubkey != "" || certPath != ""
	var ports chan int
	if needE2E {
		ports = scanner.PortPool(30000, workers)
	}

	var steps []scanner.Step

	if dohMode {
		// When domain is set, skip basic resolve (A record test for google.com) —
		// tunnel domains have no A record. Go straight to resolve/tunnel which
		// tests random subdomain TXT forwarding (the actual tunnel mechanism).
		if domain == "" {
			steps = append(steps, scanner.Step{
				Name: "doh/resolve", Timeout: dur,
				Check: scanner.DoHResolveCheck("google.com", count), SortBy: "resolve_ms",
			})
		}
		if domain != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/resolve/tunnel", Timeout: dur,
				Check: scanner.DoHTunnelCheck(domain, count), SortBy: "resolve_ms",
			})
		}
		if domain != "" && pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/e2e", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.DoHDnsttCheckBin(dnsttBin, domain, pubkey, ports), SortBy: "e2e_ms",
			})
		}
	} else {
		if !skipPing {
			steps = append(steps, scanner.Step{
				Name: "ping", Timeout: dur,
				Check: scanner.PingCheck(count), SortBy: "ping_ms",
			})
		}
		// When domain is set, skip basic resolve (A record for google.com) —
		// tunnel domains have no A record, so ResolveCheck would falsely
		// eliminate every resolver. Go straight to resolve/tunnel instead.
		if domain == "" {
			steps = append(steps, scanner.Step{
				Name: "resolve", Timeout: dur,
				Check: scanner.ResolveCheck("google.com", count), SortBy: "resolve_ms",
			})
		}
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
			// E2E tunnel test: verify dnstt Noise handshake completes through
			// each resolver. SOCKS port only opens after the cryptographic
			// handshake succeeds — proving bidirectional tunnel data flow.
			steps = append(steps, scanner.Step{
				Name: "e2e/dnstt", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.DnsttCheckBin(dnsttBin, domain, pubkey, ports), SortBy: "socks_ms",
			})
			if throughput {
				steps = append(steps, scanner.Step{
					Name: "throughput/dnstt", Timeout: time.Duration(e2eTimeout) * time.Second,
					Check: scanner.ThroughputCheckBin(dnsttBin, domain, pubkey, ports), SortBy: "throughput_ms",
				})
			}
		}
		if domain != "" && certPath != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/slipstream", Timeout: time.Duration(e2eTimeout) * time.Second,
				Check: scanner.SlipstreamCheckBin(slipstreamBin, domain, certPath, ports), SortBy: "e2e_ms",
			})
		}
	}

	if len(steps) == 0 {
		return fmt.Errorf("no scan steps configured")
	}

	// --resume: load existing results and skip already-scanned IPs
	var allPassed []scanner.IPRecord
	scanned := make(map[string]struct{}) // tracks all IPs seen (for --discover dedup)
	if resume {
		if existing, err := scanner.LoadChainReport(outputFile); err == nil {
			for _, r := range existing.Passed {
				scanned[r.IP] = struct{}{}
				allPassed = append(allPassed, r)
			}
			for _, r := range existing.Failed {
				scanned[r.IP] = struct{}{}
			}
			filtered := ips[:0]
			for _, ip := range ips {
				if _, ok := scanned[ip]; !ok {
					filtered = append(filtered, ip)
				}
			}
			skipped := len(ips) - len(filtered)
			ips = filtered
			fmt.Fprintf(os.Stderr, "  %s✔ Resume: skipping %d already-scanned IPs, %d remaining%s\n",
				colorGreen, skipped, len(ips), colorReset)
			if len(ips) == 0 {
				fmt.Fprintf(os.Stderr, "  %s✔ All IPs already scanned%s\n", colorGreen, colorReset)
				return nil
			}
		}
	}
	// Add current IPs to scanned set
	for _, ip := range ips {
		scanned[ip] = struct{}{}
	}

	if outputIPs == "" {
		outputIPs = strings.TrimSuffix(outputFile, ".json") + "_ips.txt"
	}

	// saveResults writes current results to JSON + IP list
	saveResults := func(report scanner.ChainReport) {
		// Merge with previously loaded results from --resume
		merged := report
		if len(allPassed) > 0 {
			merged.Passed = append(allPassed, report.Passed...)
		}
		scanner.WriteChainReport(merged, outputFile)
		if len(merged.Passed) > 0 {
			scanner.WriteIPList(merged.Passed, outputIPs)
		}
	}

	printBanner(len(ips), dohMode, domain, steps)
	printPreFlight(len(ips), domain, dnsttBin, slipstreamBin, steps)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	scanner.ResetE2EDiagnostic()
	scanStart := time.Now()

	var report scanner.ChainReport

	// --batch: split IPs into chunks, save after each batch
	if batchSize > 0 && len(ips) > batchSize {
		totalBatches := (len(ips) + batchSize - 1) / batchSize
		for i := 0; i < len(ips); i += batchSize {
			if ctx.Err() != nil {
				break
			}
			end := i + batchSize
			if end > len(ips) {
				end = len(ips)
			}
			batchNum := i/batchSize + 1
			chunk := ips[i:end]
			fmt.Fprintf(os.Stderr, "\n  %s━━━ Batch %d/%d (%d IPs) ━━━%s\n\n",
				colorCyan, batchNum, totalBatches, len(chunk), colorReset)

			batchReport := runPipelineScan(ctx, chunk, workers, steps)
			scanner.MergeChainReports(&report, batchReport)

			saveResults(report)
			totalPassed := len(allPassed) + len(report.Passed)
			fmt.Fprintf(os.Stderr, "  %s✔ Batch %d done — %d passed so far — saved to %s%s\n",
				colorGreen, batchNum, totalPassed, outputFile, colorReset)
		}
	} else {
		report = runPipelineScan(ctx, ips, workers, steps)
	}

	// --discover: find neighbor /24 subnets from passed IPs and scan them
	if discover && !dohMode && ctx.Err() == nil && len(report.Passed) > 0 {
		knownSubnets := make(map[string]struct{})

		for round := 1; round <= discoverRounds; round++ {
			if ctx.Err() != nil {
				break
			}

			passedIPs := make([]string, len(report.Passed))
			for i, r := range report.Passed {
				passedIPs[i] = r.IP
			}
			newSubnets := scanner.SubnetsFromIPs(passedIPs)

			var toExpand []string
			for _, cidr := range newSubnets {
				if _, ok := knownSubnets[cidr]; !ok {
					knownSubnets[cidr] = struct{}{}
					toExpand = append(toExpand, cidr)
				}
			}
			if len(toExpand) == 0 {
				fmt.Fprintf(os.Stderr, "\n  %s✔ Discovery: no new /24 subnets found%s\n", colorGreen, colorReset)
				break
			}

			neighborIPs := scanner.ExpandSubnets(toExpand, scanned)
			if len(neighborIPs) == 0 {
				fmt.Fprintf(os.Stderr, "\n  %s✔ Discovery round %d: %d subnets but all IPs already scanned%s\n",
					colorGreen, round, len(toExpand), colorReset)
				break
			}

			for _, ip := range neighborIPs {
				scanned[ip] = struct{}{}
			}

			fmt.Fprintf(os.Stderr, "\n  %s━━━ Discovery round %d: %d new /24 subnets → %d IPs ━━━%s\n\n",
				colorCyan, round, len(toExpand), len(neighborIPs), colorReset)

			roundReport := runPipelineScan(ctx, neighborIPs, workers, steps)
			scanner.MergeChainReports(&report, roundReport)

			saveResults(report)
			totalPassed := len(allPassed) + len(report.Passed)
			fmt.Fprintf(os.Stderr, "  %s✔ Round %d: %d new resolvers — %d total passed — saved to %s%s\n",
				colorGreen, round, len(roundReport.Passed), totalPassed, outputFile, colorReset)

			if len(roundReport.Passed) == 0 {
				fmt.Fprintf(os.Stderr, "  %s✔ Discovery: no new resolvers found, stopping%s\n", colorGreen, colorReset)
				break
			}
		}
	}

	totalTime := time.Since(scanStart)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n  %s⚠ Interrupted — partial results saved to %s%s\n", colorYellow, outputFile, colorReset)
	}

	printSummary(report, topN, totalTime, domain)
	saveResults(report)

	totalPassed := len(allPassed) + len(report.Passed)
	if totalPassed > 0 {
		fmt.Fprintf(os.Stderr, "  %s✔ IP list written to %s (%d IPs)%s\n", colorGreen, outputIPs, totalPassed, colorReset)
	}
	return nil
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
	fmt.Fprintf(w, "    %s✔%s %d resolvers loaded\n", colorGreen, colorReset, ipCount)
	fmt.Fprintf(w, "    %s✔%s %d workers\n", colorGreen, colorReset, workers)
	fmt.Fprintf(w, "    %s✔%s %d scan steps configured\n", colorGreen, colorReset, len(steps))
	if dnsttBin != "" {
		fmt.Fprintf(w, "    %s✔%s dnstt-client: %s%s%s\n", colorGreen, colorReset, colorDim, dnsttBin, colorReset)
	}
	if slipstreamBin != "" {
		fmt.Fprintf(w, "    %s✔%s slipstream-client: %s%s%s\n", colorGreen, colorReset, colorDim, slipstreamBin, colorReset)
	}
	if domain != "" {
		fmt.Fprintf(w, "    %s✔%s Domain: %s%s%s\n", colorGreen, colorReset, colorCyan, domain, colorReset)
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

// runPipelineScan runs the DFS-style pipeline where each worker processes
// one IP through ALL steps sequentially. Results appear as soon as individual
// IPs complete the pipeline — no waiting for all IPs to finish a step.
func runPipelineScan(ctx context.Context, ips []string, workers int, steps []scanner.Step) scanner.ChainReport {
	ch := scanner.RunPipeline(ctx, ips, workers, steps)

	w := os.Stderr
	start := time.Now()
	tty := isTTY()

	// Print pipeline banner
	if tty {
		fmt.Fprintf(w, "  %s── Pipeline: ", colorDim)
		for i, s := range steps {
			if i > 0 {
				fmt.Fprintf(w, " → ")
			}
			fmt.Fprintf(w, "%s", s.Name)
		}
		fmt.Fprintf(w, " ──%s\n\n", colorReset)
	}

	stepTested := make([]int, len(steps))
	stepPassed := make([]int, len(steps))
	stepFailed := make([]int, len(steps))

	var report scanner.ChainReport
	var done, pass, fail int
	total := len(ips)

	for r := range ch {
		done++

		if r.FailedStep == -1 {
			// Passed all steps
			for si := range steps {
				stepTested[si]++
				stepPassed[si]++
			}
			pass++
			report.Passed = append(report.Passed, scanner.IPRecord{IP: r.IP, Metrics: r.Metrics})

			// Show passed IP immediately
			if tty {
				var parts []string
				if r.Metrics != nil {
					keys := make([]string, 0, len(r.Metrics))
					for k := range r.Metrics {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						parts = append(parts, fmt.Sprintf("%s=%s", k, formatMetric(r.Metrics[k])))
					}
				}
				fmt.Fprintf(w, "\r\033[2K  %s✔%s %-15s  %s%s%s\n",
					colorGreen, colorReset, r.IP, colorDim, strings.Join(parts, "  "), colorReset)
			}
		} else {
			// Failed — update per-step stats up to the failed step
			for si := 0; si <= r.FailedStep; si++ {
				stepTested[si]++
				if si < r.FailedStep {
					stepPassed[si]++
				} else {
					stepFailed[si]++
				}
			}
			fail++
			report.Failed = append(report.Failed, scanner.IPRecord{IP: r.IP})
		}

		// Progress bar (always the last line, updated with \r)
		if tty && total > 0 {
			pct := done * 100 / total
			elapsed := time.Since(start).Truncate(time.Second)
			bar := progressBar(pct, 20)
			fmt.Fprintf(w, "\r\033[2K  %sscanning%s  %s  %d/%d  %s✔ %d%s  %s✘ %d%s  %s%s%s",
				colorBold, colorReset, bar, done, total,
				colorGreen, pass, colorReset,
				colorRed, fail, colorReset,
				colorDim, elapsed, colorReset)
		}
	}

	// Final completion line
	if tty {
		elapsed := time.Since(start).Truncate(time.Second)
		fmt.Fprintf(w, "\r\033[2K  %s✔%s Pipeline complete  %s%d/%d passed%s  %s%s%s\n",
			colorGreen, colorReset,
			colorGreen, pass, total, colorReset,
			colorDim, elapsed, colorReset)
	}

	// Build step results for the report
	report.Steps = make([]scanner.StepResult, len(steps))
	for i, step := range steps {
		report.Steps[i] = scanner.StepResult{
			Name:   step.Name,
			Tested: stepTested[i],
			Passed: stepPassed[i],
			Failed: stepFailed[i],
		}
	}

	if report.Passed == nil {
		report.Passed = []scanner.IPRecord{}
	}

	// Sort passed results by the last step's primary metric
	if len(steps) > 0 {
		lastSort := steps[len(steps)-1].SortBy
		if lastSort != "" && len(report.Passed) > 1 {
			sort.SliceStable(report.Passed, func(i, j int) bool {
				vi := report.Passed[i].Metrics[lastSort]
				vj := report.Passed[j].Metrics[lastSort]
				return vi < vj
			})
		}
	}

	return report
}
