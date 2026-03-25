package tui

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/SamNet-dev/findns/internal/binutil"
	"github.com/SamNet-dev/findns/internal/scanner"
	tea "github.com/charmbracelet/bubbletea"
)

type stepProgress struct {
	name     string
	done     int
	total    int
	passed   int
	failed   int
	finished bool
}

func (m Model) startScan() tea.Cmd {
	return func() tea.Msg {
		pipelineCh := make(chan pipelineProgressMsg, 200)
		doneCh := make(chan scanDoneMsg, 1)
		return scanStartedMsg{progressCh: nil, doneCh: doneCh, pipelineCh: pipelineCh}
	}
}

func buildSteps(cfg ScanConfig) ([]scanner.Step, error) {
	dur := time.Duration(cfg.Timeout) * time.Second
	e2eTimeout := cfg.E2ETimeout
	if e2eTimeout <= 0 {
		e2eTimeout = 30
	}
	e2eDur := time.Duration(e2eTimeout) * time.Second
	var steps []scanner.Step

	// Pre-flight: find e2e binaries if needed
	var dnsttBin, slipstreamBin string
	needE2E := cfg.Pubkey != "" || cfg.Cert != ""
	if cfg.Pubkey != "" {
		bin, err := binutil.Find("dnstt-client")
		if err != nil {
			return nil, fmt.Errorf("pubkey requires dnstt-client in PATH")
		}
		dnsttBin = bin
	}
	if cfg.Cert != "" {
		bin, err := binutil.Find("slipstream-client")
		if err != nil {
			return nil, fmt.Errorf("cert requires slipstream-client in PATH")
		}
		slipstreamBin = bin
	}
	var ports chan int
	if needE2E {
		ports = scanner.PortPool(30000, cfg.Workers)
	}

	socksOpts := scanner.SOCKS5Opts{User: cfg.SocksUser, Pass: cfg.SocksPass, ConnectAddr: cfg.ConnectAddr}

	if cfg.DoH {
		if cfg.Domain == "" {
			steps = append(steps, scanner.Step{
				Name: "doh/resolve", Timeout: dur,
				Check: scanner.DoHResolveCheck("google.com", cfg.Count), SortBy: "resolve_ms",
			})
		}
		if cfg.Domain != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/resolve/tunnel", Timeout: dur,
				Check: scanner.DoHTunnelCheck(cfg.Domain, cfg.Count), SortBy: "resolve_ms",
			})
		}
		if cfg.Domain != "" && cfg.Pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/e2e", Timeout: e2eDur,
				Check: scanner.DoHDnsttCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, ports, socksOpts), SortBy: "e2e_ms",
			})
		}
	} else {
		if !cfg.SkipPing {
			steps = append(steps, scanner.Step{
				Name: "ping", Timeout: dur,
				Check: scanner.PingCheck(cfg.Count), SortBy: "ping_ms",
			})
		}
		if cfg.Domain == "" {
			steps = append(steps, scanner.Step{
				Name: "resolve", Timeout: dur,
				Check: scanner.ResolveCheck("google.com", cfg.Count), SortBy: "resolve_ms",
			})
		}
		if !cfg.SkipNXDomain {
			steps = append(steps, scanner.Step{
				Name: "nxdomain", Timeout: dur,
				Check: scanner.NXDomainCheck(cfg.Count), SortBy: "hijack",
			})
		}
		if cfg.Domain != "" {
			if cfg.EDNS {
				steps = append(steps, scanner.Step{
					Name: "edns", Timeout: dur,
					Check: scanner.EDNSCheck(cfg.Domain, cfg.Count), SortBy: "edns_max",
				})
			}
			steps = append(steps, scanner.Step{
				Name: "resolve/tunnel", Timeout: dur,
				Check: scanner.TunnelCheck(cfg.Domain, cfg.Count), SortBy: "resolve_ms",
			})
		}
		if cfg.Domain != "" && cfg.Pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/dnstt", Timeout: e2eDur,
				Check: scanner.DnsttCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, ports, socksOpts), SortBy: "socks_ms",
			})
			if cfg.Throughput {
				steps = append(steps, scanner.Step{
					Name: "throughput/dnstt", Timeout: e2eDur,
					Check: scanner.ThroughputCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, ports, socksOpts), SortBy: "throughput_ms",
				})
			}
		}
		if cfg.Domain != "" && cfg.Cert != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/slipstream", Timeout: e2eDur,
				Check: scanner.SlipstreamCheckBin(slipstreamBin, cfg.Domain, cfg.Cert, ports, socksOpts), SortBy: "e2e_ms",
			})
		}
	}
	return steps, nil
}

func launchScan(ctx context.Context, ips []string, cfg ScanConfig, steps []scanner.Step, pipelineCh chan pipelineProgressMsg, doneCh chan scanDoneMsg) {
	// Apply EDNS buffer size before scanning
	if cfg.EDNSSize > 0 {
		scanner.EDNSBufSize = uint16(cfg.EDNSSize)
	}
	scanner.DnsttMTU = cfg.QuerySize

	if len(steps) == 0 {
		doneCh <- scanDoneMsg{err: fmt.Errorf("no scan steps configured")}
		close(pipelineCh)
		return
	}

	go func() {
		defer close(pipelineCh)
		defer func() {
			if r := recover(); r != nil {
				doneCh <- scanDoneMsg{err: fmt.Errorf("scan panicked: %v", r)}
			}
		}()

		// Open IP list file for live appending
		var ipFile *os.File
		if cfg.OutputFile != "" {
			ipPath := strings.TrimSuffix(cfg.OutputFile, ".json") + "_ips.txt"
			f, err := os.OpenFile(ipPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err == nil {
				ipFile = f
				defer ipFile.Close()
			}
		}

		start := time.Now()
		ch := scanner.RunPipeline(ctx, ips, cfg.Workers, steps)

		stepTested := make([]int, len(steps))
		stepPassed := make([]int, len(steps))
		stepFailed := make([]int, len(steps))

		var report scanner.ChainReport
		var done, pass, fail int
		total := len(ips)

		for r := range ch {
			done++

			var latestIP string
			var latestMetrics scanner.Metrics

			if r.FailedStep == -1 {
				for si := range steps {
					stepTested[si]++
					stepPassed[si]++
				}
				pass++
				report.Passed = append(report.Passed, scanner.IPRecord{IP: r.IP, Metrics: r.Metrics})
				latestIP = r.IP
				latestMetrics = r.Metrics
				// Live append to IP file
				if ipFile != nil {
					fmt.Fprintln(ipFile, r.IP)
				}
			} else {
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

			// Send progress update
			select {
			case pipelineCh <- pipelineProgressMsg{
				done:          done,
				total:         total,
				passed:        pass,
				failed:        fail,
				latestIP:      latestIP,
				latestMetrics: latestMetrics,
				stepTested:    append([]int{}, stepTested...),
				stepPassed:    append([]int{}, stepPassed...),
				stepFailed:    append([]int{}, stepFailed...),
			}:
			default:
			}
		}

		// Build step results
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

		elapsed := time.Since(start)
		var writeErr error
		if cfg.OutputFile != "" {
			writeErr = scanner.WriteChainReport(report, cfg.OutputFile)
			if writeErr == nil && len(report.Passed) > 0 {
				ipFile := strings.TrimSuffix(cfg.OutputFile, ".json") + "_ips.txt"
				_ = scanner.WriteIPList(report.Passed, ipFile)
			}
		}
		doneCh <- scanDoneMsg{report: report, elapsed: elapsed, writeErr: writeErr}
	}()
}

func waitForPipeline(ch chan pipelineProgressMsg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

func waitForDone(ch chan scanDoneMsg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}

func updateRunning(m Model, msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case scanStartedMsg:
		m.pipelineCh = msg.pipelineCh
		m.doneCh = msg.doneCh
		m.scanStart = time.Now()
		m.pipelineDone = 0
		m.pipelineTotal = len(m.ips)
		m.pipelinePassed = 0
		m.pipelineFailed = 0
		m.recentPassed = nil

		steps, err := buildSteps(m.config)
		if err != nil {
			m.err = err
			m.screen = screenConfig
			return m, nil
		}
		m.steps = make([]stepProgress, len(steps))
		for i, s := range steps {
			m.steps[i] = stepProgress{name: s.Name}
		}
		m.pStepTested = make([]int, len(steps))
		m.pStepPassed = make([]int, len(steps))
		m.pStepFailed = make([]int, len(steps))

		ctx, cancel := context.WithCancel(context.Background())
		m.scanCancel = cancel

		scanner.ResetE2EDiagnostic()
		launchScan(ctx, m.ips, m.config, steps, msg.pipelineCh, msg.doneCh)

		return m, tea.Batch(
			waitForPipeline(msg.pipelineCh),
			waitForDone(msg.doneCh),
			tickCmd(),
		)

	case pipelineProgressMsg:
		m.pipelineDone = msg.done
		m.pipelinePassed = msg.passed
		m.pipelineFailed = msg.failed

		// Update per-step stats
		copy(m.pStepTested, msg.stepTested)
		copy(m.pStepPassed, msg.stepPassed)
		copy(m.pStepFailed, msg.stepFailed)

		// Track ALL passed IPs and auto-scroll to bottom
		if msg.latestIP != "" {
			m.recentPassed = append(m.recentPassed, scanner.IPRecord{
				IP: msg.latestIP, Metrics: msg.latestMetrics,
			})
			// Auto-scroll to show latest result
			visRows := m.liveVisibleRows()
			if len(m.recentPassed) > visRows {
				m.resultsScroll = len(m.recentPassed) - visRows
			}
		}

		return m, waitForPipeline(m.pipelineCh)

	case scanDoneMsg:
		m.report = msg.report
		m.totalTime = msg.elapsed
		if msg.err != nil {
			m.err = msg.err
		}
		if msg.writeErr != nil {
			if m.err != nil {
				m.err = fmt.Errorf("%v; also failed to save results: %v", m.err, msg.writeErr)
			} else {
				m.err = fmt.Errorf("failed to save results: %w", msg.writeErr)
			}
		}
		m.screen = screenResults
		m.cursor = 0
		m.scroll = 0
		return m, nil

	case tickMsg:
		return m, tickCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.scanCancel != nil {
				m.scanCancel()
			}
			return m, tea.Quit
		case "q":
			if m.scanCancel != nil && !m.cancelling {
				m.scanCancel()
				m.cancelling = true
			}
		case "up", "k":
			if m.resultsScroll > 0 {
				m.resultsScroll--
			}
		case "down", "j":
			maxScroll := len(m.recentPassed) - m.liveVisibleRows()
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.resultsScroll < maxScroll {
				m.resultsScroll++
			}
		}
	}
	return m, nil
}

// liveVisibleRows returns how many result rows fit during scanning.
func (m Model) liveVisibleRows() int {
	// Overhead: title(2) + progress(3) + pipeline(2) + steps(N+2) + results_header(2) + scroll_hint(1) + footer(3)
	overhead := 15 + len(m.steps)
	rows := m.height - overhead
	if rows < 3 {
		rows = 3
	}
	return rows
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func viewRunning(m Model) string {
	var b strings.Builder

	elapsed := time.Since(m.scanStart).Truncate(time.Second)

	b.WriteString("\n")
	if m.cancelling {
		b.WriteString(yellowStyle.Render("  Cancelling..."))
	} else {
		b.WriteString(titleStyle.Render("  Scanning..."))
	}
	b.WriteString("  ")
	b.WriteString(dimStyle.Render(elapsed.String()))
	b.WriteString("\n\n")

	// Overall progress bar
	total := m.pipelineTotal
	if total == 0 {
		total = len(m.ips)
	}
	pct := 0
	if total > 0 {
		pct = m.pipelineDone * 100 / total
	}
	bar := progressBar(pct, 30)
	b.WriteString(fmt.Sprintf("  %s  %d/%d  ", bar, m.pipelineDone, total))
	b.WriteString(greenStyle.Render(fmt.Sprintf("%d passed", m.pipelinePassed)))
	b.WriteString("  ")
	b.WriteString(redStyle.Render(fmt.Sprintf("%d failed", m.pipelineFailed)))
	b.WriteString("\n\n")

	// Pipeline steps
	b.WriteString(dimStyle.Render("  Pipeline: "))
	for i, step := range m.steps {
		if i > 0 {
			b.WriteString(dimStyle.Render(" → "))
		}
		b.WriteString(dimStyle.Render(step.name))
	}
	b.WriteString("\n\n")

	// Per-step breakdown
	b.WriteString(dimStyle.Render("  Step breakdown:"))
	b.WriteString("\n")
	for i, step := range m.steps {
		tested := 0
		passed := 0
		if i < len(m.pStepTested) {
			tested = m.pStepTested[i]
			passed = m.pStepPassed[i]
		}
		passRate := 0
		if tested > 0 {
			passRate = passed * 100 / tested
		}

		icon := dimStyle.Render("○")
		if tested > 0 {
			if passRate >= 50 {
				icon = greenStyle.Render("✔")
			} else if passRate >= 20 {
				icon = yellowStyle.Render("◉")
			} else {
				icon = redStyle.Render("✘")
			}
		}

		b.WriteString(fmt.Sprintf("    %s %-18s ", icon, step.name))
		if tested > 0 {
			b.WriteString(greenStyle.Render(fmt.Sprintf("%d", passed)))
			b.WriteString(dimStyle.Render(fmt.Sprintf("/%d ", tested)))
			b.WriteString(dimStyle.Render(fmt.Sprintf("(%d%%)", passRate)))
		} else {
			b.WriteString(dimStyle.Render("waiting..."))
		}
		b.WriteString("\n")
	}

	// Passed IPs — scrollable table with all metrics
	if len(m.recentPassed) > 0 {
		b.WriteString("\n")
		b.WriteString(greenStyle.Render(fmt.Sprintf("  Passed: %d", len(m.recentPassed))))
		b.WriteString("\n")

		// Determine metric columns from first result
		var metricKeys []string
		if m.recentPassed[0].Metrics != nil {
			for k := range m.recentPassed[0].Metrics {
				metricKeys = append(metricKeys, k)
			}
			sort.Strings(metricKeys)
		}

		// Header
		header := fmt.Sprintf("  %-4s %-17s", "#", "IP")
		for _, k := range metricKeys {
			header += fmt.Sprintf("  %-10s", k)
		}
		b.WriteString(dimStyle.Render(header))
		b.WriteString("\n")

		// Visible rows
		visRows := m.liveVisibleRows()
		start := m.resultsScroll
		end := start + visRows
		if end > len(m.recentPassed) {
			end = len(m.recentPassed)
		}
		if start > len(m.recentPassed) {
			start = len(m.recentPassed)
		}

		for i := start; i < end; i++ {
			r := m.recentPassed[i]
			row := fmt.Sprintf("  %-4d %-17s", i+1, r.IP)
			for _, k := range metricKeys {
				if r.Metrics == nil {
					row += fmt.Sprintf("  %-10s", "-")
				} else if v, ok := r.Metrics[k]; ok {
					if v == float64(int(v)) {
						row += fmt.Sprintf("  %-10d", int(v))
					} else {
						row += fmt.Sprintf("  %-10.1f", v)
					}
				} else {
					row += fmt.Sprintf("  %-10s", "-")
				}
			}
			b.WriteString(greenStyle.Render("  ✔"))
			b.WriteString(row[3:]) // skip leading spaces already covered by ✔
			b.WriteString("\n")
		}

		if len(m.recentPassed) > visRows {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  Showing %d-%d of %d  (↑/↓ scroll)",
				start+1, end, len(m.recentPassed))))
			b.WriteString("\n")
		}
	} else {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  Waiting for results..."))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if m.cancelling {
		b.WriteString(yellowStyle.Render("  Cancelling... waiting for workers"))
	} else {
		b.WriteString(dimStyle.Render("  ↑/↓ scroll results  q cancel  ctrl+c quit"))
	}
	b.WriteString("\n")

	return b.String()
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	var b strings.Builder
	for i := 0; i < width; i++ {
		if i < filled {
			b.WriteRune('█')
		} else {
			b.WriteRune('░')
		}
	}
	return b.String()
}
