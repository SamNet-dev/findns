package tui

import (
	"context"
	"fmt"
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
				Check: scanner.DoHDnsttCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, ports), SortBy: "e2e_ms",
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
				Check: scanner.DnsttCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, ports), SortBy: "socks_ms",
			})
			if cfg.Throughput {
				steps = append(steps, scanner.Step{
					Name: "throughput/dnstt", Timeout: e2eDur,
					Check: scanner.ThroughputCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, ports), SortBy: "throughput_ms",
				})
			}
		}
		if cfg.Domain != "" && cfg.Cert != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/slipstream", Timeout: e2eDur,
				Check: scanner.SlipstreamCheckBin(slipstreamBin, cfg.Domain, cfg.Cert, ports), SortBy: "e2e_ms",
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

		// Track recent passed IPs (last 8)
		if msg.latestIP != "" {
			m.recentPassed = append(m.recentPassed, scanner.IPRecord{
				IP: msg.latestIP, Metrics: msg.latestMetrics,
			})
			if len(m.recentPassed) > 8 {
				m.recentPassed = m.recentPassed[len(m.recentPassed)-8:]
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
		if msg.String() == "ctrl+c" {
			if m.scanCancel != nil {
				m.scanCancel()
			}
			return m, tea.Quit
		}
		if msg.String() == "q" {
			if m.scanCancel != nil && !m.cancelling {
				m.scanCancel()
				m.cancelling = true
			}
		}
	}
	return m, nil
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

	// Recent passed IPs
	if len(m.recentPassed) > 0 {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  Recent results:"))
		b.WriteString("\n")
		for _, r := range m.recentPassed {
			var parts []string
			if r.Metrics != nil {
				keys := make([]string, 0, len(r.Metrics))
				for k := range r.Metrics {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					v := r.Metrics[k]
					if v == float64(int(v)) {
						parts = append(parts, fmt.Sprintf("%s=%d", k, int(v)))
					} else {
						parts = append(parts, fmt.Sprintf("%s=%.1f", k, v))
					}
				}
			}
			b.WriteString(fmt.Sprintf("    %s %-15s  %s\n",
				greenStyle.Render("✔"), r.IP,
				dimStyle.Render(strings.Join(parts, "  "))))
		}
	}

	b.WriteString("\n")
	if m.cancelling {
		b.WriteString(yellowStyle.Render("  Cancelling... waiting for workers"))
	} else {
		b.WriteString(dimStyle.Render("  q cancel  ctrl+c quit"))
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
