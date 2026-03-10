package tui

import (
	"context"
	"fmt"
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
		progressCh := make(chan progressMsg, 200)
		doneCh := make(chan scanDoneMsg, 1)
		return scanStartedMsg{progressCh: progressCh, doneCh: doneCh}
	}
}

func buildSteps(cfg ScanConfig) ([]scanner.Step, error) {
	dur := time.Duration(cfg.Timeout) * time.Second
	e2eTimeout := cfg.E2ETimeout
	if e2eTimeout <= 0 {
		e2eTimeout = 15
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
	if needE2E {
		if _, err := binutil.Find("curl"); err != nil {
			return nil, fmt.Errorf("e2e tests require curl in PATH")
		}
	}

	var ports chan int
	if needE2E {
		ports = scanner.PortPool(30000, cfg.Workers)
	}

	if cfg.DoH {
		steps = append(steps, scanner.Step{
			Name: "doh/resolve", Timeout: dur,
			Check: scanner.DoHResolveCheck("google.com", cfg.Count), SortBy: "resolve_ms",
		})
		if cfg.Domain != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/resolve/tunnel", Timeout: dur,
				Check: scanner.DoHTunnelCheck(cfg.Domain, cfg.Count), SortBy: "resolve_ms",
			})
		}
		if cfg.Domain != "" && cfg.Pubkey != "" {
			steps = append(steps, scanner.Step{
				Name: "doh/e2e", Timeout: e2eDur,
				Check: scanner.DoHDnsttCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, cfg.TestURL, cfg.ProxyAuth, ports), SortBy: "e2e_ms",
			})
		}
	} else {
		if !cfg.SkipPing {
			steps = append(steps, scanner.Step{
				Name: "ping", Timeout: dur,
				Check: scanner.PingCheck(cfg.Count), SortBy: "ping_ms",
			})
		}
		steps = append(steps, scanner.Step{
			Name: "resolve", Timeout: dur,
			Check: scanner.ResolveCheck("google.com", cfg.Count), SortBy: "resolve_ms",
		})
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
				Check: scanner.DnsttCheckBin(dnsttBin, cfg.Domain, cfg.Pubkey, cfg.TestURL, cfg.ProxyAuth, ports), SortBy: "e2e_ms",
			})
		}
		if cfg.Domain != "" && cfg.Cert != "" {
			steps = append(steps, scanner.Step{
				Name: "e2e/slipstream", Timeout: e2eDur,
				Check: scanner.SlipstreamCheckBin(slipstreamBin, cfg.Domain, cfg.Cert, cfg.TestURL, cfg.ProxyAuth, ports), SortBy: "e2e_ms",
			})
		}
	}
	return steps, nil
}

func launchScan(ctx context.Context, ips []string, cfg ScanConfig, steps []scanner.Step, progressCh chan progressMsg, doneCh chan scanDoneMsg) {
	if len(steps) == 0 {
		doneCh <- scanDoneMsg{err: fmt.Errorf("no scan steps configured")}
		close(progressCh)
		return
	}

	stepIdx := 0
	factory := func(stepName string) scanner.ProgressFunc {
		idx := stepIdx
		stepIdx++
		return func(done, total, passed, failed int) {
			select {
			case progressCh <- progressMsg{
				stepIndex: idx,
				done:      done,
				total:     total,
				passed:    passed,
				failed:    failed,
			}:
			default:
				// Drop update if buffer full — avoids blocking the scanner
			}
		}
	}

	go func() {
		defer close(progressCh)
		defer func() {
			if r := recover(); r != nil {
				doneCh <- scanDoneMsg{err: fmt.Errorf("scan panicked: %v", r)}
			}
		}()
		start := time.Now()
		report := scanner.RunChainQuietCtx(ctx, ips, cfg.Workers, steps, factory)
		elapsed := time.Since(start)
		var writeErr error
		if cfg.OutputFile != "" {
			writeErr = scanner.WriteChainReport(report, cfg.OutputFile)
		}
		doneCh <- scanDoneMsg{report: report, elapsed: elapsed, writeErr: writeErr}
	}()
}

func waitForProgress(ch chan progressMsg) tea.Cmd {
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
		m.progressCh = msg.progressCh
		m.doneCh = msg.doneCh
		m.scanStart = time.Now()

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

		ctx, cancel := context.WithCancel(context.Background())
		m.scanCancel = cancel

		scanner.ResetE2EDiagnostic()
		launchScan(ctx, m.ips, m.config, steps, msg.progressCh, msg.doneCh)

		return m, tea.Batch(
			waitForProgress(msg.progressCh),
			waitForDone(msg.doneCh),
			tickCmd(),
		)

	case progressMsg:
		if msg.stepIndex < len(m.steps) {
			m.steps[msg.stepIndex].done = msg.done
			m.steps[msg.stepIndex].total = msg.total
			m.steps[msg.stepIndex].passed = msg.passed
			m.steps[msg.stepIndex].failed = msg.failed
			if msg.done == msg.total && msg.total > 0 {
				m.steps[msg.stepIndex].finished = true
			}
		}
		return m, waitForProgress(m.progressCh)

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

	for _, step := range m.steps {
		icon := dimStyle.Render("○")
		if step.finished {
			if step.passed > 0 {
				icon = greenStyle.Render("✔")
			} else {
				icon = redStyle.Render("✘")
			}
		} else if step.total > 0 {
			icon = yellowStyle.Render("◉")
		}

		pct := 0
		if step.total > 0 {
			pct = step.done * 100 / step.total
		}

		bar := progressBar(pct, 20)

		b.WriteString(fmt.Sprintf("  %s %-18s %s  %d/%d  ",
			icon, step.name, bar, step.done, step.total))
		b.WriteString(greenStyle.Render(fmt.Sprintf("%d✔", step.passed)))
		b.WriteString("  ")
		b.WriteString(redStyle.Render(fmt.Sprintf("%d✘", step.failed)))
		b.WriteString("\n")
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
