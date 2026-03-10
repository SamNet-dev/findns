package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SamNet-dev/findns/internal/scanner"
	tea "github.com/charmbracelet/bubbletea"
)

func updateResults(m Model, msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "down", "j":
			max := len(m.report.Passed) - m.visibleRows()
			if max < 0 {
				max = 0
			}
			if m.scroll < max {
				m.scroll++
			}
		}
	}
	return m, nil
}

func (m Model) visibleRows() int {
	// Overhead: title(3) + steps + spacing(4) + passed(1) + table header(1) + scroll(2) + output(2) + footer(2)
	overhead := 15 + len(m.report.Steps)
	rows := m.height - overhead
	if rows < 5 {
		rows = 5
	}
	return rows
}

func viewResults(m Model) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render("  Results"))
	b.WriteString("  ")
	b.WriteString(dimStyle.Render(m.totalTime.Truncate(1e6).String()))
	b.WriteString("\n\n")

	if m.err != nil {
		b.WriteString(redStyle.Render(fmt.Sprintf("  Error: %v", m.err)))
		b.WriteString("\n\n")
	}

	// Step summary
	for _, step := range m.report.Steps {
		pct := 0
		if step.Tested > 0 {
			pct = step.Passed * 100 / step.Tested
		}
		icon := greenStyle.Render("✔")
		color := greenStyle
		if pct < 50 {
			icon = yellowStyle.Render("⚠")
			color = yellowStyle
		}
		if pct < 20 {
			icon = redStyle.Render("✘")
			color = redStyle
		}
		b.WriteString(fmt.Sprintf("  %s %-18s %s  %.1fs\n",
			icon, step.Name,
			color.Render(fmt.Sprintf("%d/%d (%d%%)", step.Passed, step.Tested, pct)),
			step.Seconds))
	}

	b.WriteString("\n")

	if len(m.report.Passed) == 0 {
		b.WriteString(redStyle.Render("  ✘ No resolvers passed all steps"))
		b.WriteString("\n")
		if diag := scanner.E2EDiagnostic(); diag != "" {
			b.WriteString(yellowStyle.Render("  ⚠ " + diag))
			b.WriteString("\n")
		}
	} else {
		b.WriteString(greenStyle.Render(fmt.Sprintf("  ✔ %d resolvers passed all steps", len(m.report.Passed))))
		b.WriteString("\n\n")

		// Determine metric columns from first result
		var metricKeys []string
		if len(m.report.Passed) > 0 && m.report.Passed[0].Metrics != nil {
			for k := range m.report.Passed[0].Metrics {
				metricKeys = append(metricKeys, k)
			}
			sort.Strings(metricKeys)
		}

		// Header
		header := fmt.Sprintf("  %-4s %-17s", "#", "IP")
		for _, k := range metricKeys {
			header += fmt.Sprintf("  %-12s", k)
		}
		b.WriteString(headerStyle.Render(header))
		b.WriteString("\n")

		// Rows
		visible := m.visibleRows()
		end := m.scroll + visible
		if end > len(m.report.Passed) {
			end = len(m.report.Passed)
		}

		for i := m.scroll; i < end; i++ {
			r := m.report.Passed[i]
			row := fmt.Sprintf("  %-4d %-17s", i+1, r.IP)
			for _, k := range metricKeys {
				if v, ok := r.Metrics[k]; ok {
					row += fmt.Sprintf("  %-12s", formatMetric(v))
				} else {
					row += fmt.Sprintf("  %-12s", "-")
				}
			}
			b.WriteString(row)
			b.WriteString("\n")
		}

		if len(m.report.Passed) > visible {
			b.WriteString(dimStyle.Render(fmt.Sprintf("\n  Showing %d-%d of %d  (↑/↓ to scroll)",
				m.scroll+1, end, len(m.report.Passed))))
			b.WriteString("\n")
		}
	}

	if m.config.OutputFile != "" {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render(fmt.Sprintf("  Saved to %s", m.config.OutputFile)))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  q quit"))
	b.WriteString("\n")

	return b.String()
}

func formatMetric(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d", int(v))
	}
	return fmt.Sprintf("%.1f", v)
}
