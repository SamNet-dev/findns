package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

var modeChoices = []string{
	"UDP Scan        Scan plain DNS resolvers (port 53)",
	"DoH Scan        Scan DNS-over-HTTPS resolvers (port 443)",
	"CLI Flags       Pre-fill config from command-line flags",
}

func updateWelcome(m Model, msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// CLI flags text input mode
		if m.typingCLI {
			switch msg.String() {
			case "enter":
				raw := m.cliInput.Value()
				if raw != "" {
					parseCLIFlags(&m, raw)
				}
				m.typingCLI = false
				m.screen = screenInput
				m.cursor = 0
				return m, nil
			case "esc":
				m.typingCLI = false
				return m, nil
			}
			var cmd tea.Cmd
			m.cliInput, cmd = m.cliInput.Update(msg)
			return m, cmd
		}

		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(modeChoices)-1 {
				m.cursor++
			}
		case "enter":
			if m.cursor == 2 {
				// CLI Flags mode
				m.typingCLI = true
				m.cliInput = textinput.New()
				m.cliInput.Placeholder = "--domain t.example.com --workers 100 --skip-ping"
				m.cliInput.CharLimit = 1024
				m.cliInput.Width = 70
				m.cliInput.Focus()
				return m, m.cliInput.Cursor.BlinkCmd()
			}
			m.config.DoH = m.cursor == 1
			m.screen = screenInput
			m.cursor = 0
			return m, nil
		}
	}
	return m, nil
}

// parseCLIFlags parses a raw flag string and applies values to the model config + text inputs.
func parseCLIFlags(m *Model, raw string) {
	args := splitArgs(raw)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := ""
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			next = args[i+1]
		}
		switch arg {
		case "--domain":
			if next != "" {
				m.config.Domain = next
				m.configInputs[txtDomain].SetValue(next)
				i++
			}
		case "--pubkey":
			if next != "" {
				m.config.Pubkey = next
				m.configInputs[txtPubkey].SetValue(next)
				m.config.E2E = true
				i++
			}
		case "--cert":
			if next != "" {
				m.config.Cert = next
				m.configInputs[txtCert].SetValue(next)
				m.config.E2E = true
				i++
			}
		case "--test-url":
			if next != "" {
				m.config.TestURL = next
				m.configInputs[txtTestURL].SetValue(next)
				i++
			}
		case "--proxy-auth":
			if next != "" {
				m.config.ProxyAuth = next
				m.configInputs[txtProxyAuth].SetValue(next)
				i++
			}
		case "--output", "-o":
			if next != "" {
				m.config.OutputFile = next
				m.configInputs[txtOutput].SetValue(next)
				i++
			}
		case "--workers":
			if next != "" {
				fmt.Sscanf(next, "%d", &m.config.Workers)
				m.configInputs[txtWorkers].SetValue(next)
				i++
			}
		case "--timeout", "-t":
			if next != "" {
				fmt.Sscanf(next, "%d", &m.config.Timeout)
				m.configInputs[txtTimeout].SetValue(next)
				i++
			}
		case "--count", "-c":
			if next != "" {
				fmt.Sscanf(next, "%d", &m.config.Count)
				m.configInputs[txtCount].SetValue(next)
				i++
			}
		case "--e2e-timeout":
			if next != "" {
				fmt.Sscanf(next, "%d", &m.config.E2ETimeout)
				m.configInputs[txtE2ETimeout].SetValue(next)
				i++
			}
		case "--skip-ping":
			m.config.SkipPing = true
		case "--skip-nxdomain":
			m.config.SkipNXDomain = true
		case "--edns":
			m.config.EDNS = true
		case "--edns-size":
			if next != "" {
				fmt.Sscanf(next, "%d", &m.config.EDNSSize)
				m.configInputs[txtEDNSSize].SetValue(next)
				i++
			}
		case "--e2e":
			m.config.E2E = true
		case "--doh":
			m.config.DoH = true
		}
	}
}

// splitArgs splits a string into args, respecting quoted strings.
func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range s {
		if inQuote {
			if r == quoteChar {
				inQuote = false
			} else {
				current.WriteRune(r)
			}
		} else if r == '"' || r == '\'' {
			inQuote = true
			quoteChar = r
		} else if r == ' ' || r == '\t' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func viewWelcome(m Model) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render("  findns"))
	b.WriteString("  ")
	b.WriteString(dimStyle.Render("DNS Tunnel Resolver Scanner"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  by Sam  •  github.com/SamNet-dev/findns"))
	b.WriteString("\n\n")

	// About
	b.WriteString(dimStyle.Render("  Finds DNS resolvers compatible with DNS tunneling (DNSTT/Slipstream)."))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  Tests: ping, resolve, NXDOMAIN hijack, EDNS payload, tunnel delegation, e2e."))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  Supports UDP (port 53) and DoH (port 443) with live progress and ranked results."))
	b.WriteString("\n\n")

	// Mode selection
	b.WriteString(normalStyle.Render("  Select scan mode:"))
	b.WriteString("\n\n")

	for i, choice := range modeChoices {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(choice)))
	}

	if m.typingCLI {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  Enter flags (same as CLI):"))
		b.WriteString("\n\n")
		b.WriteString("  " + m.cliInput.View())
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("  Examples:"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("    --domain t.example.com --workers 100 --skip-ping"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("    --doh --edns --output results.json"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("    --e2e --pubkey abc123 --cert cert.pem"))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("  enter confirm  esc cancel"))
		b.WriteString("\n")
	} else {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  ↑/↓ navigate  enter select  q quit"))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("  Full docs: README.md and GUIDE.md in the repo"))
		b.WriteString("\n")
	}

	return b.String()
}
