package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenWelcome screen = iota
	screenInput
	screenConfig
	screenRunning
	screenResults
)

type ScanConfig struct {
	Domain       string
	Pubkey       string
	Cert         string
	Workers      int
	Timeout      int
	Count        int
	E2ETimeout   int
	EDNSSize     int
	QuerySize    int
	SkipPing     bool
	SkipNXDomain bool
	EDNS         bool
	E2E            bool
	DoH            bool
	Discover       bool
	DiscoverRounds int
	Throughput     bool
	SocksUser      string
	SocksPass      string
	ConnectAddr    string
	OutputFile     string
}

type Model struct {
	screen screen
	cursor int
	width  int
	height int
	err    error

	// Welcome screen
	typingCLI bool
	cliInput  textinput.Model

	// Input screen
	ips         []string
	loading     bool
	typingPath  bool
	pathInput   textinput.Model
	typingCIDR  bool
	cidrInput   textinput.Model

	// Config screen
	config       ScanConfig
	configInputs []textinput.Model

	// Running screen
	steps      []stepProgress
	scanStart  time.Time
	scanCancel context.CancelFunc
	cancelling bool
	progressCh chan progressMsg
	pipelineCh chan pipelineProgressMsg
	doneCh     chan scanDoneMsg

	// Pipeline tracking
	pipelineDone   int
	pipelineTotal  int
	pipelinePassed int
	pipelineFailed int
	recentPassed   []scanner.IPRecord
	resultsScroll  int // scroll offset for live results during scan
	pStepTested    []int
	pStepPassed    []int
	pStepFailed    []int

	// Results screen
	report    scanner.ChainReport
	totalTime time.Duration
	scroll    int
}

func NewModel() Model {
	return NewModelWithConfig(ScanConfig{})
}

// NewModelWithConfig creates a Model pre-populated with the given config.
// Zero-value fields fall back to defaults.
func NewModelWithConfig(cfg ScanConfig) Model {
	// Apply defaults for zero-value fields
	if cfg.Workers <= 0 {
		cfg.Workers = 50
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3
	}
	if cfg.Count <= 0 {
		cfg.Count = 3
	}
	if cfg.E2ETimeout <= 0 {
		cfg.E2ETimeout = 15
	}
	if cfg.EDNSSize <= 0 {
		cfg.EDNSSize = 1232
	}

	inputs := initConfigInputs()

	// Pre-populate text inputs from config
	if cfg.Domain != "" {
		inputs[txtDomain].SetValue(cfg.Domain)
	}
	if cfg.Pubkey != "" {
		inputs[txtPubkey].SetValue(cfg.Pubkey)
	}
	if cfg.Cert != "" {
		inputs[txtCert].SetValue(cfg.Cert)
	}
	if cfg.OutputFile != "" {
		inputs[txtOutput].SetValue(cfg.OutputFile)
	}
	inputs[txtWorkers].SetValue(fmt.Sprintf("%d", cfg.Workers))
	inputs[txtTimeout].SetValue(fmt.Sprintf("%d", cfg.Timeout))
	inputs[txtCount].SetValue(fmt.Sprintf("%d", cfg.Count))
	inputs[txtEDNSSize].SetValue(fmt.Sprintf("%d", cfg.EDNSSize))
	inputs[txtQuerySize].SetValue(fmt.Sprintf("%d", cfg.QuerySize))
	inputs[txtE2ETimeout].SetValue(fmt.Sprintf("%d", cfg.E2ETimeout))

	return Model{
		screen:       screenWelcome,
		config:       cfg,
		configInputs: inputs,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			if m.screen == screenRunning {
				return updateRunning(m, msg)
			}
			return m, tea.Quit
		}
		// Only intercept 'q' on screens where no text input is active
		if msg.String() == "q" {
			switch m.screen {
			case screenWelcome:
				if !m.typingCLI {
					return m, tea.Quit
				}
			case screenResults:
				return m, tea.Quit
			case screenRunning:
				return updateRunning(m, msg)
			case screenInput:
				if !m.typingPath && !m.typingCIDR {
					return m, tea.Quit
				}
			// Config screen: let 'q' pass to text inputs
			}
		}
	}

	switch m.screen {
	case screenWelcome:
		return updateWelcome(m, msg)
	case screenInput:
		return updateInput(m, msg)
	case screenConfig:
		return updateConfig(m, msg)
	case screenRunning:
		return updateRunning(m, msg)
	case screenResults:
		return updateResults(m, msg)
	}

	return m, nil
}

func (m Model) View() string {
	switch m.screen {
	case screenWelcome:
		return viewWelcome(m)
	case screenInput:
		return viewInput(m)
	case screenConfig:
		return viewConfig(m)
	case screenRunning:
		return viewRunning(m)
	case screenResults:
		return viewResults(m)
	}

	return ""
}

func Run() error {
	return RunWithConfig(ScanConfig{})
}

// RunWithConfig launches the TUI with pre-populated configuration from CLI flags.
func RunWithConfig(cfg ScanConfig) error {
	p := tea.NewProgram(NewModelWithConfig(cfg), tea.WithAltScreen())
	_, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}
	return nil
}
