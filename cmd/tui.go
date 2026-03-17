package main

import (
	"github.com/SamNet-dev/findns/internal/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive terminal UI for scanning",
	Long: `Launch an interactive menu-driven interface.

All flags are optional — they pre-populate the TUI configuration fields.
You can still change any value from the TUI before starting the scan.

Examples:
  findns tui
  findns tui --domain t.example.com --workers 100 --skip-ping
  findns tui --doh --edns --output results.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.RunWithConfig(buildTUIConfig(cmd))
	},
}

func init() {
	f := tuiCmd.Flags()
	f.String("domain", "", "tunnel domain (e.g. t.example.com)")
	f.String("pubkey", "", "hex public key for dnstt e2e test")
	f.String("cert", "", "TLS cert path for slipstream e2e test")
	f.Bool("skip-ping", false, "skip ICMP ping step")
	f.Bool("skip-nxdomain", false, "skip NXDOMAIN hijack detection")
	f.Bool("edns", false, "enable EDNS0 payload size check")
	f.Bool("e2e", false, "enable end-to-end tunnel testing")
	f.Bool("doh", false, "use DNS-over-HTTPS mode")

	rootCmd.AddCommand(tuiCmd)
}

// buildTUIConfig reads cobra flags and persistent flags into a ScanConfig.
// Zero values mean "use default" — NewModelWithConfig handles defaults.
func buildTUIConfig(cmd *cobra.Command) tui.ScanConfig {
	cfg := tui.ScanConfig{}

	// Local flags
	cfg.Domain, _ = cmd.Flags().GetString("domain")
	cfg.Pubkey, _ = cmd.Flags().GetString("pubkey")
	cfg.Cert, _ = cmd.Flags().GetString("cert")
	cfg.SkipPing, _ = cmd.Flags().GetBool("skip-ping")
	cfg.SkipNXDomain, _ = cmd.Flags().GetBool("skip-nxdomain")
	cfg.EDNS, _ = cmd.Flags().GetBool("edns")
	cfg.E2E, _ = cmd.Flags().GetBool("e2e")
	cfg.DoH, _ = cmd.Flags().GetBool("doh")

	// Persistent flags from root (shared with CLI commands)
	cfg.OutputFile = outputFile
	cfg.Workers = workers
	cfg.Timeout = timeout
	cfg.Count = count
	cfg.E2ETimeout = e2eTimeout

	return cfg
}
