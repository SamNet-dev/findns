package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Test NS delegation and glue record resolution for tunnel domain",
	RunE:  runTunnel,
}

func init() {
	tunnelCmd.Flags().String("domain", "", "tunnel domain to check NS for")
	tunnelCmd.MarkFlagRequired("domain")
	resolveCmd.AddCommand(tunnelCmd)
}

func runTunnel(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.TunnelCheck(domain, count)

	start := time.Now()
	results := scanner.RunPool(ips, workers, dur, check, newProgress("resolve/tunnel"))
	elapsed := time.Since(start)

	return writeReport("resolve/tunnel", results, elapsed, "resolve_ms")
}
