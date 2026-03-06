package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var dohTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Test NS delegation and glue resolution via DoH resolver",
	RunE:  runDoHTunnel,
}

func init() {
	dohTunnelCmd.Flags().String("domain", "", "tunnel domain to check NS for")
	dohTunnelCmd.MarkFlagRequired("domain")
	dohResolveCmd.AddCommand(dohTunnelCmd)
}

func runDoHTunnel(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")

	urls, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.DoHTunnelCheck(domain, count)

	start := time.Now()
	results := scanner.RunPool(urls, workers, dur, check, newProgress("doh/resolve/tunnel"))
	elapsed := time.Since(start)

	return writeReport("doh/resolve/tunnel", results, elapsed, "resolve_ms")
}
