package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var nxdomainCmd = &cobra.Command{
	Use:   "nxdomain",
	Short: "Test NXDOMAIN integrity (detect DNS hijacking)",
	RunE:  runNXDomain,
}

func init() {
	rootCmd.AddCommand(nxdomainCmd)
}

func runNXDomain(cmd *cobra.Command, args []string) error {
	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.NXDomainCheck(count)

	start := time.Now()
	results := scanner.RunPool(ips, workers, dur, check, newProgress("nxdomain"))
	elapsed := time.Since(start)

	return writeReport("nxdomain", results, elapsed, "hijack")
}
