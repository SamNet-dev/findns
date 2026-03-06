package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var e2eSlipstreamCmd = &cobra.Command{
	Use:   "slipstream",
	Short: "Test e2e connectivity through Slipstream SOCKS tunnel",
	RunE:  runE2ESlipstream,
}

func init() {
	e2eSlipstreamCmd.Flags().String("domain", "", "Slipstream tunnel domain")
	e2eSlipstreamCmd.Flags().String("cert", "", "path to Slipstream certificate for cert pinning (optional)")
	e2eSlipstreamCmd.Flags().String("test-url", "https://httpbin.org/ip", "URL to fetch through tunnel")
	e2eSlipstreamCmd.MarkFlagRequired("domain")
	e2eCmd.AddCommand(e2eSlipstreamCmd)
}

func runE2ESlipstream(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	certPath, _ := cmd.Flags().GetString("cert")
	testURL, _ := cmd.Flags().GetString("test-url")

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(e2eTimeout) * time.Second
	ports := scanner.PortPool(30000, workers)
	check := scanner.SlipstreamCheck(domain, certPath, testURL, ports)

	start := time.Now()
	results := scanner.RunPool(ips, workers, dur, check, newProgress("e2e/slipstream"))
	elapsed := time.Since(start)

	return writeReport("e2e/slipstream", results, elapsed, "e2e_ms")
}
