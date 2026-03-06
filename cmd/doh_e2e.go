package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var dohE2ECmd = &cobra.Command{
	Use:   "e2e",
	Short: "Test e2e connectivity through DNSTT tunnel using DoH resolver",
	RunE:  runDoHE2E,
}

func init() {
	dohE2ECmd.Flags().String("domain", "", "DNSTT tunnel domain")
	dohE2ECmd.Flags().String("pubkey", "", "DNSTT server public key")
	dohE2ECmd.Flags().String("test-url", "https://httpbin.org/ip", "URL to fetch through tunnel")
	dohE2ECmd.MarkFlagRequired("domain")
	dohE2ECmd.MarkFlagRequired("pubkey")
	dohCmd.AddCommand(dohE2ECmd)
}

func runDoHE2E(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	testURL, _ := cmd.Flags().GetString("test-url")

	urls, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(e2eTimeout) * time.Second
	ports := scanner.PortPool(30000, workers)
	check := scanner.DoHDnsttCheck(domain, pubkey, testURL, ports)

	start := time.Now()
	results := scanner.RunPool(urls, workers, dur, check, newProgress("doh/e2e"))
	elapsed := time.Since(start)

	return writeReport("doh/e2e", results, elapsed, "e2e_ms")
}
