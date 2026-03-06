package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Check IP reachability via ICMP ping",
	RunE:  runPing,
}

func init() {
	rootCmd.AddCommand(pingCmd)
}

func runPing(cmd *cobra.Command, args []string) error {
	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.PingCheck(count)

	start := time.Now()
	results := scanner.RunPool(ips, workers, dur, check, newProgress("ping"))
	elapsed := time.Since(start)

	return writeReport("ping", results, elapsed, "ping_ms")
}
