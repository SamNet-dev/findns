package main

import (
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var resolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Test if resolvers can resolve a given domain",
	RunE:  runResolve,
}

func init() {
	resolveCmd.Flags().String("domain", "", "domain to test")
	resolveCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(resolveCmd)
}

func runResolve(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(timeout) * time.Second
	check := scanner.ResolveCheck(domain, count)

	start := time.Now()
	results := scanner.RunPool(ips, workers, dur, check, newProgress("resolve"))
	elapsed := time.Since(start)

	return writeReport("resolve", results, elapsed, "resolve_ms")
}
