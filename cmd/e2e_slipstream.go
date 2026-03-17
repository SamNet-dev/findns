package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
	e2eSlipstreamCmd.MarkFlagRequired("domain")
	e2eCmd.AddCommand(e2eSlipstreamCmd)
}

func runE2ESlipstream(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	certPath, _ := cmd.Flags().GetString("cert")
	bin, err := findBinary("slipstream-client")
	if err != nil {
		return err
	}

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(e2eTimeout) * time.Second
	ports := scanner.PortPool(30000, workers)
	check := scanner.SlipstreamCheckBin(bin, domain, certPath, ports)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, ips, workers, dur, check, newProgress("e2e/slipstream"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("e2e/slipstream", results, elapsed, "e2e_ms")
}
