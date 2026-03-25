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

var dohE2ECmd = &cobra.Command{
	Use:   "e2e",
	Short: "Test e2e connectivity through DNSTT tunnel using DoH resolver",
	RunE:  runDoHE2E,
}

func init() {
	dohE2ECmd.Flags().String("domain", "", "DNSTT tunnel domain")
	dohE2ECmd.Flags().String("pubkey", "", "DNSTT server public key")
	dohE2ECmd.Flags().String("socks-user", "", "SOCKS5 username for proxy auth")
	dohE2ECmd.Flags().String("socks-pass", "", "SOCKS5 password for proxy auth")
	dohE2ECmd.Flags().String("connect-addr", "", "host:port for SOCKS5 CONNECT probe (default example.com:80)")
	dohE2ECmd.MarkFlagRequired("domain")
	dohE2ECmd.MarkFlagRequired("pubkey")
	dohCmd.AddCommand(dohE2ECmd)
}

func runDoHE2E(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	socksUser, _ := cmd.Flags().GetString("socks-user")
	socksPass, _ := cmd.Flags().GetString("socks-pass")
	connectAddr, _ := cmd.Flags().GetString("connect-addr")
	bin, err := findBinary("dnstt-client")
	if err != nil {
		return err
	}

	urls, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(e2eTimeout) * time.Second
	ports := scanner.PortPool(30000, workers)
	opts := scanner.SOCKS5Opts{User: socksUser, Pass: socksPass, ConnectAddr: connectAddr}
	check := scanner.DoHDnsttCheckBin(bin, domain, pubkey, ports, opts)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, urls, workers, dur, check, newProgress("doh/e2e"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("doh/e2e", results, elapsed, "e2e_ms")
}
