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

var e2eDnsttCmd = &cobra.Command{
	Use:   "dnstt",
	Short: "Test e2e connectivity through DNSTT SOCKS tunnel",
	RunE:  runE2EDnstt,
}

func init() {
	e2eDnsttCmd.Flags().String("domain", "", "DNSTT tunnel domain")
	e2eDnsttCmd.Flags().String("pubkey", "", "DNSTT server public key")
	e2eDnsttCmd.Flags().String("socks-user", "", "SOCKS5 username for proxy auth")
	e2eDnsttCmd.Flags().String("socks-pass", "", "SOCKS5 password for proxy auth")
	e2eDnsttCmd.Flags().String("connect-addr", "", "host:port for SOCKS5 CONNECT probe (default example.com:80)")
	e2eDnsttCmd.MarkFlagRequired("domain")
	e2eDnsttCmd.MarkFlagRequired("pubkey")
	e2eCmd.AddCommand(e2eDnsttCmd)
}

func runE2EDnstt(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	socksUser, _ := cmd.Flags().GetString("socks-user")
	socksPass, _ := cmd.Flags().GetString("socks-pass")
	connectAddr, _ := cmd.Flags().GetString("connect-addr")
	bin, err := findBinary("dnstt-client")
	if err != nil {
		return err
	}

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(e2eTimeout) * time.Second
	ports := scanner.PortPool(30000, workers)
	opts := scanner.SOCKS5Opts{User: socksUser, Pass: socksPass, ConnectAddr: connectAddr}
	check := scanner.DnsttCheckBin(bin, domain, pubkey, ports, opts)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	results := scanner.RunPoolCtx(ctx, ips, workers, dur, check, newProgress("e2e/dnstt"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results\n")
	}

	return writeReport("e2e/dnstt", results, elapsed, "e2e_ms")
}
