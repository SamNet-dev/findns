package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Run multiple scan steps in sequence, passing results in-memory",
	RunE:  runChain,
}

func init() {
	chainCmd.Flags().StringArray("step", nil, `scan steps in "type:key=val,key=val" format`)
	chainCmd.Flags().Int("port-base", 30000, "base port for e2e SOCKS proxies")
	chainCmd.MarkFlagRequired("step")
	rootCmd.AddCommand(chainCmd)
}

type stepConfig struct {
	name   string
	params map[string]string
}

func parseStepFlag(raw string) (stepConfig, error) {
	raw = strings.TrimSpace(raw)
	name, paramStr, hasParams := strings.Cut(raw, ":")

	if name == "" {
		return stepConfig{}, fmt.Errorf("empty step type")
	}

	params := make(map[string]string)
	if hasParams && paramStr != "" {
		for _, kv := range strings.Split(paramStr, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k == "" {
				return stepConfig{}, fmt.Errorf("invalid param %q in step %q", kv, name)
			}
			params[k] = v
		}
	}

	return stepConfig{name: name, params: params}, nil
}

func buildStep(cfg stepConfig, defaultTimeout, defaultCount int, ports chan int, binPaths map[string]string) (scanner.Step, error) {
	stepTimeout := defaultTimeout
	if v, ok := cfg.params["timeout"]; ok {
		t, err := strconv.Atoi(v)
		if err != nil {
			return scanner.Step{}, fmt.Errorf("step %q: invalid timeout %q", cfg.name, v)
		}
		stepTimeout = t
	}
	dur := time.Duration(stepTimeout) * time.Second

	stepCount := defaultCount
	if v, ok := cfg.params["count"]; ok {
		c, err := strconv.Atoi(v)
		if err != nil {
			return scanner.Step{}, fmt.Errorf("step %q: invalid count %q", cfg.name, v)
		}
		stepCount = c
	}

	switch cfg.name {
	case "ping":
		return scanner.Step{Name: "ping", Timeout: dur, Check: scanner.PingCheck(stepCount), SortBy: "ping_ms"}, nil

	case "resolve":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		return scanner.Step{Name: "resolve", Timeout: dur, Check: scanner.ResolveCheck(domain, stepCount), SortBy: "resolve_ms"}, nil

	case "resolve/tunnel":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		return scanner.Step{Name: "resolve/tunnel", Timeout: dur, Check: scanner.TunnelCheck(domain, stepCount), SortBy: "resolve_ms"}, nil

	case "e2e/dnstt":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		pubkey, ok := cfg.params["pubkey"]
		if !ok || pubkey == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'pubkey'", cfg.name)
		}
		return scanner.Step{Name: "e2e/dnstt", Timeout: dur, Check: scanner.DnsttSOCKSCheckBin(binPaths["dnstt-client"], domain, pubkey, ports), SortBy: "socks_ms"}, nil

	case "e2e/slipstream":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		cert := cfg.params["cert"]
		return scanner.Step{Name: "e2e/slipstream", Timeout: dur, Check: scanner.SlipstreamCheckBin(binPaths["slipstream-client"], domain, cert, ports), SortBy: "e2e_ms"}, nil

	case "nxdomain":
		return scanner.Step{Name: "nxdomain", Timeout: dur, Check: scanner.NXDomainCheck(stepCount), SortBy: "hijack"}, nil

	case "edns":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		return scanner.Step{Name: "edns", Timeout: dur, Check: scanner.EDNSCheck(domain, stepCount), SortBy: "edns_max"}, nil

	case "doh/resolve":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		return scanner.Step{Name: "doh/resolve", Timeout: dur, Check: scanner.DoHResolveCheck(domain, stepCount), SortBy: "resolve_ms"}, nil

	case "doh/resolve/tunnel":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		return scanner.Step{Name: "doh/resolve/tunnel", Timeout: dur, Check: scanner.DoHTunnelCheck(domain, stepCount), SortBy: "resolve_ms"}, nil

	case "doh/e2e":
		domain, ok := cfg.params["domain"]
		if !ok || domain == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'domain'", cfg.name)
		}
		pubkey, ok := cfg.params["pubkey"]
		if !ok || pubkey == "" {
			return scanner.Step{}, fmt.Errorf("step %q: missing required param 'pubkey'", cfg.name)
		}
		return scanner.Step{Name: "doh/e2e", Timeout: dur, Check: scanner.DoHDnsttCheckBin(binPaths["dnstt-client"], domain, pubkey, ports), SortBy: "e2e_ms"}, nil

	default:
		return scanner.Step{}, fmt.Errorf("unknown step type %q", cfg.name)
	}
}

func runChain(cmd *cobra.Command, args []string) error {
	stepFlags, _ := cmd.Flags().GetStringArray("step")
	portBase, _ := cmd.Flags().GetInt("port-base")

	// Parse all steps first (fail-fast)
	configs := make([]stepConfig, 0, len(stepFlags))
	for _, raw := range stepFlags {
		cfg, err := parseStepFlag(raw)
		if err != nil {
			return err
		}
		configs = append(configs, cfg)
	}

	// Pre-flight: check required binaries for e2e steps
	binPaths := make(map[string]string) // "dnstt-client" -> resolved path
	for _, cfg := range configs {
		switch cfg.name {
		case "e2e/dnstt", "doh/e2e":
			if _, ok := binPaths["dnstt-client"]; !ok {
				bin, err := findBinary("dnstt-client")
				if err != nil {
					return fmt.Errorf("step %q requires dnstt-client: %w", cfg.name, err)
				}
				binPaths["dnstt-client"] = bin
			}
			if _, err := findBinary("curl"); err != nil {
				return fmt.Errorf("step %q requires curl in PATH (not found)", cfg.name)
			}
		case "e2e/slipstream":
			if _, ok := binPaths["slipstream-client"]; !ok {
				bin, err := findBinary("slipstream-client")
				if err != nil {
					return fmt.Errorf("step %q requires slipstream-client: %w", cfg.name, err)
				}
				binPaths["slipstream-client"] = bin
			}
			if _, err := findBinary("curl"); err != nil {
				return fmt.Errorf("step %q requires curl in PATH (not found)", cfg.name)
			}
		}
	}

	// Shared port pool for e2e steps
	ports := scanner.PortPool(portBase, workers)

	// Build all steps
	steps := make([]scanner.Step, 0, len(configs))
	for _, cfg := range configs {
		s, err := buildStep(cfg, timeout, count, ports, binPaths)
		if err != nil {
			return err
		}
		steps = append(steps, s)
	}

	ips, err := loadInput()
	if err != nil {
		return err
	}

	if outputFile == "" {
		return fmt.Errorf("--output / -o flag is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	report := scanner.RunChainCtx(ctx, ips, workers, steps, newProgressFactory())

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — saving partial results to %s\n", outputFile)
	}

	return scanner.WriteChainReport(report, outputFile)
}
