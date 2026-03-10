package main

import (
	"fmt"
	"os"
	"time"

	"github.com/SamNet-dev/findns/internal/binutil"
	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/SamNet-dev/findns/internal/tui"
	"github.com/spf13/cobra"
)

var (
	inputFile     string
	outputFile    string
	includeFailed bool
	workers       int
	timeout       int
	count         int
	e2eTimeout    int
)

var rootCmd = &cobra.Command{
	Use:               "findns",
	Short:             "DNS tunnel scanner - test resolvers for tunneling viability",
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	// Launch TUI when no subcommand is given
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := tui.ScanConfig{
			OutputFile: outputFile,
			Workers:    workers,
			Timeout:    timeout,
			Count:      count,
			E2ETimeout: e2eTimeout,
		}
		return tui.RunWithConfig(cfg)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputFile, "input", "i", "", "input file (text or JSON)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output JSON file")
	rootCmd.PersistentFlags().BoolVar(&includeFailed, "include-failed", false, "also scan failed IPs from JSON input")
	rootCmd.PersistentFlags().IntVar(&workers, "workers", 50, "concurrent workers")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 3, "timeout per attempt in seconds")
	rootCmd.PersistentFlags().IntVarP(&count, "count", "c", 3, "number of attempts per IP for ping/resolve checks")
	rootCmd.PersistentFlags().IntVar(&e2eTimeout, "e2e-timeout", 10, "timeout for e2e tunnel tests in seconds")
	rootCmd.SilenceUsage = true
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadInput() ([]string, error) {
	if inputFile == "" {
		return nil, fmt.Errorf("--input / -i flag is required")
	}
	ips, err := scanner.LoadInput(inputFile, includeFailed)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no resolvers found in %s", inputFile)
	}
	return ips, nil
}

func writeReport(mode string, results []scanner.Result, elapsed time.Duration, sortBy string) error {
	if outputFile == "" {
		return fmt.Errorf("--output / -o flag is required")
	}
	// Sort passed results by metric before writing
	passed := make([]scanner.Result, 0, len(results))
	failed := make([]scanner.Result, 0)
	for _, r := range results {
		if r.OK {
			passed = append(passed, r)
		} else {
			failed = append(failed, r)
		}
	}
	if sortBy != "" {
		scanner.SortByMetric(passed, sortBy)
	}
	sorted := make([]scanner.Result, 0, len(results))
	sorted = append(sorted, passed...)
	sorted = append(sorted, failed...)

	if err := scanner.WriteReport(sorted, outputFile); err != nil {
		return err
	}
	scanner.PrintStats(mode, results, elapsed)
	return nil
}

func findBinary(name string) (string, error) {
	return binutil.Find(name)
}

func isTTY() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func newProgress(label string) scanner.ProgressFunc {
	if !isTTY() {
		return nil
	}
	start := time.Now()
	return func(done, total, passed, failed int) {
		if total == 0 {
			return
		}
		pct := done * 100 / total
		elapsed := time.Since(start).Truncate(time.Second)
		bar := progressBar(pct, 20)
		fmt.Fprintf(os.Stderr, "\r\033[2K  \033[1m%s\033[0m  %s  %d/%d  \033[32m%d \u2714\033[0m  \033[31m%d \u2718\033[0m  \033[2m%s\033[0m",
			label, bar, done, total, passed, failed, elapsed)
		if done == total {
			elapsed = time.Since(start).Truncate(time.Second)
			fmt.Fprintf(os.Stderr, "\r\033[2K  \033[32m\u2714\033[0m \033[1m%s\033[0m  %d/%d passed  \033[2m%s\033[0m\n",
				label, passed, total, elapsed)
		}
	}
}

func newProgressFactory() scanner.ProgressFactory {
	if !isTTY() {
		return nil
	}
	return func(stepName string) scanner.ProgressFunc {
		return newProgress(stepName)
	}
}

func newScanProgressFactory(totalSteps int, descriptions map[string]string) scanner.ProgressFactory {
	if !isTTY() {
		return nil
	}
	stepNum := 0
	return func(stepName string) scanner.ProgressFunc {
		stepNum++
		label := fmt.Sprintf("[%d/%d] %s", stepNum, totalSteps, stepName)

		// Print step description banner
		w := os.Stderr
		if desc, ok := descriptions[stepName]; ok {
			fmt.Fprintf(w, "  %s── %s ─────────────────────────────────%s\n", colorDim, desc, colorReset)
		}

		start := time.Now()
		warnedLow := false

		return func(done, total, passed, failed int) {
			if total == 0 {
				return
			}
			pct := done * 100 / total
			elapsed := time.Since(start).Truncate(time.Second)
			bar := progressBar(pct, 20)
			fmt.Fprintf(w, "\r\033[2K  \033[1m%s\033[0m  %s  %d/%d  \033[32m%d \u2714\033[0m  \033[31m%d \u2718\033[0m  \033[2m%s\033[0m",
				label, bar, done, total, passed, failed, elapsed)

			// Live warning: after 25% done with enough samples, if pass rate < 5%
			if !warnedLow && done > 20 && done >= total/4 {
				rate := passed * 100 / done
				if rate < 5 {
					warnedLow = true
					fmt.Fprintf(w, "\n  %s\u26a0 Very low pass rate (%d%%) — check configuration%s\n", colorYellow, rate, colorReset)
				}
			}

			// Completion: inter-step summary
			if done == total {
				elapsed = time.Since(start).Truncate(time.Second)
				passRate := 0
				if total > 0 {
					passRate = passed * 100 / total
				}
				color := colorGreen
				if passRate < 50 {
					color = colorYellow
				}
				if passRate < 20 {
					color = colorRed
				}
				fmt.Fprintf(w, "\r\033[2K  %s\u2714%s %-18s  %s%d/%d passed (%d%%)%s  %s%s%s\n",
					color, colorReset,
					stepName,
					color, passed, total, passRate, colorReset,
					colorDim, elapsed, colorReset)
				if stepNum < totalSteps && passed > 0 {
					fmt.Fprintf(w, "  %s\u21b3 %d resolvers advancing to next step%s\n", colorDim, passed, colorReset)
				}
			}
		}
	}
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	bar := make([]rune, width)
	for i := range bar {
		if i < filled {
			bar[i] = '\u2588' // █
		} else {
			bar[i] = '\u2591' // ░
		}
	}
	return fmt.Sprintf("\033[36m%s\033[0m %3d%%", string(bar), pct)
}
