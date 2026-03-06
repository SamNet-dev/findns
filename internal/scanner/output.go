package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type IPRecord struct {
	IP      string  `json:"ip"`
	Metrics Metrics `json:"metrics,omitempty"`
}

type Report struct {
	Passed []IPRecord `json:"passed"`
	Failed []IPRecord `json:"failed"`
}

func WriteReport(results []Result, path string) error {
	report := Report{
		Passed: []IPRecord{},
		Failed: []IPRecord{},
	}
	for _, r := range results {
		if r.OK {
			report.Passed = append(report.Passed, IPRecord{IP: r.IP, Metrics: r.Metrics})
		} else {
			report.Failed = append(report.Failed, IPRecord{IP: r.IP})
		}
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func PrintStats(mode string, results []Result, duration time.Duration) {
	var passCount, failCount int
	for _, r := range results {
		if r.OK {
			passCount++
		} else {
			failCount++
		}
	}
	fmt.Fprintf(os.Stdout, "%s: %d tested | %d pass | %d fail | %.1fs\n",
		mode, len(results), passCount, failCount, duration.Seconds())
}
