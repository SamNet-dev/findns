package scanner

import (
	"context"
)

// PipelineResult is the outcome of running one IP through the full step pipeline.
type PipelineResult struct {
	IP         string
	OK         bool
	Metrics    Metrics
	FailedStep int // index of the step where it failed; -1 if passed all
}

// RunPipeline processes each IP through all steps sequentially per-IP (DFS).
// Unlike RunChain which processes all IPs through step 1, then step 2 (BFS),
// each worker takes one IP and runs it through the entire pipeline.
// Results are emitted to the returned channel as each IP completes.
// The channel is closed when all IPs are processed or the context is cancelled.
func RunPipeline(ctx context.Context, ips []string, workers int, steps []Step) <-chan PipelineResult {
	out := make(chan PipelineResult, workers)

	go func() {
		defer close(out)

		jobs := make(chan string)
		bufSize := workers * 4
		if bufSize > len(ips) {
			bufSize = len(ips)
		}
		if bufSize < 1 {
			bufSize = 1
		}
		results := make(chan PipelineResult, bufSize)

		// Launch workers — each takes one IP and runs ALL steps on it
		for i := 0; i < workers; i++ {
			go func() {
				for ip := range jobs {
					func() {
						defer func() {
							if r := recover(); r != nil {
								results <- PipelineResult{IP: ip, OK: false, FailedStep: 0}
							}
						}()

						m := make(Metrics)
						for si, step := range steps {
							if ctx.Err() != nil {
								results <- PipelineResult{IP: ip, OK: false, FailedStep: si}
								return
							}
							ok, sm := step.Check(ip, step.Timeout)
							if !ok {
								results <- PipelineResult{IP: ip, OK: false, FailedStep: si}
								return
							}
							for k, v := range sm {
								m[k] = v
							}
						}
						results <- PipelineResult{IP: ip, OK: true, Metrics: m, FailedStep: -1}
					}()
				}
			}()
		}

		// Feed IPs to workers
		go func() {
			for _, ip := range ips {
				select {
				case jobs <- ip:
				case <-ctx.Done():
					close(jobs)
					return
				}
			}
			close(jobs)
		}()

		// Forward results to output channel
		for i := 0; i < len(ips); i++ {
			select {
			case r := <-results:
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}
