// Command execstress starts short-lived processes at a steady rate. It is the
// load generator for Sentinel's process-collection stress test:
//
//	go run ./tools/execstress -rate 5000 -duration 60s
//
// Each process is a fork and an exec of the given binary, which exits at
// once, so a collector sees a fork, an exec and an exit for every one.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	rate := flag.Int("rate", 5000, "processes to start per second")
	duration := flag.Duration("duration", 60*time.Second, "how long to run")
	workers := flag.Int("workers", 16, "concurrent starters")
	binary := flag.String("binary", "/bin/true", "the program to run")
	flag.Parse()

	if _, err := os.Stat(*binary); err != nil {
		fmt.Fprintln(os.Stderr, "execstress:", err)
		os.Exit(1)
	}

	// One token per process, released on schedule. The buffer lets the
	// workers catch up after a stall instead of losing the tokens.
	tokens := make(chan struct{}, *rate)
	var started, failed atomic.Int64

	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range tokens {
				if err := exec.Command(*binary).Run(); err != nil {
					failed.Add(1)
					continue
				}
				started.Add(1)
			}
		}()
	}

	begin := time.Now()
	const tick = 10 * time.Millisecond
	ticker := time.NewTicker(tick)
	released := 0

	for now := range ticker.C {
		elapsed := now.Sub(begin)
		if elapsed >= *duration {
			break
		}

		// Release whatever the schedule says is due by now.
		due := int(float64(*rate) * elapsed.Seconds())
		for ; released < due; released++ {
			select {
			case tokens <- struct{}{}:
			default:
				// The workers cannot keep up with the rate asked for.
			}
		}
	}
	ticker.Stop()
	close(tokens)
	wg.Wait()

	took := time.Since(begin)
	fmt.Printf("execstress: started %d processes in %s (%.0f/s; asked for %d/s), %d failed\n",
		started.Load(), took.Round(time.Millisecond), float64(started.Load())/took.Seconds(), *rate, failed.Load())
}
