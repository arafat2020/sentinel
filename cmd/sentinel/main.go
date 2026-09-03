package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
	"github.com/arafat2020/sentinel/internal/monitor"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	collector := processCollector.NewCollector()
	detector := processDetector.NewLifecycleDetector()

	processMonitor := monitor.NewProcessMonitor(
		collector,
		detector,
		2*time.Second,
	)

	processMonitor.Run(ctx)
}
