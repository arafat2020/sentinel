package main

import (
	"context"
	"fmt"
	"log"

	"github.com/arafatmannan/sentinel/internal/collector/process"
)

func main() {
	ctx := context.Background()

	collector := process.NewCollector()

	snapshot, err := collector.Collect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sentinel collected %d processes\n\n", len(snapshot.Processes))

	for _, p := range snapshot.Processes {
		fmt.Printf(
			"PID=%d PPID=%d NAME=%s EXE=%s\n",
			p.PID,
			p.PPID,
			p.Name,
			p.Executable,
		)
	}
}
