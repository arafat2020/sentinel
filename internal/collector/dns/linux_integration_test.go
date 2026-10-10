//go:build linux && integration

package dns

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// The capture reads with a timeout so that Close cannot block. It must still
// see queries, and Close must return promptly on a quiet interface.
func TestLinuxCaptureSeesQueriesAndClosesPromptly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}

	collector, err := NewLinuxCollector("any", nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var seen atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		collector.Run(ctx, func(q core.DNSQuery) {
			if q.Domain == "sentinel-capture-test.example" || q.Domain == "sentinel-capture-test.example." {
				seen.Add(1)
			}
		})
	}()

	// Several read timeouts pass with nothing to read before the query.
	time.Sleep(time.Second)

	conn, err := net.Dial("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	// A minimal DNS query for sentinel-capture-test.example, type A.
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"sentinel-capture-test", "example"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	conn.Write(query)
	conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for seen.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if seen.Load() == 0 {
		t.Error("the query was not captured")
	}

	// Now nothing is arriving. Close must not wait for a packet.
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	began := time.Now()
	closed := make(chan struct{})
	go func() { collector.Close(); close(closed) }()
	select {
	case <-closed:
		if took := time.Since(began); took > 2*time.Second {
			t.Errorf("Close took %v", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return on a quiet interface")
	}
}
