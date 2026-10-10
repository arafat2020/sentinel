package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestLatencyBucketsAreContiguous(t *testing.T) {
	previous := time.Duration(-1)
	for index := 0; index < latencyBuckets; index++ {
		ceiling := latencyBucketCeiling(index)
		if ceiling <= previous {
			t.Fatalf("bucket %d ends at %v, not after bucket %d (%v)", index, ceiling, index-1, previous)
		}
		// The first and last duration of the bucket both land in it.
		if got := latencyBucket(previous + 1); got != index {
			t.Fatalf("%v falls in bucket %d, want %d", previous+1, got, index)
		}
		if got := latencyBucket(ceiling); got != index {
			t.Fatalf("%v falls in bucket %d, want %d", ceiling, got, index)
		}
		previous = ceiling
	}
	if previous < time.Hour {
		t.Errorf("the histogram reaches only %v", previous)
	}
}

func TestLatencyQuantiles(t *testing.T) {
	var h latencyHistogram
	if h.summary() != (LatencySummary{}) {
		t.Fatal("an empty histogram reports something")
	}

	// 1..100 ms: the median is about 50 ms, the 99th percentile about 99.
	for ms := 1; ms <= 100; ms++ {
		h.record(time.Duration(ms) * time.Millisecond)
	}
	s := h.summary()

	within := func(name string, got, want time.Duration) {
		t.Helper()
		if got < want || float64(got) > 1.2*float64(want) {
			t.Errorf("%s = %v, want %v or up to 20%% above (bucket ceiling)", name, got, want)
		}
	}
	within("p50", s.P50, 50*time.Millisecond)
	within("p99", s.P99, 99*time.Millisecond)
	if s.Max != 100*time.Millisecond || s.Count != 100 {
		t.Errorf("summary = %+v", s)
	}

	// A quantile never exceeds the largest value seen.
	var one latencyHistogram
	one.record(3 * time.Second)
	if s := one.summary(); s.P50 != 3*time.Second || s.P99 != 3*time.Second {
		t.Errorf("single sample summary = %+v", s)
	}
}

// Latency runs from the timestamp of the event that led to the finding to the
// moment the finding is emitted.
func TestEngineMeasuresDetectionLatency(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "curl-connects",
		Processes: []ProcessPattern{named("p", "curl", core.EventNetworkConnect)},
	}})

	p := proc(10, 1, "curl", at(0))
	h.start(p, at(0))
	h.detect(at(0))

	// The connection happened at 1 s; the engine gets to it at 1.25 s.
	h.clock.set(at(1250 * time.Millisecond))
	subject := p
	h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: at(time.Second), Process: &subject})
	if got := findingKeys(h.DetectBehaviors()); got != "curl-connects:10" {
		t.Fatalf("findings = %q", got)
	}

	latency := h.Metrics().DetectionLatency
	if latency.Count != 1 || latency.Max != 250*time.Millisecond {
		t.Fatalf("latency = %+v, want one finding at 250ms", latency)
	}

	// An evaluation that finds nothing, or that nothing was ingested for,
	// measures nothing.
	h.detect(at(2 * time.Second))
	h.start(proc(11, 1, "ls", at(3*time.Second)), at(3*time.Second))
	h.detect(at(3 * time.Second))
	if got := h.Metrics().DetectionLatency.Count; got != 1 {
		t.Errorf("count = %d after evaluations without findings", got)
	}
}
