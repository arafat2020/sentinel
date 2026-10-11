package correlation

import (
	"math/bits"
	"time"
)

// LatencySummary describes how long findings took to be emitted, measured
// from the timestamp of the event that led to them. For an event stamped by
// the kernel that covers everything in between: the collector, the wait on
// the event bus, and the search.
type LatencySummary struct {
	// Count is how many findings were measured.
	Count uint64 `json:"count"`
	// P50 and P99 are the median and 99th-percentile latency, to within
	// the histogram's resolution (about 19%). Max is exact.
	P50 time.Duration `json:"p50"`
	P99 time.Duration `json:"p99"`
	Max time.Duration `json:"max"`
}

// latencyHistogram counts durations in buckets that each span a quarter of a
// doubling, from a microsecond up to about an hour. It is a fixed size
// whatever is recorded.
type latencyHistogram struct {
	buckets [latencyBuckets]uint64
	count   uint64
	max     time.Duration
}

const (
	latencySubBuckets = 4
	latencyOctaves    = 32
	latencyBuckets    = latencyOctaves * latencySubBuckets
)

func latencyBucket(d time.Duration) int {
	micros := uint64(d / time.Microsecond)
	if micros < latencySubBuckets {
		return int(micros)
	}

	// The octave is the position of the top bit; the two bits below it
	// choose the quarter.
	octave := bits.Len64(micros) - 1
	quarter := (micros >> (octave - 2)) & (latencySubBuckets - 1)
	index := (octave-1)*latencySubBuckets + int(quarter)

	if index >= latencyBuckets {
		return latencyBuckets - 1
	}
	return index
}

// latencyBucketCeiling is the largest duration that falls in the bucket.
func latencyBucketCeiling(index int) time.Duration {
	if index < latencySubBuckets {
		return time.Duration(index+1)*time.Microsecond - 1
	}

	octave := index/latencySubBuckets + 1
	quarter := uint64(index % latencySubBuckets)
	next := (uint64(latencySubBuckets) + quarter + 1) << (octave - 2)

	return time.Duration(next)*time.Microsecond - 1
}

func (h *latencyHistogram) record(d time.Duration) {
	if d < 0 {
		d = 0
	}

	h.buckets[latencyBucket(d)]++
	h.count++
	if d > h.max {
		h.max = d
	}
}

func (h *latencyHistogram) quantile(q float64) time.Duration {
	if h.count == 0 {
		return 0
	}

	rank := uint64(q*float64(h.count-1)) + 1
	seen := uint64(0)

	for index, n := range h.buckets {
		seen += n
		if seen >= rank {
			if ceiling := latencyBucketCeiling(index); ceiling < h.max {
				return ceiling
			}
			return h.max
		}
	}

	return h.max
}

func (h *latencyHistogram) summary() LatencySummary {
	return LatencySummary{
		Count: h.count,
		P50:   h.quantile(0.50),
		P99:   h.quantile(0.99),
		Max:   h.max,
	}
}
