package correlation

import (
	"sort"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

const (
	// MaxThresholdCount is the largest count an event requirement may ask
	// for. It bounds what one counter can hold.
	MaxThresholdCount = 1000

	// maxThresholdCounters is the most (requirement, process) counters kept
	// at once. Further ones are not created until the sweep frees some.
	maxThresholdCounters = 4096

	// thresholdEvidenceEvents is how many of the most recent matching
	// events a counter keeps to show as evidence.
	thresholdEvidenceEvents = 10
)

// thresholdSpec is an event requirement that asks for more than one event:
// a number of matching events, or of distinct values of a field, inside a
// span of time.
type thresholdSpec struct {
	// id identifies the requirement among those of the patterns currently
	// loaded.
	id     int
	count  int
	within time.Duration
	// distinct reads the value to count distinct occurrences of, or is nil
	// to count events.
	distinct func(*core.Event) (distinctValue, bool)
}

// distinctValue is a field value as a map-free, allocation-free key.
type distinctValue struct {
	text   string
	number int64
}

// thresholdCounter tracks one requirement for one process. It holds no more
// than the requirement's count of timestamps or values, whatever the rate of
// events, so it does not depend on how many events a chain retains.
type thresholdCounter struct {
	// times are the most recent matching event times, oldest first, at most
	// spec.count of them. Used when counting events.
	times []time.Time
	// values are the distinct values seen and when each was last seen, at
	// most spec.count of them. Used when counting distinct values.
	values []seenValue
	// newest is the time of the latest matching event, for eviction.
	newest time.Time
	// metAt is the end of the most recent span in which the requirement was
	// met. The requirement holds for as long as that moment is in the
	// correlation window.
	metAt time.Time

	recent     [thresholdEvidenceEvents]core.Event
	recentNext int
	recentLen  int
}

type seenValue struct {
	value distinctValue
	last  time.Time
}

// record counts one matching event.
func (c *thresholdCounter) record(spec *thresholdSpec, event *core.Event) {
	ts := event.Timestamp

	if ts.After(c.newest) {
		c.newest = ts
	}

	c.recent[c.recentNext] = *event
	c.recentNext = (c.recentNext + 1) % thresholdEvidenceEvents
	if c.recentLen < thresholdEvidenceEvents {
		c.recentLen++
	}

	if spec.distinct == nil {
		c.recordTime(spec, ts)
		return
	}

	if value, ok := spec.distinct(event); ok {
		c.recordValue(spec, value, ts)
	}
}

// recordTime keeps the latest spec.count event times and notes when they all
// fall inside one span.
func (c *thresholdCounter) recordTime(spec *thresholdSpec, ts time.Time) {
	if len(c.times) == spec.count {
		if !ts.After(c.times[0]) {
			return // older than everything kept
		}
		c.times = c.times[:copy(c.times, c.times[1:])]
	}

	// Events normally arrive in order, which makes this an append.
	at := sort.Search(len(c.times), func(i int) bool { return c.times[i].After(ts) })
	c.times = append(c.times, time.Time{})
	copy(c.times[at+1:], c.times[at:])
	c.times[at] = ts

	newest := c.times[len(c.times)-1]
	if len(c.times) == spec.count && newest.Sub(c.times[0]) < spec.within && newest.After(c.metAt) {
		c.metAt = newest
	}
}

// recordValue keeps the spec.count most recently seen distinct values and
// notes when they were all seen inside one span.
func (c *thresholdCounter) recordValue(spec *thresholdSpec, value distinctValue, ts time.Time) {
	found := false
	oldest := 0

	for i := range c.values {
		if c.values[i].value == value {
			if ts.After(c.values[i].last) {
				c.values[i].last = ts
			}
			found = true
		}
		if c.values[i].last.Before(c.values[oldest].last) {
			oldest = i
		}
	}

	switch {
	case found:
	case len(c.values) < spec.count:
		c.values = append(c.values, seenValue{value: value, last: ts})
	case ts.After(c.values[oldest].last):
		// Full: the value seen longest ago is the least use to a span
		// ending now.
		c.values[oldest] = seenValue{value: value, last: ts}
	default:
		return
	}

	if len(c.values) < spec.count {
		return
	}

	earliest, latest := c.values[0].last, c.values[0].last
	for _, seen := range c.values[1:] {
		if seen.last.Before(earliest) {
			earliest = seen.last
		}
		if seen.last.After(latest) {
			latest = seen.last
		}
	}

	if latest.Sub(earliest) < spec.within && latest.After(c.metAt) {
		c.metAt = latest
	}
}

// recentEvents returns the retained matching events, oldest first.
func (c *thresholdCounter) recentEvents() []core.Event {
	events := make([]core.Event, 0, c.recentLen)

	start := (c.recentNext - c.recentLen + thresholdEvidenceEvents) % thresholdEvidenceEvents
	for i := 0; i < c.recentLen; i++ {
		events = append(events, c.recent[(start+i)%thresholdEvidenceEvents])
	}

	return events
}

// replay runs events, which must be in time order, through a fresh counter.
// It is how a threshold is evaluated when there is no engine keeping
// counters, and is limited by however many events were retained.
func (e *compiledEvent) replay(events []core.Event) *thresholdCounter {
	counter := &thresholdCounter{}

	for i := range events {
		if events[i].Type != e.eventType {
			continue
		}
		if e.where == nil || e.where(&events[i]) {
			counter.record(e.threshold, &events[i])
		}
	}

	return counter
}

// counterKey identifies a counter: one requirement, one process.
type counterKey struct {
	requirement int
	process     core.ProcessIdentity
}

// thresholdRef locates a threshold requirement among the loaded patterns.
type thresholdRef struct {
	role  *compiledRole
	event *compiledEvent
}
