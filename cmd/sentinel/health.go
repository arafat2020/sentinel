package main

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/collector/process/procevents"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

// healthLogInterval is how often headless mode logs a health line, unless
// --health-interval says otherwise.
const healthLogInterval = 60 * time.Second

// health gathers, in one place, everything that says whether Sentinel is
// keeping up: which collectors are in use, what they have dropped or could
// not describe, how full the event bus is, and every limit the correlation
// engine has run into. The TUI, the desktop UI and the headless log all show
// the same report.
type health struct {
	collection *processCollection
	bus        *eventbus.Bus
	engine     *correlation.Engine
}

type healthReport struct {
	Requested procevents.Backend
	Skipped   []procevents.Skip
	Failure   string
	Collector procevents.Stats
	Bus       eventbus.Stats
	Engine    correlation.Metrics
	// Excluded is the number of findings dropped by exclusions, by rule.
	Excluded map[string]int
}

func (h *health) Report() healthReport {
	h.collection.mu.Lock()
	failure := h.collection.failure
	h.collection.mu.Unlock()

	return healthReport{
		Requested: h.collection.requested,
		Skipped:   h.collection.skipped,
		Failure:   failure,
		Collector: h.collection.Stats(),
		Bus:       h.bus.Stats(),
		Engine:    h.engine.Metrics(),
		Excluded:  h.engine.ExcludedFindings(),
	}
}

// otherCollectors names the collectors that are not selectable, by platform.
func otherCollectors() string {
	network := fmt.Sprintf("network: poll every %s", processPollInterval)

	switch runtime.GOOS {
	case "linux":
		return network + "   dns: libpcap   file: fanotify"
	case "darwin":
		return network + "   dns: libpcap   file: Endpoint Security"
	case "windows":
		return network + "   dns: Npcap   file: ReadDirectoryChangesW"
	default:
		return network
	}
}

// Lines renders the report for a person to read.
func (r healthReport) Lines() []string {
	c, b, e := r.Collector, r.Bus, r.Engine

	backend := fmt.Sprintf("Process collector  %s  (requested: %s)", c.Backend, r.Requested)
	if c.Backend == procevents.BackendPoll {
		backend += fmt.Sprintf("  snapshot every %s", processPollInterval)
	}

	lines := []string{backend}
	for _, skip := range r.Skipped {
		lines = append(lines, "  skipped "+skip.String())
	}
	if r.Failure != "" {
		lines = append(lines, "  "+r.Failure)
	}
	lines = append(lines, "Other collectors   "+otherCollectors())

	if c.Backend != procevents.BackendPoll {
		lines = append(lines,
			fmt.Sprintf("Events    starts %d (at exec %d, at fork %d)   execs %d   exits %d",
				c.Starts, c.StartsAtExec, c.StartsAtFork, c.Execs, c.Exits),
			fmt.Sprintf("Kernel    forks %d   execs %d   exits %d   dropped %d   undecodable %d",
				c.RawForks, c.RawExecs, c.RawExits, c.KernelDrops, c.DecodeErrors),
			fmt.Sprintf("Quality   partial %d   args truncated %d   clock error <= %s",
				c.Partial, c.ArgsTruncated, time.Duration(c.ClockErrorNanos)),
			fmt.Sprintf("Tracker   tracked %d   pending %d   cap hits %d   pid reuses %d   untracked execs %d exits %d",
				c.Tracked, c.Pending, c.TrackedCapHits, c.PIDReuses, c.UntrackedExecs, c.UntrackedExits),
			fmt.Sprintf("Repair    reconciled starts %d   exits %d   duplicate forks %d   user cache %d (resets %d)",
				c.ReconciledStarts, c.ReconciledExits, c.DuplicateForks, c.UserCacheSize, c.UserCacheResets),
		)
	}

	lines = append(lines,
		fmt.Sprintf("Bus       published %d   waited %d   dropped %d   depth %d/%d",
			b.Published, b.Waited, b.Dropped, b.Depth, b.Capacity),
		fmt.Sprintf("Engine    processes %d   findings %d   excluded %d   suppressed %d   active suppressions %d",
			e.Processes, e.FindingsEmitted, e.FindingsExcluded, e.FindingsSuppressed, e.ActiveSuppressions),
		fmt.Sprintf("Limits    descendant walks truncated %d   sequences possibly truncated %d   sequence searches aborted %d",
			e.DescendantWalksTruncated, e.SequencesPossiblyTruncated, e.SequenceSearchesAborted),
		fmt.Sprintf("          threshold counters %d   evicted %d   cap hits %d",
			e.ThresholdCounters, e.ThresholdCountersEvicted, e.ThresholdCounterCapHits),
	)

	if len(r.Excluded) > 0 {
		rules := make([]string, 0, len(r.Excluded))
		for rule, count := range r.Excluded {
			rules = append(rules, fmt.Sprintf("%s %d", rule, count))
		}
		sort.Strings(rules)
		lines = append(lines, "Excluded  "+strings.Join(rules, "   "))
	}

	return lines
}

// LogLine renders the report as one line of key=value pairs, for logs that
// are read by programs as well as people.
func (r healthReport) LogLine() string {
	c, b, e := r.Collector, r.Bus, r.Engine

	fields := []string{
		"process_collector=" + string(c.Backend),
	}

	if c.Backend != procevents.BackendPoll {
		fields = append(fields,
			fmt.Sprintf("starts=%d execs=%d exits=%d", c.Starts, c.Execs, c.Exits),
			fmt.Sprintf("starts_at_exec=%d starts_at_fork=%d", c.StartsAtExec, c.StartsAtFork),
			fmt.Sprintf("raw_forks=%d raw_execs=%d raw_exits=%d", c.RawForks, c.RawExecs, c.RawExits),
			fmt.Sprintf("kernel_drops=%d decode_errors=%d partial=%d args_truncated=%d", c.KernelDrops, c.DecodeErrors, c.Partial, c.ArgsTruncated),
			fmt.Sprintf("tracked=%d pending=%d tracked_cap_hits=%d", c.Tracked, c.Pending, c.TrackedCapHits),
			fmt.Sprintf("pid_reuses=%d untracked_execs=%d untracked_exits=%d duplicate_forks=%d", c.PIDReuses, c.UntrackedExecs, c.UntrackedExits, c.DuplicateForks),
			fmt.Sprintf("reconciled_starts=%d reconciled_exits=%d", c.ReconciledStarts, c.ReconciledExits),
			fmt.Sprintf("user_cache=%d user_cache_resets=%d clock_error_ns=%d", c.UserCacheSize, c.UserCacheResets, c.ClockErrorNanos),
		)
	}

	fields = append(fields,
		fmt.Sprintf("bus_published=%d bus_waited=%d bus_dropped=%d bus_depth=%d bus_capacity=%d", b.Published, b.Waited, b.Dropped, b.Depth, b.Capacity),
		fmt.Sprintf("engine_processes=%d findings=%d findings_excluded=%d findings_suppressed=%d active_suppressions=%d",
			e.Processes, e.FindingsEmitted, e.FindingsExcluded, e.FindingsSuppressed, e.ActiveSuppressions),
		fmt.Sprintf("descendant_walks_truncated=%d sequences_possibly_truncated=%d sequence_searches_aborted=%d",
			e.DescendantWalksTruncated, e.SequencesPossiblyTruncated, e.SequenceSearchesAborted),
		fmt.Sprintf("threshold_counters=%d threshold_counters_evicted=%d threshold_counter_cap_hits=%d",
			e.ThresholdCounters, e.ThresholdCountersEvicted, e.ThresholdCounterCapHits),
	)

	return strings.Join(fields, " ")
}

// Text is Lines joined, for a text view.
func (h *health) Text() string {
	return strings.Join(h.Report().Lines(), "\n")
}
