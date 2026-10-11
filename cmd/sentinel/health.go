package main

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/collector/network/netevents"
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
	// network, when set, adds the network collector.
	network *networkCollection
	bus     *eventbus.Bus
	engine  *correlation.Engine
	// patterns, when set, adds the state of the patterns file.
	patterns *patternStore
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
	// Patterns is how many patterns are loaded, and PatternProblems what
	// is wrong with the patterns file, if anything.
	Patterns        int
	Exclusions      int
	PatternProblems []string
	// HavePatterns is false when the report was made without a patterns
	// file to describe.
	HavePatterns bool

	// Network is the network collector's counters, with what was asked
	// for and why anything else was passed over. HaveNetwork is false when
	// the report was made without one.
	Network          netevents.Stats
	NetworkRequested netevents.Backend
	NetworkSkipped   []netevents.Skip
	NetworkFailure   string
	HaveNetwork      bool
	// OrderTolerance is the order_tolerance given to sequences that do not
	// set their own.
	OrderTolerance time.Duration
}

// Alerts names the counters that are not zero and mean something was lost
// or missed: the things to look at first.
func (r healthReport) Alerts() []string {
	var alerts []string
	add := func(n uint64, what string) {
		if n > 0 {
			alerts = append(alerts, fmt.Sprintf("%s %d", what, n))
		}
	}

	add(r.Collector.KernelDrops, "kernel drops")
	add(r.Network.KernelDrops, "network kernel drops")
	add(r.Network.Unowned, "connections closed with no known owner")
	add(r.Collector.TrackedCapHits, "tracked-process cap hits")
	add(r.Bus.Dropped, "bus drops")
	add(r.Engine.SequencesPossiblyTruncated, "sequences possibly truncated")
	add(r.Engine.SequenceSearchesAborted, "sequence searches aborted")
	add(r.Engine.ThresholdCounterCapHits, "threshold counter cap hits")
	add(r.Engine.DescendantWalksTruncated, "descendant walks truncated")
	add(r.Engine.FullRescans, "full rescans")
	add(uint64(len(r.PatternProblems)), "pattern errors")

	return alerts
}

// alertPrefix begins the line of a report that lists its alerts. The
// interfaces look for it to draw that line in a warning colour.
const alertPrefix = "ATTENTION "

func (h *health) Report() healthReport {
	h.collection.mu.Lock()
	failure := h.collection.failure
	h.collection.mu.Unlock()

	report := healthReport{
		Requested: h.collection.requested,
		Skipped:   h.collection.skipped,
		Failure:   failure,
		Collector: h.collection.Stats(),
		Bus:       h.bus.Stats(),
		Engine:    h.engine.Metrics(),
		Excluded:  h.engine.ExcludedFindings(),
	}

	report.OrderTolerance = h.engine.DefaultOrderToleranceInUse()

	if h.network != nil {
		h.network.mu.Lock()
		report.NetworkFailure = h.network.failure
		h.network.mu.Unlock()

		report.HaveNetwork = true
		report.Network = h.network.Stats()
		report.NetworkRequested = h.network.requested
		report.NetworkSkipped = h.network.skipped
	}

	if h.patterns != nil {
		state := h.patterns.State()
		report.HavePatterns = true
		report.Patterns, report.Exclusions = len(state.Patterns), len(state.Exclusions)
		report.PatternProblems = state.Problems()
	}

	return report
}

// otherCollectors names the collectors that are not selectable, by platform,
// as label and description pairs.
func otherCollectors() [][2]string {
	network := [2]string{"Network", fmt.Sprintf("poll every %s", processPollInterval)}

	switch runtime.GOOS {
	case "linux":
		return [][2]string{network, {"DNS", "libpcap"}, {"File", "fanotify"}}
	case "darwin":
		return [][2]string{network, {"DNS", "libpcap"}, {"File", "Endpoint Security"}}
	case "windows":
		return [][2]string{network, {"DNS", "Npcap"}, {"File", "ReadDirectoryChangesW"}}
	default:
		return [][2]string{network}
	}
}

// healthCell is one named value of the report.
type healthCell struct {
	Label string
	Value string
	// Zero marks a count of nothing, which a view may play down. Bad marks
	// a value that means something was lost or missed when it is not zero.
	Zero bool
	Bad  bool
}

// healthNote is a line of a section that is a sentence rather than a value.
type healthNote struct {
	Label string // optional; aligned with the cells' labels
	Text  string
	Bad   bool
}

// healthSection is a titled group of the report: notes first, then values
// that a view lays out in as many columns as it has room for.
type healthSection struct {
	Title string
	Notes []healthNote
	Cells []healthCell
}

func count[T int | int64 | uint64](label string, n T) healthCell {
	return healthCell{Label: label, Value: fmt.Sprint(n), Zero: n == 0}
}

func bad[T int | int64 | uint64](label string, n T) healthCell {
	cell := count(label, n)
	cell.Bad = true
	return cell
}

func duration(label string, d time.Duration, measured bool) healthCell {
	if !measured {
		return healthCell{Label: label, Value: "—", Zero: true}
	}
	return healthCell{Label: label, Value: d.Round(time.Microsecond).String()}
}

// Sections is the report in the order and grouping every view shows it.
func (r healthReport) Sections() []healthSection {
	c, b, e := r.Collector, r.Bus, r.Engine

	// --- Collectors: what is watching, and why not something better.
	process := fmt.Sprintf("%s (requested: %s)", c.Backend, r.Requested)
	if c.Backend == procevents.BackendPoll {
		process += fmt.Sprintf(", snapshot every %s", processPollInterval)
	}
	collectors := healthSection{Title: "Collectors", Notes: []healthNote{{Label: "Process", Text: process}}}
	for _, skip := range r.Skipped {
		// A blank label keeps it under the collector it explains.
		collectors.Notes = append(collectors.Notes, healthNote{Label: " ", Text: "skipped " + skip.String()})
	}
	if r.Failure != "" {
		collectors.Notes = append(collectors.Notes, healthNote{Label: " ", Text: r.Failure, Bad: true})
	}
	for _, other := range otherCollectors() {
		// The network collector describes itself when there is one.
		if other[0] != "Network" || !r.HaveNetwork {
			collectors.Notes = append(collectors.Notes, healthNote{Label: other[0], Text: other[1]})
			continue
		}

		n := r.Network
		text := fmt.Sprintf("%s (requested: %s)", n.Backend, r.NetworkRequested)
		if n.Backend == netevents.BackendPoll {
			text += fmt.Sprintf(", snapshot every %s", networkPollInterval)
		}
		collectors.Notes = append(collectors.Notes, healthNote{Label: "Network", Text: text})
		for _, skip := range r.NetworkSkipped {
			collectors.Notes = append(collectors.Notes, healthNote{Label: " ", Text: "skipped " + skip.String()})
		}
		if r.NetworkFailure != "" {
			collectors.Notes = append(collectors.Notes, healthNote{Label: " ", Text: r.NetworkFailure, Bad: true})
		}
	}
	sections := []healthSection{collectors}

	// --- Process events: only an event-driven collector has counters.
	if c.Backend != procevents.BackendPoll {
		clock := healthCell{Label: "clock error ≤", Value: time.Duration(c.ClockErrorNanos).String()}
		sections = append(sections, healthSection{Title: "Process events", Cells: []healthCell{
			count("starts", c.Starts), count("at exec", c.StartsAtExec), count("at fork", c.StartsAtFork),
			count("execs", c.Execs), count("exits", c.Exits),
			count("kernel forks", c.RawForks), count("kernel execs", c.RawExecs), count("kernel exits", c.RawExits),
			bad("kernel drops", c.KernelDrops), bad("undecodable", c.DecodeErrors),
			count("partial", c.Partial), count("args truncated", c.ArgsTruncated), clock,
			count("tracked", c.Tracked), count("pending", c.Pending), bad("tracked cap hits", c.TrackedCapHits),
			count("pid reuses", c.PIDReuses), count("untracked execs", c.UntrackedExecs), count("untracked exits", c.UntrackedExits),
			count("reconciled starts", c.ReconciledStarts), count("reconciled exits", c.ReconciledExits),
			count("duplicate forks", c.DuplicateForks), count("user cache", c.UserCacheSize), count("cache resets", c.UserCacheResets),
		}})
	}

	// --- Network events: only the event-driven collector has counters.
	if r.HaveNetwork && r.Network.Backend != netevents.BackendPoll {
		n := r.Network
		sections = append(sections, healthSection{Title: "Network events", Cells: []healthCell{
			count("connects", n.Connects), count("failed connects", n.Failed), count("accepts", n.Accepts),
			count("closes", n.Closes), count("listens", n.Listens), count("udp sockets", n.UDP),
			bad("kernel drops", n.KernelDrops), bad("unowned closes", n.Unowned), bad("undecodable", n.DecodeErrors),
			count("undescribed", n.Undescribed),
			{Label: "sockets tracked", Value: fmt.Sprintf("%d/%d", min(n.SockInserts, netevents.SockTableSize), netevents.SockTableSize)},
			count("socket inserts", n.SockInserts), count("udp inserts", n.UDPInserts),
			{Label: "clock error ≤", Value: time.Duration(n.ClockErrorNanos).String()},
		}})
	}

	// --- Event bus.
	sections = append(sections, healthSection{Title: "Event bus", Cells: []healthCell{
		count("published", b.Published), count("waited", b.Waited), bad("dropped", b.Dropped),
		{Label: "depth", Value: fmt.Sprintf("%d/%d", b.Depth, b.Capacity), Zero: b.Depth == 0},
	}})

	// --- Detection: what the engine holds and has found.
	measured := e.DetectionLatency.Count > 0
	sections = append(sections, healthSection{Title: "Detection", Cells: []healthCell{
		count("processes", e.Processes), count("exited", e.Tombstones), count("forgotten early", e.TombstonesEvicted),
		count("findings", e.FindingsEmitted), count("excluded", e.FindingsExcluded), count("suppressed", e.FindingsSuppressed),
		count("active suppressions", e.ActiveSuppressions),
		duration("latency p50", e.DetectionLatency.P50, measured),
		duration("latency p99", e.DetectionLatency.P99, measured),
		duration("latency max", e.DetectionLatency.Max, measured),
		count("latency samples", e.DetectionLatency.Count),
		{Label: "order tolerance", Value: r.OrderTolerance.String()},
	}})

	// --- Search effort and the limits it can run into.
	sections = append(sections, healthSection{Title: "Search and limits", Cells: []healthCell{
		count("candidates tried", e.SearchCandidates), count("work deferred", e.SearchWorkDeferred),
		count("processes waiting", e.DeferredProcesses), bad("full rescans", e.FullRescans),
		bad("walks truncated", e.DescendantWalksTruncated), bad("sequences truncated", e.SequencesPossiblyTruncated),
		bad("searches aborted", e.SequenceSearchesAborted),
		count("threshold counters", e.ThresholdCounters), count("counters evicted", e.ThresholdCountersEvicted),
		bad("counter cap hits", e.ThresholdCounterCapHits),
	}})

	// --- Patterns.
	if r.HavePatterns || len(r.Excluded) > 0 {
		patterns := healthSection{Title: "Patterns"}
		if r.HavePatterns {
			patterns.Cells = []healthCell{count("loaded", r.Patterns), count("exclusions", r.Exclusions), bad("errors", len(r.PatternProblems))}
			for _, problem := range r.PatternProblems {
				patterns.Notes = append(patterns.Notes, healthNote{Text: "✗ " + problem, Bad: true})
			}
		}

		rules := make([]string, 0, len(r.Excluded))
		for rule := range r.Excluded {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		for _, rule := range rules {
			patterns.Notes = append(patterns.Notes, healthNote{Label: "excluded", Text: fmt.Sprintf("%s ×%d", rule, r.Excluded[rule])})
		}
		sections = append(sections, patterns)
	}

	return sections
}

// Widths of the report's columns: a cell is a label and a value, and a
// note's label lines up with the cells' labels.
const (
	healthLabelWidth = 20
	healthValueWidth = 10
	healthCellWidth  = healthLabelWidth + healthValueWidth
	healthIndent     = "  "
)

// healthColumns is how many cells fit side by side in width columns.
func healthColumns(width int) int {
	columns := (width - len(healthIndent)) / healthCellWidth
	if columns < 1 {
		return 1
	}
	if columns > 4 {
		return 4
	}
	return columns
}

// layoutHealth renders a report width columns wide. decorate is given each
// piece of text and what it is, and returns it as the view wants it (with
// colour, or as it is).
func layoutHealth(r healthReport, width int, decorate func(text, kind string) string) []string {
	var lines []string

	if alerts := r.Alerts(); len(alerts) > 0 {
		lines = append(lines, decorate(alertPrefix+strings.Join(alerts, " · "), "alert"), "")
	}

	columns := healthColumns(width)

	for i, section := range r.Sections() {
		if i > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, decorate(strings.ToUpper(section.Title), "title"))

		for _, note := range section.Notes {
			kind := "note"
			if note.Bad {
				kind = "bad"
			}
			line := healthIndent + decorate(pad(note.Label, healthLabelWidth), "label") + decorate(note.Text, kind)
			if note.Label == "" {
				line = healthIndent + healthIndent + decorate(note.Text, kind)
			}
			lines = append(lines, line)
		}

		for start := 0; start < len(section.Cells); start += columns {
			var row strings.Builder
			row.WriteString(healthIndent)

			for _, cell := range section.Cells[start:min(start+columns, len(section.Cells))] {
				kind := "value"
				switch {
				case cell.Bad && !cell.Zero:
					kind = "bad"
				case cell.Zero:
					kind = "zero"
				}
				row.WriteString(decorate(pad(cell.Label, healthLabelWidth), "label"))
				row.WriteString(decorate(pad(cell.Value, healthValueWidth), kind))
			}
			lines = append(lines, strings.TrimRight(row.String(), " "))
		}
	}

	return lines
}

// pad extends text with spaces to width columns, always leaving one.
func pad(text string, width int) string {
	if n := len([]rune(text)); n < width {
		return text + strings.Repeat(" ", width-n)
	}
	return text + " "
}

// Lines renders the report as plain text, three values to a row.
func (r healthReport) Lines() []string {
	return layoutHealth(r, len(healthIndent)+3*healthCellWidth, func(text, _ string) string { return text })
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
		fmt.Sprintf("engine_processes=%d tombstones=%d tombstones_evicted=%d findings=%d findings_excluded=%d findings_suppressed=%d active_suppressions=%d",
			e.Processes, e.Tombstones, e.TombstonesEvicted, e.FindingsEmitted, e.FindingsExcluded, e.FindingsSuppressed, e.ActiveSuppressions),
		fmt.Sprintf("detection_latency_count=%d detection_latency_p50_us=%d detection_latency_p99_us=%d detection_latency_max_us=%d",
			e.DetectionLatency.Count, e.DetectionLatency.P50.Microseconds(), e.DetectionLatency.P99.Microseconds(), e.DetectionLatency.Max.Microseconds()),
		fmt.Sprintf("search_candidates=%d search_work_deferred=%d deferred_processes=%d full_rescans=%d",
			e.SearchCandidates, e.SearchWorkDeferred, e.DeferredProcesses, e.FullRescans),
		fmt.Sprintf("descendant_walks_truncated=%d sequences_possibly_truncated=%d sequence_searches_aborted=%d",
			e.DescendantWalksTruncated, e.SequencesPossiblyTruncated, e.SequenceSearchesAborted),
		fmt.Sprintf("threshold_counters=%d threshold_counters_evicted=%d threshold_counter_cap_hits=%d",
			e.ThresholdCounters, e.ThresholdCountersEvicted, e.ThresholdCounterCapHits),
	)

	if r.HaveNetwork {
		n := r.Network
		fields = append(fields, "network_collector="+string(n.Backend))
		if n.Backend != netevents.BackendPoll {
			fields = append(fields,
				fmt.Sprintf("net_connects=%d net_failed=%d net_accepts=%d net_closes=%d net_listens=%d net_udp=%d",
					n.Connects, n.Failed, n.Accepts, n.Closes, n.Listens, n.UDP),
				fmt.Sprintf("net_kernel_drops=%d net_unowned=%d net_decode_errors=%d net_undescribed=%d net_sock_inserts=%d net_udp_inserts=%d",
					n.KernelDrops, n.Unowned, n.DecodeErrors, n.Undescribed, n.SockInserts, n.UDPInserts),
			)
		}
	}
	fields = append(fields, fmt.Sprintf("order_tolerance_ms=%d", r.OrderTolerance.Milliseconds()))

	if r.HavePatterns {
		fields = append(fields, fmt.Sprintf("patterns=%d exclusions=%d pattern_errors=%d", r.Patterns, r.Exclusions, len(r.PatternProblems)))
	}

	return strings.Join(fields, " ")
}

// Text is Lines joined, for a text view.
func (h *health) Text() string {
	return strings.Join(h.Report().Lines(), "\n")
}

// collectorSummary names the active process and network collectors, for the
// TUI footer.
func collectorSummary(processes *processCollection, network *networkCollection) string {
	return fmt.Sprintf("process %s, network %s", processes.Active(), network.Active())
}
