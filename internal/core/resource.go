package core

import "time"

// ProcessUsage is one process's resource consumption at a point in time.
//
// A metric whose *Valid flag is false could not be measured (permission
// denied, no previous sample to diff against, platform limitation); its value
// is then meaningless and must not be shown as a real zero.
type ProcessUsage struct {
	PID int32
	// StartTime is the process creation time, or the zero Time when the
	// platform would not report it.
	StartTime time.Time
	Name      string // empty when the name could not be read
	// CPUPercent is relative to a single core: a process saturating two
	// cores reports 200.
	CPUPercent  float64
	CPUValid    bool
	MemoryBytes uint64 // resident set size
	MemoryValid bool
}

// SameProcess reports whether p and other describe the same process, not just
// the same PID. PIDs are recycled, so the start time is compared as well. When
// neither side has a start time the PID is all there is to go on and is
// trusted; when only one side has one they are treated as different.
func (p ProcessUsage) SameProcess(other ProcessUsage) bool {
	return p.PID == other.PID && p.StartTime.Equal(other.StartTime)
}

// SystemUsage is host-wide utilization. The *Valid flags are false when the
// platform could not supply the figure (or, for CPU, when there is no
// previous sample to diff against yet).
type SystemUsage struct {
	CPUPercent  float64 // 0-100 across all cores
	CPUValid    bool
	MemoryUsed  uint64
	MemoryTotal uint64
	MemoryValid bool
}

// ResourceSnapshot is a live view of resource usage. It is display-only
// telemetry: it is never published on the event bus or persisted.
type ResourceSnapshot struct {
	Timestamp time.Time
	System    SystemUsage
	Processes []ProcessUsage
}
