package core

import "time"

// ProcessUsage is one process's resource consumption at a point in time.
type ProcessUsage struct {
	PID  int32
	Name string
	// CPUPercent is relative to a single core: a process saturating two
	// cores reports 200.
	CPUPercent  float64
	MemoryBytes uint64 // resident set size
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
