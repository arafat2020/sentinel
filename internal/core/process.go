package core

import "time"

type ProcessIdentity struct {
	PID       int32
	StartTime time.Time
}

type Process struct {
	PID         int32     `json:"pid"`
	PPID        int32     `json:"ppid"`
	StartTime   time.Time `json:"start_time,omitzero"`
	Name        string    `json:"name,omitempty"`
	Executable  string    `json:"executable,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	User        string    `json:"user,omitempty"`
}

// ProcessImage is the program a process was running until it replaced it
// with exec.
type ProcessImage struct {
	Name        string `json:"name,omitempty"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	// ReplacedAt is when the exec that ended this image happened.
	ReplacedAt time.Time `json:"replaced_at,omitzero"`
}

func (p Process) Identity() ProcessIdentity {
	return ProcessIdentity{
		PID:       p.PID,
		StartTime: p.StartTime,
	}
}

type ProcessSnapshot struct {
	Processes []Process
}
