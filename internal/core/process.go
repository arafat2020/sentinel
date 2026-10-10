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

func (p Process) Identity() ProcessIdentity {
	return ProcessIdentity{
		PID:       p.PID,
		StartTime: p.StartTime,
	}
}

type ProcessSnapshot struct {
	Processes []Process
}
