package core

import "time"

type ProcessIdentity struct {
	PID       int32
	StartTime time.Time
}

type Process struct {
	PID         int32
	PPID        int32
	StartTime   time.Time
	Name        string
	Executable  string
	CommandLine string
	User        string
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
