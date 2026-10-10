package core

import (
	"encoding/json"
	"time"
)

// Evidence was first stored without JSON tags, so rows written then use the Go
// field names as keys ("StartTime", "CommandLine", "HostID", ...). The tags
// now fix snake_case names. encoding/json matches keys without regard to
// case, which already reads every single-word legacy key ("PID", "Process",
// "Timestamp"); the decoders below add the multi-word ones, which differ by an
// underscore and would otherwise be dropped silently.
//
// Only reading is affected. Evidence is always written with the tagged names.

func (p *Process) UnmarshalJSON(data []byte) error {
	type plain Process
	aux := struct {
		*plain
		StartTime   *time.Time `json:"StartTime"`
		CommandLine *string    `json:"CommandLine"`
	}{plain: (*plain)(p)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.StartTime != nil {
		p.StartTime = *aux.StartTime
	}
	if aux.CommandLine != nil {
		p.CommandLine = *aux.CommandLine
	}
	return nil
}

func (e *Event) UnmarshalJSON(data []byte) error {
	type plain Event
	aux := struct {
		*plain
		HostID *string `json:"HostID"`
	}{plain: (*plain)(e)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.HostID != nil {
		e.HostID = *aux.HostID
	}
	return nil
}

func (c *NetworkConnection) UnmarshalJSON(data []byte) error {
	type plain NetworkConnection
	aux := struct {
		*plain
		LocalAddress  *string `json:"LocalAddress"`
		LocalPort     *uint32 `json:"LocalPort"`
		RemoteAddress *string `json:"RemoteAddress"`
		RemotePort    *uint32 `json:"RemotePort"`
	}{plain: (*plain)(c)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.LocalAddress != nil {
		c.LocalAddress = *aux.LocalAddress
	}
	if aux.LocalPort != nil {
		c.LocalPort = *aux.LocalPort
	}
	if aux.RemoteAddress != nil {
		c.RemoteAddress = *aux.RemoteAddress
	}
	if aux.RemotePort != nil {
		c.RemotePort = *aux.RemotePort
	}
	return nil
}

func (f *FileEvent) UnmarshalJSON(data []byte) error {
	type plain FileEvent
	aux := struct {
		*plain
		OldPath *string `json:"OldPath"`
	}{plain: (*plain)(f)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.OldPath != nil {
		f.OldPath = *aux.OldPath
	}
	return nil
}
