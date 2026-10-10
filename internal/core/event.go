package core

import "time"

type EventType string

const (
	EventProcessStart EventType = "PROCESS_START"
	EventProcessExit  EventType = "PROCESS_EXIT"
	// EventProcessExec is a running process replacing its program image
	// with execve. The process keeps its identity; its name, executable
	// and command line change. Only event-driven process collectors report
	// it: a process's first exec shortly after it is created is folded into
	// its PROCESS_START instead.
	EventProcessExec       EventType = "PROCESS_EXEC"
	EventProcessSnapshot   EventType = "PROCESS_SNAPSHOT"
	EventNetworkConnect    EventType = "NETWORK_CONNECT"
	EventNetworkClose      EventType = "NETWORK_CLOSE"
	EventFileCreate        EventType = "FILE_CREATE"
	EventFileModify        EventType = "FILE_MODIFY"
	EventFileDelete        EventType = "FILE_DELETE"
	EventFileRename        EventType = "FILE_RENAME"
	EventPersistenceChange EventType = "PERSISTENCE_CHANGE"
	EventDNSQuery          EventType = "DNS_QUERY"
	EventScriptExecution   EventType = "SCRIPT_EXECUTION"
)

type Event struct {
	ID        string             `json:"id,omitempty"`
	Timestamp time.Time          `json:"timestamp,omitzero"`
	Type      EventType          `json:"type"`
	HostID    string             `json:"host_id,omitempty"`
	OS        string             `json:"os,omitempty"`
	Process   *Process           `json:"process,omitempty"`
	Network   *NetworkConnection `json:"network,omitempty"`
	Metadata  map[string]any     `json:"metadata,omitempty"`
	DNS       *DNSQuery          `json:"dns,omitempty"`
	File      *FileEvent         `json:"file,omitempty"`
}
