package core

import "time"

type EventType string

const (
	EventProcessStart      EventType = "PROCESS_START"
	EventProcessExit       EventType = "PROCESS_EXIT"
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
	ID        string
	Timestamp time.Time
	Type      EventType

	HostID string
	OS     string

	Process *Process

	Network *NetworkConnection

	Metadata map[string]any
	DNS      *DNSQuery
}
