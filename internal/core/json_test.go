package core

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func jsonSample() Evidence {
	started := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	process := Process{PID: 200, PPID: 100, StartTime: started, Name: "x", Executable: "/tmp/x", CommandLine: "/tmp/x --run", User: "www-data"}

	return Evidence{
		Process:   &process,
		Processes: []Process{process},
		Roles:     map[string]Process{"payload": process},
		Events: []Event{
			{
				ID: "e1", Timestamp: started.Add(time.Second), Type: EventNetworkConnect, HostID: "host-1", OS: "linux", Process: &process,
				Network:  &NetworkConnection{Timestamp: started, PID: 200, PPID: 100, Protocol: "tcp", LocalAddress: "10.0.0.5", LocalPort: 51000, RemoteAddress: "203.0.113.9", RemotePort: 4444, State: "ESTABLISHED"},
				Metadata: map[string]any{"partial": true},
			},
			{
				Timestamp: started.Add(2 * time.Second), Type: EventFileRename, Process: &process,
				File: &FileEvent{Timestamp: started, PID: 200, Path: "/tmp/x", OldPath: "/tmp/x.part", Operation: FileRename},
			},
			{
				Timestamp: started.Add(3 * time.Second), Type: EventDNSQuery,
				DNS: &DNSQuery{Timestamp: started, PID: 200, Domain: "c2.example", Type: "A", Resolver: "8.8.8.8"},
			},
		},
	}
}

// The stored form of evidence uses fixed snake_case keys, whatever the Go
// fields are called.
func TestEvidenceJSONUsesStableKeys(t *testing.T) {
	encoded, err := json.Marshal(jsonSample())
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		`"process":`, `"processes":`, `"roles":`, `"events":`,
		`"pid":200`, `"ppid":100`, `"start_time":"2026-01-01T12:00:00Z"`, `"name":"x"`, `"executable":"/tmp/x"`, `"command_line":"/tmp/x --run"`, `"user":"www-data"`,
		`"id":"e1"`, `"timestamp":`, `"type":"NETWORK_CONNECT"`, `"host_id":"host-1"`, `"os":"linux"`, `"metadata":{"partial":true}`,
		`"network":`, `"protocol":"tcp"`, `"local_address":"10.0.0.5"`, `"local_port":51000`, `"remote_address":"203.0.113.9"`, `"remote_port":4444`, `"state":"ESTABLISHED"`,
		`"file":`, `"path":"/tmp/x"`, `"old_path":"/tmp/x.part"`, `"operation":"RENAME"`,
		`"dns":`, `"domain":"c2.example"`, `"resolver":"8.8.8.8"`,
	} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("encoded evidence lacks %s:\n%s", key, encoded)
		}
	}

	// No key may still follow a Go field name.
	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				// Role names and metadata keys are data, not schema.
				if path != "roles" && path != "metadata" && key != strings.ToLower(key) {
					t.Errorf("key %q under %q is not snake_case", key, path)
				}
				walk(key, child)
			}
		case []any:
			for _, child := range v {
				walk(path, child)
			}
		}
	}
	walk("", generic)
}

func TestEvidenceJSONRoundTrips(t *testing.T) {
	want := jsonSample()

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Evidence
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the evidence:\n got %+v\nwant %+v", got, want)
	}
}

// legacy mirrors the types as they were when evidence was first stored:
// untagged, so encoding/json wrote the Go field names.
type legacyProcess struct {
	PID         int32
	PPID        int32
	StartTime   time.Time
	Name        string
	Executable  string
	CommandLine string
	User        string
}

type legacyNetwork struct {
	Timestamp     time.Time
	PID           int32
	PPID          int32
	Protocol      string
	LocalAddress  string
	LocalPort     uint32
	RemoteAddress string
	RemotePort    uint32
	State         string
	Process       *legacyProcess
}

type legacyDNS struct {
	Timestamp time.Time
	PID       int32
	PPID      int32
	Domain    string
	Type      string
	Resolver  string
	Process   *legacyProcess
}

type legacyFile struct {
	Timestamp time.Time
	PID       int32
	PPID      int32
	Path      string
	OldPath   string
	Operation FileOperation
	Process   *legacyProcess
}

type legacyEvent struct {
	ID        string
	Timestamp time.Time
	Type      EventType
	HostID    string
	OS        string
	Process   *legacyProcess
	Network   *legacyNetwork
	Metadata  map[string]any
	DNS       *legacyDNS
	File      *legacyFile
}

type legacyEvidence struct {
	Process   *legacyProcess
	Processes []legacyProcess
	Roles     map[string]legacyProcess
	Events    []legacyEvent
}

// Evidence stored under the Go field names must read back with nothing lost,
// including the multi-word fields whose new keys differ by an underscore.
func TestEvidenceJSONReadsGoFieldNames(t *testing.T) {
	want := jsonSample()

	// Re-encode the sample through the untagged mirror types.
	current, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var mirror legacyEvidence
	if err := json.Unmarshal(current, &mirror); err != nil {
		t.Fatal(err)
	}
	// The mirror's multi-word fields have no tags, so fill them by hand.
	fill := func(p *legacyProcess, from Process) {
		p.StartTime, p.CommandLine = from.StartTime, from.CommandLine
	}
	fill(mirror.Process, *want.Process)
	fill(&mirror.Processes[0], want.Processes[0])
	payload := mirror.Roles["payload"]
	fill(&payload, want.Roles["payload"])
	mirror.Roles["payload"] = payload
	for i := range mirror.Events {
		if mirror.Events[i].Process != nil {
			fill(mirror.Events[i].Process, *want.Events[i].Process)
		}
	}
	mirror.Events[0].HostID = want.Events[0].HostID
	network := want.Events[0].Network
	mirror.Events[0].Network.LocalAddress, mirror.Events[0].Network.LocalPort = network.LocalAddress, network.LocalPort
	mirror.Events[0].Network.RemoteAddress, mirror.Events[0].Network.RemotePort = network.RemoteAddress, network.RemotePort
	mirror.Events[1].File.OldPath = want.Events[1].File.OldPath

	legacy, err := json.Marshal(mirror)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"StartTime"`, `"CommandLine"`, `"HostID"`, `"LocalAddress"`, `"RemotePort"`, `"OldPath"`} {
		if !strings.Contains(string(legacy), key) {
			t.Fatalf("the legacy fixture lacks %s; it does not exercise the old format", key)
		}
	}

	var got Evidence
	if err := json.Unmarshal(legacy, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("legacy evidence was not read back whole:\n got %+v\nwant %+v", got, want)
	}
}
