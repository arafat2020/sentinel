//go:build linux && integration

package procevents_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	filecollector "github.com/arafat2020/sentinel/internal/collector/file"
	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	processcollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/collector/process/procevents"
	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
	lifecycle "github.com/arafat2020/sentinel/internal/detection/process"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/monitor"
)

const guide = "../../../../docs/behavioral-patterns.md"

// guidePattern loads one worked example from the pattern guide, exactly as a
// user would paste it into patterns.yaml.
func guidePattern(t *testing.T, name string) correlation.BehaviorPattern {
	t.Helper()

	data, err := os.ReadFile(guide)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(string(data), "```")
	for i := 1; i < len(parts); i += 2 {
		body, isYAML := strings.CutPrefix(parts[i], "yaml\n")
		if !isYAML || !strings.HasPrefix(body, "- name: "+name+"\n") {
			continue
		}

		lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
		for j, line := range lines {
			if line != "" {
				lines[j] = "  " + line
			}
		}

		path := filepath.Join(t.TempDir(), "patterns.yaml")
		if err := os.WriteFile(path, []byte("patterns:\n"+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		set, err := config.LoadPatterns(path)
		if err != nil || len(set.Errors) != 0 || len(set.Patterns) != 1 {
			t.Fatalf("the guide's %s example does not load: %v %v", name, err, set.Errors)
		}
		return set.Patterns[0]
	}

	t.Fatalf("the guide has no example named %s", name)
	return correlation.BehaviorPattern{}
}

// slowDownload serves a file, pausing part-way through. The connection then
// stays open for longer than the network collector's two-second poll, so the
// collector sees it. (Network collection becomes event-driven in a later
// phase; until then a connection that opens and closes between two polls is
// invisible, whatever the process collector does.)
func slowDownload(t *testing.T, content []byte, pause time.Duration) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		half := len(content) / 2

		w.Write(content[:half])
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(pause)
		w.Write(content[half:])
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	return "http://" + listener.Addr().String() + "/x"
}

// The guide's download-and-execute example, for real: a local web server, a
// shell that runs curl -o /tmp/…/x, chmod +x, and then the downloaded file.
// The payload is a copy of true(1), which exits within a millisecond of
// starting.
//
// Every collector is the real one, as the entrypoints wire them: fanotify for
// the file, the network poller for the connection, and the process backend
// under test. That they agree on which process is which is part of what is
// being tested: the file and network events are attributed through /proc,
// and the rule only matches if those are the same identities the process
// backend reported.
func TestDownloadAndExecuteEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, tool := range []string{"curl", "sh", "chmod", "true"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s on this host", tool)
		}
	}

	pattern := guidePattern(t, "download-and-execute")

	truePath, _ := exec.LookPath("true")
	payload, err := os.ReadFile(truePath)
	if err != nil {
		t.Fatal(err)
	}

	fired := map[procevents.Backend]bool{}

	for _, backend := range []procevents.Backend{procevents.BackendEBPF, procevents.BackendProcConnector, procevents.BackendPoll} {
		t.Run(string(backend), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var running sync.WaitGroup
			defer func() {
				cancel()
				running.Wait()
			}()

			collector := processcollector.NewCollector()
			snapshot := func(ctx context.Context) ([]core.Process, error) {
				s, err := collector.Collect(ctx)
				if err != nil {
					return nil, err
				}
				return s.Processes, nil
			}

			source, _, err := procevents.Open(backend, procevents.Options{Snapshot: snapshot})
			if err != nil {
				t.Fatal(err)
			}

			engine := correlation.NewEngine(correlation.DefaultWindow)
			engine.SetPatterns([]correlation.BehaviorPattern{pattern})

			var mu sync.Mutex
			var findings []core.Finding
			var seen []string

			bus := eventbus.New(1000)
			bus.Subscribe(func(event core.Event) {
				engine.Process(event)
				found := engine.DetectBehaviors()

				mu.Lock()
				defer mu.Unlock()
				findings = append(findings, found...)
				if event.Process != nil {
					line := fmt.Sprintf("%s %s pid=%d ppid=%d started=%d %s exe=%s",
						event.Timestamp.Format("15:04:05.000"), event.Type, event.Process.PID, event.Process.PPID,
						event.Process.StartTime.UnixMilli(), event.Process.Name, event.Process.Executable)
					if event.File != nil {
						line += " path=" + event.File.Path
					}
					seen = append(seen, line)
				}
			})

			seed, err := snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			engine.Seed(seed)
			bus.Start(ctx)

			// Process events, from the backend under test.
			running.Add(1)
			go func() {
				defer running.Done()
				if source == nil {
					monitor.NewProcessMonitor(collector, lifecycle.NewLifecycleDetector(), 2*time.Second, bus, noSnapshots{}).Run(ctx)
					return
				}
				defer source.Close()
				if err := monitor.NewProcessEventMonitor(source, bus).Run(ctx, seed); err != nil {
					t.Errorf("%s stopped: %v", backend, err)
				}
			}()

			// File events, from fanotify.
			files, err := filecollector.NewLinuxCollector("/", processcollector.NewResolver())
			if err != nil {
				t.Fatal(err)
			}
			running.Add(1)
			go func() {
				defer running.Done()
				if err := monitor.NewFileMonitor(files, bus).Run(ctx); err != nil && ctx.Err() == nil {
					t.Errorf("file monitor stopped: %v", err)
				}
			}()

			// Network events, polled.
			running.Add(1)
			go func() {
				defer running.Done()
				monitor.NewNetworkMonitor(networkcollector.NewCollector(), networkdetector.NewLifecycleDetector(), 2*time.Second, bus).Run(ctx)
			}()

			// Let every collector take its baseline.
			time.Sleep(3 * time.Second)

			dir, err := os.MkdirTemp("/tmp", "sentinel-e2e-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			dropped := filepath.Join(dir, "x")

			url := slowDownload(t, payload, 5*time.Second)

			// The trailing command keeps the shell from exec'ing the
			// payload in place of itself, which would be a PROCESS_EXEC
			// on the shell rather than the start of a child.
			script := fmt.Sprintf("curl -s -o %s %s; chmod +x %s; %s; true", dropped, url, dropped, dropped)
			if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
				t.Fatalf("the scenario itself failed: %v\n%s", err, out)
			}

			matched := func() *core.Finding {
				mu.Lock()
				defer mu.Unlock()
				for i := range findings {
					if findings[i].Rule == "download-and-execute" && findings[i].Evidence.Roles["payload"].Executable == dropped {
						return &findings[i]
					}
				}
				return nil
			}

			deadline := time.Now().Add(8 * time.Second)
			for matched() == nil && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}

			finding := matched()
			fired[backend] = finding != nil

			if finding == nil {
				mu.Lock()
				var relevant []string
				for _, line := range seen {
					if strings.Contains(line, dir) || strings.Contains(line, " curl ") || strings.Contains(line, script) {
						relevant = append(relevant, line)
					}
				}
				mu.Unlock()
				t.Logf("%s: download-and-execute did NOT fire. Events naming curl or the payload:\n  %s", backend, strings.Join(relevant, "\n  "))
			} else {
				roles := finding.Evidence.Roles
				t.Logf("%s: download-and-execute fired: launcher=%s(%d) downloader=%s(%d) payload=%s(%d), %d evidence events",
					backend, roles["launcher"].Name, roles["launcher"].PID, roles["downloader"].Name, roles["downloader"].PID,
					roles["payload"].Executable, roles["payload"].PID, len(finding.Evidence.Events))

				if roles["downloader"].Name != "curl" || roles["launcher"].Name != "sh" && roles["launcher"].Name != "dash" {
					t.Errorf("roles bound to the wrong processes: %+v", roles)
				}
				if roles["payload"].PPID != roles["launcher"].PID || roles["downloader"].PPID != roles["launcher"].PID {
					t.Errorf("roles are not parent and children: %+v", roles)
				}
			}

			if backend == procevents.BackendEBPF && finding == nil {
				t.Errorf("the rule must fire with the eBPF backend")
			}
		})
	}

	t.Logf("download-and-execute fired: ebpf=%v proc-connector=%v poll=%v",
		fired[procevents.BackendEBPF], fired[procevents.BackendProcConnector], fired[procevents.BackendPoll])
}

// noSnapshots stands in for the legacy rule coordinator, which this test does
// not exercise.
type noSnapshots struct{}

func (noSnapshots) UpdateSnapshot(*core.ProcessSnapshot) {}
