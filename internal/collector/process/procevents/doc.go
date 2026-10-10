// Package procevents reports process lifecycle events as they happen.
//
// Polling the process table every two seconds cannot see a process that
// starts and exits between two polls, and stamps everything else up to two
// seconds late. The backends here are told by the kernel instead:
//
//   - ebpf attaches to the scheduler's fork, exec and exit tracepoints and
//     receives the process's identity, parent, user, program path and
//     arguments from the kernel itself, so even a process that lives for a
//     millisecond is described completely.
//   - proc-connector listens to the kernel's process-event netlink connector.
//     It is told only that a PID forked, exec'd or exited, and reads the rest
//     from /proc, which may already be gone for a very short-lived process.
//   - poll is the existing snapshot comparison and is not implemented here;
//     see monitor.ProcessMonitor.
//
// Both event-driven backends feed raw kernel events to a Tracker, which turns
// them into PROCESS_START, PROCESS_EXEC and PROCESS_EXIT events with the
// semantics described on Tracker.
//
// # Identity
//
// A process is identified by its PID and start time, and every other
// collector derives the start time the way gopsutil does: the start time in
// clock ticks since boot from /proc/<pid>/stat, converted to milliseconds,
// plus the boot time in whole seconds that gopsutil read once and cached.
// The backends here produce exactly that value from the kernel's own start
// time (see StartTimes), so an event from any source names the same process
// with an identical ProcessIdentity. Nothing matches identities approximately.
//
// # Bounds
//
// Every buffer and table has a cap and a counter, all reported by Stats: the
// kernel ring buffer (drops counted in the kernel), the netlink receive buffer
// (overruns counted), the table of tracked processes, and the cache of user
// names.
package procevents
