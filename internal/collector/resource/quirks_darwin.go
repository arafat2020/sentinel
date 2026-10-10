//go:build darwin

package resource

// zeroTaskInfoMeansDenied: on macOS gopsutil reads CPU time and memory with
// proc_pidinfo but ignores its return value, so a query the kernel refused
// (another user's process without root, or a zombie) comes back as all zeros
// with a nil error. A running process always has resident and virtual memory,
// so an all-zero reading there means "not readable", not "idle".
const zeroTaskInfoMeansDenied = true
