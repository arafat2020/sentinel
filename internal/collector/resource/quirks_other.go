//go:build !darwin

package resource

// zeroTaskInfoMeansDenied: elsewhere a failed query is reported as an error,
// and all-zero readings are genuine (Linux kernel threads, for example).
const zeroTaskInfoMeansDenied = false
