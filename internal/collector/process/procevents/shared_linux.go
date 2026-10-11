//go:build linux

package procevents

import (
	"time"

	"golang.org/x/sys/unix"
)

// What the network collector shares with this one, so that both turn kernel
// time and user IDs into exactly the same values: one conversion, used twice,
// rather than two that are supposed to agree.

// BootClock converts CLOCK_BOOTTIME readings, as bpf_ktime_get_boot_ns
// returns them, to wall-clock time.
type BootClock struct{ clock *wallClock }

// NewBootClock measures the offset once; call Sync to measure it again.
func NewBootClock() *BootClock { return &BootClock{clock: newWallClock(unix.CLOCK_BOOTTIME)} }

// At is the wall-clock time of a kernel timestamp.
func (c *BootClock) At(bootNanos uint64) time.Time { return c.clock.at(bootNanos) }

// Sync measures the offset again; the wall clock is steered and can step.
func (c *BootClock) Sync() { c.clock.sync() }

// ErrorNanos bounds the error of the last measurement.
func (c *BootClock) ErrorNanos() int64 { return c.clock.bound.Load() }

// UserNames resolves user IDs to names as the process collectors do, with a
// bounded cache.
type UserNames struct{ cache *userCache }

func NewUserNames() *UserNames { return &UserNames{cache: newUserCache()} }

// Name returns the user name, or "" when nothing knows the ID.
func (u *UserNames) Name(uid uint32) string { return u.cache.name(uid) }

// ImageName is the process name the collectors report for a kernel task name
// (see imageName); with only the task name to go on it is that name.
func ImageName(comm string) string { return imageName(comm, "", "") }
