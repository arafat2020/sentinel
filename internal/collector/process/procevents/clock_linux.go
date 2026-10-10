//go:build linux

package procevents

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"

	// The polling collector turns on gopsutil's boot-time cache when it
	// is loaded. StartTimes depends on that cache being on.
	_ "github.com/arafat2020/sentinel/internal/collector/process"
)

// StartTimes converts the kernel's record of when a process started into the
// start time every other part of Sentinel uses for that process, exactly.
//
// The rest of Sentinel takes a process's start time from gopsutil, which
// computes, in integer arithmetic,
//
//	milliseconds = ticks * 1000 / CLK_TCK + bootSeconds * 1000
//
// where ticks is field 22 of /proc/<pid>/stat and bootSeconds is the boot
// time gopsutil read once and cached. The kernel derives ticks from the
// task's start_boottime (nanoseconds since boot) by dividing by the length of
// a tick, 1e9 / USER_HZ, discarding the remainder. USER_HZ is what CLK_TCK
// reports. So from start_boottime:
//
//	ticks = start_boottime / (1e9 / CLK_TCK)
//
// and the same formula then gives the same millisecond. No rounding differs
// and nothing is compared approximately.
//
// bootSeconds is not read again here, because a second reading could differ
// from the cached one (that is why it is cached). It is recovered from
// gopsutil itself: this process's start time as gopsutil reports it, minus
// this process's ticks converted the same way, is exactly the base gopsutil
// is using.
type StartTimes struct {
	clockTicks   uint64
	nanosPerTick uint64
	bootMillis   int64
}

// NewStartTimes works out the conversion for this host.
func NewStartTimes() (*StartTimes, error) {
	ticksPerSecond := clockTicks()
	if ticksPerSecond == 0 || 1_000_000_000%ticksPerSecond != 0 {
		// The kernel then converts with a different formula; no such
		// configuration exists on a supported architecture.
		return nil, fmt.Errorf("unsupported clock tick rate %d", ticksPerSecond)
	}

	pid := os.Getpid()
	_, _, ticks, err := readStat(pid)
	if err != nil {
		return nil, fmt.Errorf("read own start time: %w", err)
	}

	self, err := gopsprocess.NewProcess(int32(pid))
	if err != nil {
		return nil, fmt.Errorf("look up own process: %w", err)
	}
	created, err := self.CreateTime()
	if err != nil {
		return nil, fmt.Errorf("read own creation time: %w", err)
	}

	return &StartTimes{
		clockTicks:   ticksPerSecond,
		nanosPerTick: 1_000_000_000 / ticksPerSecond,
		bootMillis:   created - int64(ticks*1000/ticksPerSecond),
	}, nil
}

// FromTicks converts field 22 of /proc/<pid>/stat.
func (s *StartTimes) FromTicks(ticks uint64) time.Time {
	return time.UnixMilli(int64(ticks*1000/s.clockTicks) + s.bootMillis)
}

// FromBootNanos converts a task's start_boottime.
func (s *StartTimes) FromBootNanos(nanos uint64) time.Time {
	return s.FromTicks(nanos / s.nanosPerTick)
}

// clockTicks is CLK_TCK, which the kernel passes to every process in its
// auxiliary vector.
func clockTicks() uint64 {
	const atClockTick = 17 // AT_CLKTCK

	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 100
	}

	word := strconv.IntSize / 8
	for i := 0; i+2*word <= len(auxv); i += 2 * word {
		var key, value uint64
		if word == 8 {
			key, value = binary.NativeEndian.Uint64(auxv[i:]), binary.NativeEndian.Uint64(auxv[i+8:])
		} else {
			key, value = uint64(binary.NativeEndian.Uint32(auxv[i:])), uint64(binary.NativeEndian.Uint32(auxv[i+4:]))
		}
		if key == atClockTick && value > 0 {
			return value
		}
	}

	return 100
}

// readStat reads the name, parent and start time (in clock ticks since boot)
// of a process from /proc/<pid>/stat.
func readStat(pid int) (comm string, ppid int32, startTicks uint64, err error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, 0, err
	}

	// The name is in parentheses and may itself contain parentheses and
	// spaces, so it ends at the last ')'.
	text := string(data)
	open, shut := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open < 0 || shut < open {
		return "", 0, 0, errors.New("malformed stat")
	}
	comm = text[open+1 : shut]

	// Fields after the name start with field 3 (state); the parent is
	// field 4 and the start time field 22.
	fields := strings.Fields(text[shut+1:])
	if len(fields) < 20 {
		return "", 0, 0, errors.New("malformed stat")
	}

	parent, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return "", 0, 0, err
	}
	startTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", 0, 0, err
	}

	return comm, int32(parent), startTicks, nil
}

// wallClock converts readings of a kernel clock (CLOCK_BOOTTIME for eBPF,
// CLOCK_MONOTONIC for the proc connector) to wall-clock time.
//
// Both clocks count nanoseconds from an arbitrary origin. The offset to the
// wall clock is found by reading the wall clock, the kernel clock, and the
// wall clock again: the kernel clock was read somewhere between the two wall
// readings, so taking their midpoint is wrong by at most half the time the
// three readings took. The best of several attempts is used, and the bound
// is reported in Stats.ClockErrorNanos. The offset is refreshed periodically
// because the wall clock is steered by NTP and can be stepped.
type wallClock struct {
	id     int32
	offset atomic.Int64
	bound  atomic.Int64
}

func newWallClock(id int32) *wallClock {
	w := &wallClock{id: id}
	w.sync()
	return w
}

func (w *wallClock) sync() {
	best := int64(-1)
	offset := int64(0)

	for attempt := 0; attempt < 8; attempt++ {
		var before, kernel, after unix.Timespec
		if unix.ClockGettime(unix.CLOCK_REALTIME, &before) != nil ||
			unix.ClockGettime(w.id, &kernel) != nil ||
			unix.ClockGettime(unix.CLOCK_REALTIME, &after) != nil {
			continue
		}

		spread := after.Nano() - before.Nano()
		if spread < 0 {
			continue // the wall clock was stepped between the readings
		}
		if best < 0 || spread < best {
			best = spread
			offset = before.Nano() + spread/2 - kernel.Nano()
		}
	}

	if best >= 0 {
		w.offset.Store(offset)
		w.bound.Store((best + 1) / 2)
	}
}

func (w *wallClock) at(kernelNanos uint64) time.Time {
	return time.Unix(0, w.offset.Load()+int64(kernelNanos))
}
