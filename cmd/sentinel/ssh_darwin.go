//go:build darwin

package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

const (
	sshPlist   = "/System/Library/LaunchDaemons/ssh.plist"
	sshService = "system/com.openssh.sshd"
)

// sshCurrentStatus checks whether sshd is accepting connections on port 22.
// This is the definitive test: no timing races, no process-name guessing.
func sshCurrentStatus() string {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 2*time.Second)
	if err == nil {
		conn.Close()
		return "enabled"
	}
	return "disabled"
}

func sshEnable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Persist across reboots.
	if out, err := exec.CommandContext(ctx, "launchctl", "enable", sshService).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl enable: %w — %s", err, strings.TrimSpace(string(out)))
	}

	// Try bootstrap (works when the service is not yet loaded into launchd).
	// If that fails the service is already known — use kickstart to start it.
	if err := exec.CommandContext(ctx, "launchctl", "bootstrap", "system", sshPlist).Run(); err != nil {
		out, err2 := exec.CommandContext(ctx, "launchctl", "kickstart", "-k", sshService).CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("launchctl kickstart: %w — %s", err2, strings.TrimSpace(string(out)))
		}
	}

	// Give sshd up to 5 seconds to open port 22.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sshCurrentStatus() == "enabled" {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("sshd started but port 22 is not yet accepting connections")
}

func sshDisable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop the running service; ignore "not loaded" errors.
	exec.CommandContext(ctx, "launchctl", "bootout", sshService).Run()

	// Persist disabled state across reboots.
	if out, err := exec.CommandContext(ctx, "launchctl", "disable", sshService).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl disable: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
