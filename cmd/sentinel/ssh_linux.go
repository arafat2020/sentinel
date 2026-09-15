//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func sshCurrentStatus() string {
	// Different distros use "sshd" or "ssh" as the service name.
	for _, svc := range []string{"sshd", "ssh"} {
		out, err := exec.Command("systemctl", "is-active", svc).Output()
		if err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return "enabled"
			}
			return "disabled"
		}
	}
	return "unknown"
}

func sshEnable() error {
	for _, svc := range []string{"sshd", "ssh"} {
		out, err := exec.Command("systemctl", "start", svc).CombinedOutput()
		if err == nil {
			return nil
		}
		if len(strings.TrimSpace(string(out))) > 0 {
			return fmt.Errorf("%w — %s", err, strings.TrimSpace(string(out)))
		}
	}
	return fmt.Errorf("could not start sshd or ssh service")
}

func sshDisable() error {
	for _, svc := range []string{"sshd", "ssh"} {
		out, err := exec.Command("systemctl", "stop", svc).CombinedOutput()
		if err == nil {
			return nil
		}
		if len(strings.TrimSpace(string(out))) > 0 {
			return fmt.Errorf("%w — %s", err, strings.TrimSpace(string(out)))
		}
	}
	return fmt.Errorf("could not stop sshd or ssh service")
}
