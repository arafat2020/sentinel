//go:build windows

package main

import (
	"os/exec"
	"strings"
)

func sshCurrentStatus() string {
	out, err := exec.Command("sc", "query", "sshd").Output()
	if err != nil {
		return "unknown"
	}
	if strings.Contains(string(out), "RUNNING") {
		return "enabled"
	}
	return "disabled"
}

func sshEnable() error {
	return exec.Command("sc", "start", "sshd").Run()
}

func sshDisable() error {
	return exec.Command("sc", "stop", "sshd").Run()
}
