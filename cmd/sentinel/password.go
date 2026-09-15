package main

import (
	"fmt"
	"os"

	"github.com/arafat2020/sentinel/internal/auth"
	"github.com/arafat2020/sentinel/internal/store"
	"golang.org/x/term"
)

const maxAttempts = 3

// runPasswordGate enforces the password gate before the main UI starts.
//
// First run (no password stored): prompts to create one.
// Subsequent runs: prompts for the password; exits after maxAttempts failures.
// --reset-password flag: prompts for the old password (if set), then a new one.
func runPasswordGate(s *store.Store, resetMode bool) {
	if resetMode {
		resetPassword(s)
		return
	}

	if !s.HasPassword() {
		setupPassword(s)
		return
	}

	verifyPassword(s)
}

// setupPassword is shown on first install — no existing password.
func setupPassword(s *store.Store) {
	fmt.Println("Welcome to Sentinel. Please create a password to protect the TUI.")
	fmt.Println()

	for {
		pw := readPassword("New password: ")
		if pw == "" {
			fmt.Fprintln(os.Stderr, "Password must not be empty. Try again.")
			continue
		}
		confirm := readPassword("Confirm password: ")
		if pw != confirm {
			fmt.Fprintln(os.Stderr, "Passwords do not match. Try again.")
			continue
		}
		hash, err := auth.Hash(pw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: failed to hash password: %v\n", err)
			os.Exit(1)
		}
		if err := s.SetPasswordHash(hash); err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: failed to save password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Password set. Starting Sentinel...")
		fmt.Println()
		return
	}
}

// verifyPassword prompts for the password and exits on repeated failure.
func verifyPassword(s *store.Store) {
	hash := s.GetPasswordHash()

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		pw := readPassword("Sentinel password: ")
		if err := auth.Verify(hash, pw); err == nil {
			fmt.Println()
			return
		}
		remaining := maxAttempts - attempt
		if remaining == 0 {
			fmt.Fprintln(os.Stderr, "Too many failed attempts. Exiting.")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Wrong password. %d attempt(s) remaining.\n", remaining)
	}
}

// resetPassword lets the user change their password.
// If a password is already set the old one must be verified first.
func resetPassword(s *store.Store) {
	fmt.Println("Sentinel — Reset Password")
	fmt.Println()

	if s.HasPassword() {
		hash := s.GetPasswordHash()
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			old := readPassword("Current password: ")
			if auth.Verify(hash, old) == nil {
				break
			}
			remaining := maxAttempts - attempt
			if remaining == 0 {
				fmt.Fprintln(os.Stderr, "Too many failed attempts. Exiting.")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Wrong password. %d attempt(s) remaining.\n", remaining)
		}
	}

	for {
		pw := readPassword("New password: ")
		if pw == "" {
			fmt.Fprintln(os.Stderr, "Password must not be empty. Try again.")
			continue
		}
		confirm := readPassword("Confirm new password: ")
		if pw != confirm {
			fmt.Fprintln(os.Stderr, "Passwords do not match. Try again.")
			continue
		}
		hash, err := auth.Hash(pw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: failed to hash password: %v\n", err)
			os.Exit(1)
		}
		if err := s.SetPasswordHash(hash); err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: failed to save password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Password updated successfully.")
		os.Exit(0)
	}
}

// readPassword reads a password from the terminal with echo suppressed.
// Falls back to a plain read if stdin is not a TTY (e.g. piped input in tests).
func readPassword(prompt string) string {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println() // newline after hidden input
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: could not read password: %v\n", err)
			os.Exit(1)
		}
		return string(b)
	}
	// Non-TTY fallback (useful in CI / scripted installs).
	var pw string
	fmt.Scanln(&pw)
	return pw
}
