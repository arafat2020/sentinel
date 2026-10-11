package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// patternState is everything the patterns file currently amounts to.
type patternState struct {
	Patterns   []correlation.BehaviorPattern
	Exclusions []correlation.Exclusion
	// Errors are the entries of the file that were left out, and Warnings
	// the things in it that were ignored.
	Errors   []config.PatternError
	Warnings []string
	// FileError is set when the file as a whole could not be used (it is
	// unreadable, or not YAML). The patterns in force are then the ones
	// from before.
	FileError string
	// Source says what produced this state: "startup", "saved" (by
	// Sentinel itself) or "file changed" (by something else).
	Source string
}

// Problems lists everything wrong with the patterns, for display.
func (s patternState) Problems() []string {
	problems := patternProblems(s.Errors, s.Patterns)
	if s.FileError != "" {
		problems = append([]string{s.FileError}, problems...)
	}
	return problems
}

// patternStore is the one place the patterns file is read, written and
// applied to the engine. The pattern editors, the exclusion form and the
// file watcher all go through it, so that whichever of them changes the
// file, the engine and every interface see the same result.
type patternStore struct {
	path   string
	engine *correlation.Engine

	mu        sync.Mutex
	state     patternState
	applied   [sha256.Size]byte // hash of the file contents last applied
	listeners []func(patternState)

	// externalReloads counts the times a change made by something other
	// than Sentinel was applied.
	externalReloads atomic.Int64
}

// newPatternStore takes over a patterns file that has just been loaded as
// initial and applied to the engine.
func newPatternStore(path string, engine *correlation.Engine, initial config.PatternSet, loadErr error) *patternStore {
	s := &patternStore{path: path, engine: engine}

	s.state = patternState{
		Patterns:   initial.Patterns,
		Exclusions: initial.Exclusions,
		Errors:     initial.Errors,
		Warnings:   initial.Warnings,
		Source:     "startup",
	}
	if loadErr != nil {
		s.state.FileError = loadErr.Error() + " (using the built-in patterns)"
	}
	if data, err := os.ReadFile(path); err == nil {
		s.applied = sha256.Sum256(data)
	}

	return s
}

// State returns the current patterns. The slices are shared: do not modify
// them.
func (s *patternStore) State() patternState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// OnChange registers fn to be called, from whichever goroutine made the
// change, each time the patterns are replaced.
func (s *patternStore) OnChange(fn func(patternState)) {
	s.mu.Lock()
	s.listeners = append(s.listeners, fn)
	s.mu.Unlock()
}

// Writable reports whether the patterns file can be saved from here.
func (s *patternStore) Writable() error { return config.CheckWritable(s.path) }

// refresh reads the file and, unless its contents are the ones already in
// force, applies it to the engine and tells the listeners. It reports
// whether anything was applied.
//
// Comparing contents is what stops Sentinel reacting to its own saves: a save
// is followed at once by a refresh, so by the time the watcher hears of the
// write there is nothing new in the file.
func (s *patternStore) refresh(source string) bool {
	data, readErr := os.ReadFile(s.path)

	s.mu.Lock()

	if readErr == nil {
		hash := sha256.Sum256(data)
		if hash == s.applied {
			s.mu.Unlock()
			return false
		}
		s.applied = hash
	}

	set, err := config.LoadPatterns(s.path)
	if readErr != nil || err != nil {
		// Nothing can be made of the file. Keep detecting with what was
		// loaded before, and say so.
		if readErr != nil {
			err = readErr
		}
		message := fmt.Sprintf("%v (keeping the patterns loaded before)", err)
		if s.state.FileError == message {
			s.mu.Unlock()
			return false
		}
		s.state.FileError = message
		s.state.Source = source
	} else {
		s.state = patternState{
			Patterns:   set.Patterns,
			Exclusions: set.Exclusions,
			Errors:     set.Errors,
			Warnings:   set.Warnings,
			Source:     source,
		}
		// Invalid exclusions are already among the errors.
		_ = s.engine.Reload(set.Patterns, set.Exclusions)
	}

	state := s.state
	listeners := append([]func(patternState){}, s.listeners...)
	s.mu.Unlock()

	for _, listener := range listeners {
		listener(state)
	}
	return true
}

// SavePatterns writes the patterns an editor holds and applies the result.
// What the editors do not hold (exclusions, and patterns that do not load)
// is kept, as config.SavePatterns keeps it.
func (s *patternStore) SavePatterns(patterns []correlation.BehaviorPattern) error {
	if err := s.Writable(); err != nil {
		return err
	}
	if err := config.SavePatterns(s.path, patterns); err != nil {
		return err
	}
	s.refresh("saved")
	return nil
}

// PatternYAML returns the YAML of the pattern at index, as it would be saved.
func (s *patternStore) PatternYAML(index int) (string, error) {
	state := s.State()
	if index < 0 || index >= len(state.Patterns) {
		return "", fmt.Errorf("no pattern at position %d", index)
	}
	return config.PatternYAML(state.Patterns[index])
}

// SavePatternYAML checks YAML from the editor and, only if nothing is wrong
// with it, saves it as the pattern at index, or as a new pattern when index
// is negative. Anything wrong is returned and nothing is written.
func (s *patternStore) SavePatternYAML(index int, text string) []config.EditError {
	pattern, problems := config.ParsePatternYAML(text)
	if len(problems) > 0 {
		return problems
	}

	state := s.State()
	if index >= len(state.Patterns) {
		return []config.EditError{{Message: "the pattern being edited no longer exists (the file changed); copy your text and reopen it"}}
	}

	for i, existing := range state.Patterns {
		if i != index && existing.Name == pattern.Name {
			return []config.EditError{{Path: "name", Message: fmt.Sprintf("another pattern is already called %q", pattern.Name)}}
		}
	}

	patterns := append([]correlation.BehaviorPattern{}, state.Patterns...)
	if index < 0 {
		patterns = append(patterns, pattern)
	} else {
		patterns[index] = pattern
	}

	if err := s.SavePatterns(patterns); err != nil {
		return []config.EditError{{Message: err.Error()}}
	}
	return nil
}

// ExclusionsYAML returns the file's top-level exclusions for editing.
func (s *patternStore) ExclusionsYAML() (string, error) {
	return config.ExclusionsYAML(s.path)
}

// SaveExclusionsYAML checks an edited exclusions list and, only if nothing
// is wrong with it, saves it.
func (s *patternStore) SaveExclusionsYAML(text string) []config.EditError {
	entries, problems := config.ParseExclusionsYAML(text)
	if len(problems) > 0 {
		return problems
	}
	if err := s.Writable(); err != nil {
		return []config.EditError{{Message: err.Error()}}
	}
	if err := config.SaveExclusions(s.path, entries); err != nil {
		return []config.EditError{{Message: err.Error()}}
	}
	s.refresh("saved")
	return nil
}

// AddExclusion saves an exclusion built from a finding: on one role of one
// rule (rule and role set), or on every rule (global set).
func (s *patternStore) AddExclusion(draft exclusionDraft) error {
	if err := draft.Validate(); err != nil {
		return err
	}
	if err := s.Writable(); err != nil {
		return err
	}

	if draft.AllRules {
		if err := config.AppendExclusion(s.path, draft.Global()); err != nil {
			return err
		}
		s.refresh("saved")
		return nil
	}

	state := s.State()
	patterns := append([]correlation.BehaviorPattern{}, state.Patterns...)
	for i := range patterns {
		if patterns[i].Name != draft.Rule {
			continue
		}

		updated := patterns[i]
		updated.Exclude = append(append([]correlation.RoleExclusion{}, updated.Exclude...), draft.ForRole())
		if err := updated.Validate(); err != nil {
			return err
		}
		patterns[i] = updated

		return s.SavePatterns(patterns)
	}

	return fmt.Errorf("the rule %q is not among the loaded patterns, so it cannot be given an exclusion; exclude for all rules instead", draft.Rule)
}

// watchDebounce is how long the file must be quiet before a change to it is
// acted on. Editors write a file in several steps.
const watchDebounce = 250 * time.Millisecond

// Watch applies changes made to the patterns file by anything other than
// Sentinel, until ctx is cancelled. It returns once the watch is in place.
//
// The directory is watched rather than the file: an editor that saves by
// writing a new file and renaming it over the old one replaces the file, and
// a watch on the old one would see nothing more.
func (s *patternStore) Watch(ctx context.Context, debounce time.Duration) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watch %s: %w", s.path, err)
	}

	dir := filepath.Dir(s.path)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch %s: %w", dir, err)
	}

	name := filepath.Base(s.path)

	go func() {
		defer watcher.Close()

		var quiet <-chan time.Time
		timer := time.NewTimer(time.Hour)
		timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) != name {
					continue
				}
				// Whatever happened to it, wait for it to settle.
				timer.Reset(debounce)
				quiet = timer.C

			case <-quiet:
				quiet = nil
				if s.refresh("file changed") {
					s.externalReloads.Add(1)
				}

			case _, ok := <-watcher.Errors:
				if !ok {
					return
				}
			}
		}
	}()

	return nil
}
