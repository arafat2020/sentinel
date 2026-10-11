package core

import "time"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is one detection. Its JSON form is what is stored and what the
// interfaces copy to the clipboard, so the keys are fixed by the tags.
type Finding struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    Severity  `json:"severity"`
	Rule        string    `json:"rule"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Evidence    Evidence  `json:"evidence"`
}

// FindingStatus is what an analyst has done about a finding.
type FindingStatus string

const (
	// StatusNew is a finding nobody has dealt with.
	StatusNew FindingStatus = "new"
	// StatusAcknowledged is a finding someone has seen and is handling.
	StatusAcknowledged FindingStatus = "acknowledged"
	// StatusDismissed is a finding judged not to matter.
	StatusDismissed FindingStatus = "dismissed"
)

// ValidStatus reports whether s is one of the three statuses.
func ValidStatus(s FindingStatus) bool {
	return s == StatusNew || s == StatusAcknowledged || s == StatusDismissed
}
