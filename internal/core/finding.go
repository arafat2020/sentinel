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

type Finding struct {
	ID          string
	Timestamp   time.Time
	Severity    Severity
	Rule        string
	Title       string
	Description string
	Evidence    Evidence
}
