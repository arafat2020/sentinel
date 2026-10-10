package core

// Evidence is what a finding is based on.
type Evidence struct {
	// Process is the process the finding is chiefly about.
	Process *Process
	// Processes are the processes involved, in the order the rule lists
	// them.
	Processes []Process
	// Roles maps each role of the rule that produced the finding to the
	// process that filled it.
	Roles map[string]Process
	// Events are the events that made the rule match: the events of its
	// sequence in order, then an example of each required event, then the
	// most recent events counted towards each threshold. The list is
	// capped, so it is a sample rather than a complete record.
	Events []Event
}
