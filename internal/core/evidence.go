package core

// Evidence is what a finding is based on.
//
// Its JSON form is stored with each finding, so the key names are part of the
// storage format: they are fixed by the tags here and on the types it
// contains, and do not follow the Go field names. See json.go for how rows
// written before the tags existed are still read.
type Evidence struct {
	// Process is the process the finding is chiefly about.
	Process *Process `json:"process,omitempty"`
	// Processes are the processes involved, in the order the rule lists
	// them.
	Processes []Process `json:"processes,omitempty"`
	// Roles maps each role of the rule that produced the finding to the
	// process that filled it.
	Roles map[string]Process `json:"roles,omitempty"`
	// PreviousImages lists, for each role whose process has replaced its
	// program image with exec, the images it ran before the one shown in
	// Roles, oldest first. Only the most recent few are kept.
	PreviousImages map[string][]ProcessImage `json:"previous_images,omitempty"`
	// Events are the events that made the rule match: the events of its
	// sequence in order, then an example of each required event, then the
	// most recent events counted towards each threshold. The list is
	// capped, so it is a sample rather than a complete record.
	Events []Event `json:"events,omitempty"`
	// Captures are the events the rule's sequence named so that later steps
	// could refer to them, in step order. They are recorded when the
	// finding is made, so the finding still says what was captured after
	// the rule has been edited or removed.
	Captures []Capture `json:"captures,omitempty"`
}

// Capture is an event a sequence step named with "capture".
type Capture struct {
	Name  string `json:"name"`
	Event Event  `json:"event"`
}
