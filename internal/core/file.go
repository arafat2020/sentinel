package core

import "time"

type FileOperation string

const (
	FileCreate FileOperation = "CREATE"
	FileModify FileOperation = "MODIFY"
	FileDelete FileOperation = "DELETE"
	FileRename FileOperation = "RENAME"
)

type FileEvent struct {
	Timestamp time.Time `json:"timestamp,omitzero"`

	PID  int32 `json:"pid"`
	PPID int32 `json:"ppid"`

	Path    string `json:"path,omitempty"`
	OldPath string `json:"old_path,omitempty"`

	Operation FileOperation `json:"operation,omitempty"`

	Process *Process `json:"process,omitempty"`
}
