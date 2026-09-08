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
	Timestamp time.Time

	PID  int32
	PPID int32

	Path    string
	OldPath string

	Operation FileOperation

	Process *Process
}
