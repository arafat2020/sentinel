package process

import (
	"context"
	"fmt"

	gopsprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/arafat2020/sentinel/internal/core"
)

type Resolver struct{}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) Resolve(
	ctx context.Context,
	pid int32,
) (*core.Process, error) {
	p, err := gopsprocess.NewProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("find process %d: %w", pid, err)
	}

	process := buildProcess(p, ctx)

	return &process, nil
}
