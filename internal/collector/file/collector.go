package file

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

type Collector interface {
	Run(
		ctx context.Context,
		handler func(core.FileEvent),
	) error

	Close()
}
