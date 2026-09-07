package dns

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

type Collector interface {
	Run(
		ctx context.Context,
		handler func(core.DNSQuery),
	) error

	Close()
}
