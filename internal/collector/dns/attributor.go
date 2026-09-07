package dns

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

type Attributor interface {
	Attribute(
		ctx context.Context,
		query *core.DNSQuery,
		sourceIP string,
		sourcePort uint32,
	) error
}
