package finding

import "github.com/arafat2020/sentinel/internal/core"

type Sink interface {
	Handle(*core.Finding)
}
