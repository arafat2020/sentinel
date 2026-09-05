package finding

import "testing"

func TestConsoleSinkImplementsSink(t *testing.T) {
	var _ Sink = (*ConsoleSink)(nil)
}
