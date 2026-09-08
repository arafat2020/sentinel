package monitor

import (
	"context"
	"fmt"

	filecollector "github.com/arafat2020/sentinel/internal/collector/file"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type FileMonitor struct {
	collector filecollector.Collector
	bus       *eventbus.Bus
}

func NewFileMonitor(
	collector filecollector.Collector,
	bus *eventbus.Bus,
) *FileMonitor {
	return &FileMonitor{
		collector: collector,
		bus:       bus,
	}
}

func (m *FileMonitor) Run(ctx context.Context) error {
	return m.collector.Run(
		ctx,
		func(fileEvent core.FileEvent) {
			eventType, err := fileEventType(fileEvent.Operation)
			if err != nil {
				return
			}

			event := core.Event{
				ID:        "",
				Timestamp: fileEvent.Timestamp,
				Type:      eventType,
				Process:   fileEvent.Process,
				File:      &fileEvent,
			}

			m.bus.Publish(event)
		},
	)
}

func (m *FileMonitor) Close() {
	m.collector.Close()
}

func fileEventType(operation core.FileOperation) (core.EventType, error) {
	switch operation {
	case core.FileCreate:
		return core.EventFileCreate, nil

	case core.FileModify:
		return core.EventFileModify, nil

	case core.FileDelete:
		return core.EventFileDelete, nil

	case core.FileRename:
		return core.EventFileRename, nil

	default:
		return "", fmt.Errorf("unsupported file operation: %s", operation)
	}
}
