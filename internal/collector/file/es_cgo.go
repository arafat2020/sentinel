//go:build darwin && cgo && es

package file

/*
#cgo CFLAGS: -I${SRCDIR} -DSENTINEL_ES_ENABLED
#cgo LDFLAGS: -lEndpointSecurity -lbsm -framework Security -framework CoreFoundation

#include "es_bridge_darwin.h"
*/
import "C"

import "fmt"

type esClient struct {
	client *C.sentinel_es_client
}

func newESClient() (*esClient, error) {
	var client *C.sentinel_es_client

	result := C.sentinel_es_client_create(&client)
	if result != 0 {
		return nil, fmt.Errorf(
			"create Endpoint Security client: %d",
			int(result),
		)
	}

	return &esClient{
		client: client,
	}, nil
}

func (c *esClient) subscribe() error {
	if c == nil || c.client == nil {
		return fmt.Errorf("Endpoint Security client is nil")
	}

	result := C.sentinel_es_client_subscribe(c.client)
	if result != 0 {
		return fmt.Errorf(
			"subscribe Endpoint Security events: %d",
			int(result),
		)
	}

	return nil
}

func (c *esClient) close() {
	if c == nil || c.client == nil {
		return
	}

	C.sentinel_es_client_delete(c.client)
	c.client = nil
}
