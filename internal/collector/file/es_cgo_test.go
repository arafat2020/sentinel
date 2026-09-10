//go:build darwin && cgo && integration

package file

import "testing"

func TestESClientCanBeCreated(t *testing.T) {
	client, err := newESClient()
	if err != nil {
		t.Fatalf("newESClient() error = %v", err)
	}

	if client == nil {
		t.Fatal("newESClient() returned nil client")
	}

	if client.client == nil {
		t.Fatal("newESClient() returned client with nil native client")
	}

	client.close()
}
