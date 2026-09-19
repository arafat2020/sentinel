package auth

import (
	"testing"
)

func TestHash_RejectsEmpty(t *testing.T) {
	_, err := Hash("")
	if err == nil {
		t.Fatal("expected error for empty password, got nil")
	}
}

func TestHash_ProducesVerifiableHash(t *testing.T) {
	hash, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if err := Verify(hash, "correct-horse-battery-staple"); err != nil {
		t.Fatalf("Verify with correct password: %v", err)
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	hash, _ := Hash("secret")
	err := Verify(hash, "wrong")
	if err == nil {
		t.Fatal("expected ErrWrongPassword, got nil")
	}
	if err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestHash_DifferentHashesSameInput(t *testing.T) {
	// bcrypt generates a unique salt each call; two hashes of the same password
	// must be different strings but both must verify correctly.
	h1, _ := Hash("same")
	h2, _ := Hash("same")
	if h1 == h2 {
		t.Fatal("expected different hashes for same password due to random salt")
	}
	if err := Verify(h1, "same"); err != nil {
		t.Fatalf("Verify h1: %v", err)
	}
	if err := Verify(h2, "same"); err != nil {
		t.Fatalf("Verify h2: %v", err)
	}
}
