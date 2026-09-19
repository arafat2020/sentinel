package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

var ErrWrongPassword = errors.New("wrong password")

// Hash returns a bcrypt hash of the plaintext password.
func Hash(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// Verify checks plaintext against a stored bcrypt hash.
// Returns ErrWrongPassword when the password does not match.
func Verify(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrWrongPassword
	}
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	return nil
}
