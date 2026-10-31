package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// ID represents a unique identifier.
type ID string

// NewID generates a new unique identifier.
func NewID() ID {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return ID(time.Now().UTC().Format("20060102T150405.000000000") + "-" + hex.EncodeToString(buf))
}

// ExecutionRequest represents a request to execute a command.
type ExecutionRequest struct {
	Command       []string
	Dir           string
	Environ       []string
	Timeout       time.Duration
	MaxOutput     int
	WorkspacePath string
	InstanceID    string
}

// PolicyValidationError represents a policy validation error.
type PolicyValidationError struct {
	Message string
}

func (e *PolicyValidationError) Error() string {
	return e.Message
}

// DigestError represents a digest mismatch error.
type DigestError struct {
	Expected string
	Got      string
}

func (e *DigestError) Error() string {
	return fmt.Sprintf("digest mismatch: expected %s, got %s", e.Expected, e.Got)
}
