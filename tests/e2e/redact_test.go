package e2e

import (
	"crypto/sha256"
	"fmt"
)

// redacted names a secret by its length and a short digest, so a failure can
// say which value it saw without the value reaching the log.
func redacted(s string) string {
	if s == "" {
		return "<empty>"
	}
	return fmt.Sprintf("<%d chars, sha256:%.8x>", len(s), sha256.Sum256([]byte(s)))
}
