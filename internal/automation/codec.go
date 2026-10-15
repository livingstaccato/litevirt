package automation

import "github.com/litevirt/litevirt/internal/automation/contract"

// CanonicalCommand returns the private retry identity, excluding session and ciphertext.
func CanonicalCommand(c Command) ([]byte, error) { return contract.CanonicalCommand(c) }
