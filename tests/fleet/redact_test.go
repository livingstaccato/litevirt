package fleet

import (
	"crypto/sha256"
	"fmt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// redacted names a secret by its length and a short digest, so a failure can
// say which value it saw without the value reaching the log.
func redacted(s string) string {
	if s == "" {
		return "<empty>"
	}
	return fmt.Sprintf("<%d chars, sha256:%.8x>", len(s), sha256.Sum256([]byte(s)))
}

// credState describes a token-carrying response without printing the token.
func credState(r interface{ GetToken() string }) string {
	if r.GetToken() == "" {
		return "token empty"
	}
	return "token present " + redacted(r.GetToken())
}

// ipmiPassOf is a host row's BMC password, or "" for no row.
func ipmiPassOf(h *corrosion.HostRecord) string {
	if h == nil {
		return ""
	}
	return h.IPMIPass
}
