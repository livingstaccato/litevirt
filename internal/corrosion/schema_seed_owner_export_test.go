package corrosion

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The external test package owns health's real minter; this registration only
// connects the explicit private pair without a corrosion/health import cycle.
type PrivateSchemaSeedOwner struct {
	MarkerPath    func(string) string
	Latched       func(string) bool
	CallbackCount func(capabilities.Feature) int
}
type PrivateSchemaSeedPing func(context.Context, string) ([]string, time.Time, error)
type PrivateSchemaSeedConfirm func(context.Context, string, string, string) (bool, error)

var privateSchemaSeedOwnerFactory func(*testing.T, *Client, string, *ClaimVerifier, PrivateSchemaSeedPing, PrivateSchemaSeedConfirm) PrivateSchemaSeedOwner

func RegisterPrivateSchemaSeedOwner(fn func(*testing.T, *Client, string, *ClaimVerifier, PrivateSchemaSeedPing, PrivateSchemaSeedConfirm) PrivateSchemaSeedOwner) {
	if fn == nil || privateSchemaSeedOwnerFactory != nil {
		panic("private schema seed owner registration must occur once")
	}
	privateSchemaSeedOwnerFactory = fn
}
