package automation

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func TestObserveValidatesBeforeStorageOrNetwork(t *testing.T) {
	// A valid request needs real dependencies. Invalid caller input must be
	// rejected before touching either storage or transport, even before enter.
	e := NewEngine("host", nil, nil, nil)
	for _, uid := range []string{"", strings.Repeat("u", contract.MaxStringBytes+1), "uid\x00suffix", string([]byte{0xff})} {
		if _, err := e.Observe(context.Background(), uid, 0); Code(err) != CodeValidation {
			t.Fatalf("invalid UID returned %v", err)
		}
	}
	if _, err := e.Observe(context.Background(), "valid-uid", math.MaxUint64); Code(err) != CodeValidation {
		t.Fatalf("out-of-range minimum returned %v", err)
	}
}
