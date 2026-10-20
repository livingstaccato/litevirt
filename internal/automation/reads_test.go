package automation

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
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

func TestObserveNameValidatesBeforeDependencies(t *testing.T) {
	e := NewEngine("host", nil, nil, nil)
	for _, name := range []string{"", ".", "..", "../machine", "a/b", "bad name", strings.Repeat("n", contract.MaxStringBytes+1), "name\x00suffix", string([]byte{0xff})} {
		got, err := e.ObserveName(context.Background(), name, 0)
		if Code(err) != CodeValidation || got != (corrosion.AutomationNameObservation{}) {
			t.Fatalf("invalid name %q reached dependencies: %+v %v", name, got, err)
		}
	}
	if got, err := e.ObserveName(context.Background(), "machine", math.MaxUint64); Code(err) != CodeValidation || got != (corrosion.AutomationNameObservation{}) {
		t.Fatalf("invalid minimum reached dependencies: %+v %v", got, err)
	}
}

func TestObserveNamePreservesEnterCancellationBoundary(t *testing.T) {
	e := NewEngine("host", nil, nil, nil)
	e.lock <- struct{}{}
	defer func() { <-e.lock }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := e.ObserveName(ctx, "machine", 0)
	// The existing enter owner intentionally masks context cancellation.
	if Code(err) != CodeUnavailable || got != (corrosion.AutomationNameObservation{}) {
		t.Fatalf("enter boundary changed: %+v %v", got, err)
	}
}
