package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Both marker writes failing together is one correlated fault — a full or
// read-only volume takes out the domain metadata write and the file write at
// once — not two coincidences and not a configuration.
//
// The refusal is correct and stays: a running row that proves nothing is exactly
// what mark-then-commit exists to prevent, and TestPublishVMRunning_NoMarkerAtAll
// DoesNotCommit pins that. But refusing holds the row at its previous state while
// the guest runs, the caller retries, and the dual-run detector suppresses the
// result — so the cause has to reach an operator, or they see a VM that never
// finishes starting and no reason anywhere.
func TestPublishVMRunning_ACorrelatedFaultIsRefusedWithItsCause(t *testing.T) {
	base := t.TempDir()
	notADir := filepath.Join(base, "blocked")
	if err := os.WriteFile(notADir, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New() // no domain, so the metadata write fails too

	committed := false
	err := PublishVMRunning(context.Background(), fake, notADir, "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil })

	if committed || err == nil {
		t.Fatal("a running row with no marker at all was published; that is the unprovable " +
			"state mark-then-commit refuses")
	}
	// The cause has to be IN the error, not only in a log line the caller drops.
	if !strings.Contains(err.Error(), "owner-epoch") {
		t.Errorf("error = %q; it must name what could not be written", err)
	}
}

// The genuine impossibility is a different refusal with a different cause: no
// usable backend and no data directory is a configuration in which marking can
// never work, so no amount of waiting fixes it.
func TestPublishVMRunning_ImpossibleSaysSoDistinctly(t *testing.T) {
	err := PublishVMRunning(context.Background(), nil, "", "vm1", "running", 5,
		func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("marking was impossible and the publish was allowed")
	}
	if !strings.Contains(err.Error(), "no usable libvirt backend and no data directory") {
		t.Errorf("error = %q; a configuration that can never mark must not read like a "+
			"transient write failure — the operator actions are different", err)
	}
}
