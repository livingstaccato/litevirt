package grpcapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// The failover reconciler's rebuild of a missing disk (RecreateOverlayDisk)
// writes <disks>/<vm>-<disk>.qcow2, a path a delete's kept overlay on this
// host may name as its missing base. It gets the kept-create check: such an
// overlay, or kept state that cannot be read, refuses it with a
// health.KeptRebuildRefusedError (the reconciler fails the start retryably
// and raises vm_disk_kept_base), and nothing is written. (Laptop re-review 2,
// finding 1.)
//
// Mutation: drop the check from RecreateOverlayDisk - the refusal subtests
// red (the overlay is built at the kept overlay's missing base).
func TestRecreateOverlayDisk_GetsTheKeptCreateCheck(t *testing.T) {
	wantRefused := func(t *testing.T, err error, base, named, cause string) {
		t.Helper()
		var kr *health.KeptRebuildRefusedError
		if !errors.As(err, &kr) || kr.Path != base || !strings.Contains(err.Error(), named) {
			t.Fatalf("RecreateOverlayDisk = %v; want a KeptRebuildRefusedError for %s naming %s", err, base, named)
		}
		if kr.Cause != cause {
			t.Fatalf("refusal cause = %q, want %q", kr.Cause, cause)
		}
		if exists(base) {
			t.Fatal("a refused rebuild wrote the disk")
		}
	}
	t.Run("a kept overlay names the disk as its missing base", func(t *testing.T) {
		s := pruneServer(t)
		noSeams(s)
		importVersion(t, s, "ubuntu", "A ")
		base := s.images.DiskPath("web", "root")
		top := registryKeep(t, s, "old", base)
		_, err := s.RecreateOverlayDisk("web", "root", "ubuntu", "1048576")
		wantRefused(t, err, base, top, health.KeptRebuildOverlay)
	})
	for _, how := range []string{"registry", "chain"} {
		t.Run("kept state unreadable: "+how, func(t *testing.T) {
			s := pruneServer(t)
			noSeams(s)
			importVersion(t, s, "ubuntu", "A ")
			named := keptUnknown(t, s, how)
			_, err := s.RecreateOverlayDisk("web", "root", "ubuntu", "1048576")
			wantRefused(t, err, s.images.DiskPath("web", "root"), named, health.KeptRebuildUnreadable)
		})
	}
	t.Run("a kept overlay naming another path does not hold it", func(t *testing.T) {
		s := pruneServer(t)
		noSeams(s)
		importVersion(t, s, "ubuntu", "A ")
		registryKeep(t, s, "old", s.images.DiskPath("other", "root"))
		disk, err := s.RecreateOverlayDisk("web", "root", "ubuntu", "1048576")
		if err != nil || !exists(disk) {
			t.Fatalf("RecreateOverlayDisk = %q, %v; want the disk rebuilt", disk, err)
		}
	})
}

// keptRefusalCause tells the three causes of a kept refusal apart, so
// vm_disk_kept_base advises the right fix. Mutation: return
// KeptRebuildOverlay for every error - red.
func TestKeptRefusalCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a kept overlay names the path", health.NewKeptBackingFileError("names it"), health.KeptRebuildOverlay},
		{"kept state cannot be read", keptChainsRefusal("lead", &keptRegistryError{msg: "bad json"}, "tail"), health.KeptRebuildUnreadable},
		{"the database did not answer", keptChainsRefusal("lead", &keptRegistryError{msg: "no answer", transient: true}, "tail"), health.KeptRebuildNoAnswer},
		{"storage did not answer", errors.New("stat: no answer within 5s"), health.KeptRebuildNoAnswer},
	} {
		if got := keptRefusalCause(tc.err); got != tc.want {
			t.Errorf("%s: cause %q, want %q", tc.name, got, tc.want)
		}
	}
}
