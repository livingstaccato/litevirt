package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/randid"
)

// What a create of a name does with what a deleted VM of that name was kept
// with (`lv rm --keep-disks`), when the create fails.
//
// The create moves a kept disk at the path its new disk takes to
// <path>.kept-<time> (clearDiskDebrisBeforeCreate), and the kept VM's
// cloud-init seed to <seed>.kept-<time> (setAsideKeptSeed), only once the
// refusals it can judge up front have passed (firmwarePreflight). A create
// that then fails puts both back where the kept VM recorded them
// (restoreKeptAfterFailedCreate). A create that succeeds leaves them at their
// .kept- names, which nothing removes but an operator.

// seedCompanions are the files beside a seed that go where it goes: its
// stamp and its stale mark.
var seedCompanions = []func(string) string{cloudinit.SeedOwnerPath, cloudinit.SeedStalePath}

// keptSeed is a seed a create moved off its path: from path, to to.
type keptSeed struct{ path, to string }

// setAsideKeptSeed clears name's seed path for a create: a seed of the
// deleted VM the name was kept with (seedOfAKeptVM) is moved to
// <seed>.kept-<time> with its stamp and stale mark, and any other seed there
// is removed, as before. keptDisks says the create moved a disk a delete kept.
// A kept seed that cannot be moved refuses the create: removing it is what
// this exists to prevent.
func (s *Server) setAsideKeptSeed(ctx context.Context, name string, keptDisks bool, now time.Time) (keptSeed, error) {
	iso := lv.CloudInitISOPath(s.dataDir, name)
	if _, err := os.Lstat(iso); errors.Is(err, fs.ErrNotExist) {
		return keptSeed{}, nil
	}
	if !s.seedOfAKeptVM(ctx, name, iso, keptDisks) {
		_ = cloudinit.RemoveSeed(iso)
		return keptSeed{}, nil
	}
	to := health.KeptName(iso, now)
	if err := os.Rename(iso, to); err != nil {
		return keptSeed{}, fmt.Errorf("the cloud-init seed of the deleted VM %s the create would replace is kept, and moving it to %s failed (%v); "+
			"retry, or place the VM on another host", name, to, err)
	}
	for _, c := range seedCompanions {
		if err := os.Rename(c(iso), c(to)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("create: could not move a file beside a kept seed with it", "vm", name, "path", c(iso), "error", err)
		}
	}
	slog.Info("create: moved the cloud-init seed of a deleted VM of this name that the operator kept off the path the create writes; nothing removes it",
		"vm", name, "path", iso, "moved_to", to)
	s.keptEvent(ctx, name, fmt.Sprintf("the cloud-init seed of the deleted VM %s, which the operator kept, was at %s, which the create of %s on %s writes; it is moved to %s, and only an operator removes it",
		name, iso, name, s.hostName, to))
	return keptSeed{path: iso, to: to}, nil
}

// seedOfAKeptVM reports whether the seed at iso is the one a deleted VM of
// name was kept with: it is stamped for the name's deleted incarnation, or
// for the VM whose firmware state a --keep-disks delete retained. An
// unstamped seed (written before stamps) counts when this host holds what a
// delete kept of the name. What cannot be read counts: a seed moved aside is
// kept, a seed removed is lost.
func (s *Server) seedOfAKeptVM(ctx context.Context, name, iso string, keptDisks bool) bool {
	stamp, stamped, err := cloudinit.SeedOwner(iso)
	if err != nil {
		return true
	}
	_, spec, err := corrosion.GetTombstonedVM(ctx, s.db, name)
	if err != nil {
		return true
	}
	var owners []string
	if u := cloudinit.SpecUUID(spec); u != "" {
		owners = append(owners, u)
	}
	marker, markerOK := lv.ReadRetainedFirmwareMarker(s.dataDir, name)
	if markerOK && marker != "" {
		owners = append(owners, marker)
	}
	if stamped {
		return slices.Contains(owners, stamp)
	}
	return keptDisks || markerOK
}

// restoreKeptAfterFailedCreate puts back what a failed create of name moved
// aside: each kept disk (health.RestoreKeptAfterFailedCreate) and the kept
// seed, each only onto a free path. note records each outcome for the
// create's cleanup report.
func (s *Server) restoreKeptAfterFailedCreate(ctx context.Context, name string, moved []health.MovedBeforeCreate, seed keptSeed, note func(string)) {
	for _, b := range health.RestoreKeptAfterFailedCreate(s.dataDir, name, moved) {
		if b.Err != nil {
			note(fmt.Sprintf("kept disk left at %s (%v)", b.From, b.Err))
			s.keptEvent(ctx, name, fmt.Sprintf("the create of %s on %s failed, and the disk the deleted VM %s was kept with stays at %s: %v",
				name, s.hostName, name, b.From, b.Err))
			continue
		}
		note("kept disk moved back to " + b.Path)
		s.keptEvent(ctx, name, fmt.Sprintf("the create of %s on %s failed; the disk the deleted VM %s was kept with is back at %s",
			name, s.hostName, name, b.Path))
	}
	if seed.to == "" {
		return
	}
	if err := restoreSeed(seed); err != nil {
		slog.Warn("create failed: the kept cloud-init seed of a deleted VM of this name stays where the create moved it",
			"vm", name, "path", seed.path, "kept_at", seed.to, "error", err)
		note(fmt.Sprintf("kept seed left at %s (%v)", seed.to, err))
		return
	}
	note("kept seed moved back to " + seed.path)
}

// restoreSeed links a kept seed back to its path, which it never replaces,
// then moves its stamp and stale mark back beside it.
func restoreSeed(k keptSeed) error {
	if err := os.Link(k.to, k.path); err != nil {
		return err
	}
	if err := os.Remove(k.to); err != nil {
		slog.Warn("create failed: a kept seed is back at its path, and its .kept- name could not be removed", "path", k.path, "kept_at", k.to, "error", err)
	}
	for _, c := range seedCompanions {
		if _, err := os.Lstat(c(k.path)); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.Rename(c(k.to), c(k.path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("create failed: could not move a file beside a kept seed back", "path", c(k.to), "error", err)
		}
	}
	return nil
}

// keptEvent records a vm.disk.kept event of name.
func (s *Server) keptEvent(ctx context.Context, name, detail string) {
	if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: name, HostName: s.hostName, Type: "vm.disk.kept",
		Result: "ok", Severity: "info", Detail: detail, Username: "create",
	}); err != nil {
		slog.Warn("create: record the event", "vm", name, "type", "vm.disk.kept", "error", err)
	}
}
