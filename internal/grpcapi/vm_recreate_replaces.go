package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A rebuild (RebuildVM) and a rolling recreate (serverOps.recreateAs)
// tombstone a VM and then create it again under the same name. The create
// may run on a host whose replica has not yet applied that tombstone: the
// host placement or a pin chose, which the create is forwarded to
// milliseconds later, or the node running a rollout whose delete ran on the
// VM's own host. That host's create still sees the old row, and refusing it
// AlreadyExists after the teardown loses the VM (lab, 2026-10-08; main had
// the same loss).
//
// So the create carries the VM it replaces as its delete saw it — its name,
// incarnation (created_at, which every mutation of a row keeps and every
// re-create renews), and the host, owner epoch, spec generation and identity
// its delete guard bound (corrosion.VMDeleteSnapshot) — in-process as a
// context value, and across the forward in metadata honoured only from a
// peer host. A host whose live row that snapshot covers (the same
// incarnation, not ahead of the delete on any authority axis) knows the
// deleter's tombstone kills it. It first waits, bounded, for its replica to
// apply the tombstone, which brings everything the deleting host wrote before
// it (the released addresses among them); if the tombstone does not arrive in
// time, it retires its copy itself (retireReplacedRow) rather than lose the
// VM. Anything else is still refused AlreadyExists, as on main: a live row of
// another incarnation, a row that has moved past the deleter's view (a
// failover the deleter had not heard of — its tombstone would not kill that
// row either), and any row while this host has a domain of the name (in the
// case this exists for, the VM did not run here).

// defaultReplacedTombstoneWait is how long a re-create waits for this host's
// replica to apply the tombstone of the VM it replaces. Replication normally
// takes milliseconds; the bound only matters when it is cut off.
const defaultReplacedTombstoneWait = 10 * time.Second

// replacedVMPoll is how often the wait re-reads the row.
const replacedVMPoll = 50 * time.Millisecond

// replacedVMKey carries a replacedVM in a context. This process sets it after
// it has deleted the VM (withReplacedVM), or from what a peer host handed
// over (acceptReplacedVMMD); a caller cannot.
type replacedVMKey struct{}

// replacedVM is the VM a create re-creates, as its delete saw it.
type replacedVM struct {
	name string
	snap corrosion.VMDeleteSnapshot
}

// withReplacedVM returns ctx carrying vm's identity into the create that
// re-creates it. Call it only once vm's delete has been committed.
func withReplacedVM(ctx context.Context, vm *corrosion.VMRecord) context.Context {
	if vm == nil || vm.Name == "" || vm.CreatedAt == "" {
		return ctx
	}
	return context.WithValue(ctx, replacedVMKey{}, replacedVM{name: vm.Name, snap: corrosion.SnapshotForDelete(*vm)})
}

// replacedVMFor returns the replaced VM ctx carries when it is named name.
func replacedVMFor(ctx context.Context, name string) (replacedVM, bool) {
	r, ok := ctx.Value(replacedVMKey{}).(replacedVM)
	if !ok || name == "" || r.name != name || r.snap.CreatedAt == "" {
		return replacedVM{}, false
	}
	return r, true
}

// replacedVMMD is the metadata key that hands a replacedVM to the host a
// re-create is forwarded to. That host honours it only from a peer host
// (acceptReplacedVMMD), which hands one over only for a VM it has deleted.
const replacedVMMD = "x-litevirt-recreate-replaces"

type replacedVMWire struct {
	Name           string `json:"name"`
	CreatedAt      string `json:"created_at"`
	HostName       string `json:"host_name"`
	OwnerEpoch     int64  `json:"owner_epoch"`
	SpecGeneration int64  `json:"spec_generation"`
	IdentityHash   string `json:"identity_hash"`
}

// withReplacedVMMD returns ctx with the replaced VM ctx holds for name added
// to its outgoing metadata, or ctx unchanged when it holds none.
func withReplacedVMMD(ctx context.Context, name string) context.Context {
	r, ok := replacedVMFor(ctx, name)
	if !ok {
		return ctx
	}
	b, err := json.Marshal(replacedVMWire{
		Name: r.name, CreatedAt: r.snap.CreatedAt, HostName: r.snap.HostName,
		OwnerEpoch: r.snap.OwnerEpoch, SpecGeneration: r.snap.SpecGeneration, IdentityHash: r.snap.IdentityHash,
	})
	if err != nil {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, replacedVMMD, string(b))
}

// acceptReplacedVMMD returns ctx holding the replaced VM a peer host handed
// over in its metadata, or ctx unchanged: none, several, a malformed one, or
// a caller that is not a peer host.
func (s *Server) acceptReplacedVMMD(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	vals := md.Get(replacedVMMD)
	if len(vals) != 1 || s.requirePeerCert(ctx) != nil {
		return ctx
	}
	var w replacedVMWire
	// A sender on the round-0 build sends no guard snapshot; without one
	// nothing can show the row is not ahead of its delete, so it names nothing.
	if err := json.Unmarshal([]byte(vals[0]), &w); err != nil || w.Name == "" || w.CreatedAt == "" ||
		w.HostName == "" || w.IdentityHash == "" {
		return ctx
	}
	return context.WithValue(ctx, replacedVMKey{}, replacedVM{name: w.Name, snap: corrosion.VMDeleteSnapshot{
		CreatedAt: w.CreatedAt, HostName: w.HostName, OwnerEpoch: w.OwnerEpoch,
		SpecGeneration: w.SpecGeneration, IdentityHash: w.IdentityHash,
	}})
}

func (s *Server) replacedTombstoneWaitBound() time.Duration {
	if s.replacedTombstoneWait > 0 {
		return s.replacedTombstoneWait
	}
	return defaultReplacedTombstoneWait
}

// settleReplacedVM decides a create's existence check when this host's
// replica holds a live row (existing) for the name being created. It reports
// true when that row is one the replaced VM's delete kills and it is now gone
// from this replica — the tombstone arrived, or this host retired the row
// itself after waiting — and false when it is anything else, which the create
// refuses AlreadyExists as before.
func (s *Server) settleReplacedVM(ctx context.Context, existing *corrosion.VMRecord) (bool, error) {
	r, ok := replacedVMFor(ctx, existing.Name)
	if !ok || !r.snap.Covers(*existing) {
		return false, nil
	}
	if s.hasLocalDomain(existing.Name) {
		slog.Warn("re-create: this host has a domain of the VM another host deleted; refusing, leaving it as it is",
			"vm", existing.Name, "deleter_saw_host", r.snap.HostName)
		return false, nil
	}
	deadline := time.Now().Add(s.replacedTombstoneWaitBound())
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(replacedVMPoll):
		}
		cur, err := corrosion.GetVM(ctx, s.db, existing.Name)
		if err != nil {
			continue
		}
		if cur == nil {
			return !s.hasLocalDomain(existing.Name), nil
		}
		if !r.snap.Covers(*cur) {
			return false, nil
		}
	}
	slog.Warn("re-create: this host's replica has not applied the tombstone of the VM it replaces; retiring its copy here",
		"vm", existing.Name, "incarnation", r.snap.CreatedAt, "waited", s.replacedTombstoneWaitBound())
	return s.retireReplacedRow(ctx, existing.Name, r.snap)
}

// hasLocalDomain reports whether this host has a libvirt domain of name,
// running or only defined.
func (s *Server) hasLocalDomain(name string) bool {
	return s.virt != nil && s.virt.DomainExists(name)
}

// retireReplacedRow tombstones this host's stale copy of the VM snap
// describes, as DeleteVM's stale-record path removes a row whose domain is
// gone: its addresses go back first, then the row, then the device lease and
// the name's owner-epoch marker on this host.
func (s *Server) retireReplacedRow(ctx context.Context, name string, snap corrosion.VMDeleteSnapshot) (bool, error) {
	cur, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil {
		return false, err
	}
	if cur == nil {
		return !s.hasLocalDomain(name), nil
	}
	if !snap.Covers(*cur) || s.hasLocalDomain(name) {
		return false, nil
	}
	s.releaseNICLeasesBestEffort(ctx, cur, "recreate-retire")
	err = corrosion.DeleteVMIncarnation(ctx, s.db, name, snap)
	if errors.Is(err, corrosion.ErrVMIncarnationMismatch) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.clearDeviceLease(name)
	if err := health.RemoveVMOwnerEpochMarker(s.dataDir, name); err != nil {
		slog.Warn("re-create: owner-epoch marker not removed with the retired copy", "vm", name, "error", err)
	}
	return true, nil
}

// recreateFailedAfterTeardown is the error a rebuild or recreate returns when
// its create fails after the VM was torn down: it says what is gone, where
// the spec to re-create it from was kept, and the create's own error.
func (s *Server) recreateFailedAfterTeardown(op, name, where string, spec *pb.VMSpec, cause error) error {
	kept := s.keepRecreateSpec(op, name, spec)
	slog.Error(op+": the VM was torn down and its re-create failed",
		"vm", name, "torn_down_on", where, "spec_kept_at", kept, "error", cause)
	st := status.Convert(cause)
	return status.Errorf(st.Code(), "%s %q: the VM was torn down on %s (its domain, disks and record are gone) and "+
		"re-creating it failed: %s. %s", op, name, where, st.Message(), kept)
}

// recreateKeepMax and recreateKeepMaxAge bound <data_dir>/recreate-failed/:
// the newest recreateKeepMax kept specs are kept, and none older than
// recreateKeepMaxAge.
const (
	recreateKeepMax    = 50
	recreateKeepMaxAge = 30 * 24 * time.Hour
)

// keepRecreateSpec writes spec, the one a failed re-create was given, to a
// file of its own only root can read on this host, prunes the directory to
// its bound, and returns a sentence naming the file.
func (s *Server) keepRecreateSpec(op, name string, spec *pb.VMSpec) string {
	if s.dataDir == "" || spec == nil {
		return "Its spec was not kept; re-create it from your own copy."
	}
	dir := filepath.Join(s.dataDir, "recreate-failed")
	b, err := protojson.MarshalOptions{Multiline: true}.Marshal(spec)
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	var path string
	if err == nil {
		// CreateTemp: a unique name (two failures in one second never
		// overwrite each other), created 0600.
		var f *os.File
		f, err = os.CreateTemp(dir, fmt.Sprintf("%s-%s-%s-*.json", name, op, time.Now().UTC().Format("20060102T150405Z")))
		if err == nil {
			path = f.Name()
			_, err = f.Write(b)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
	}
	if err != nil {
		slog.Error(op+": could not keep the spec of a VM whose re-create failed", "vm", name, "error", err)
		return "Its spec could not be kept (" + err.Error() + "); re-create it from your own copy."
	}
	pruneRecreateKept(dir, path)
	return fmt.Sprintf("Its spec is kept on %s at %s; re-create the VM from it.", s.hostName, path)
}

// pruneRecreateKept removes from dir every kept spec older than
// recreateKeepMaxAge and all but the newest recreateKeepMax, never keep.
func pruneRecreateKept(dir, keep string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type kept struct {
		path string
		mod  time.Time
	}
	var files []kept
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if p != keep && time.Since(info.ModTime()) > recreateKeepMaxAge {
			_ = os.Remove(p)
			continue
		}
		files = append(files, kept{p, info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].path == keep || files[j].path == keep {
			return files[i].path == keep
		}
		if !files[i].mod.Equal(files[j].mod) {
			return files[i].mod.After(files[j].mod)
		}
		return files[i].path > files[j].path
	})
	for _, f := range files[min(len(files), recreateKeepMax):] {
		_ = os.Remove(f.path)
	}
}
