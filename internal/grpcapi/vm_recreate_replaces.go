package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
// So the create carries the identity of the VM it replaces — its name and
// incarnation (created_at, which every mutation of a row keeps and every
// re-create renews) — in-process as a context value, and across the forward
// in metadata honoured only from a peer host. A host whose live row for that
// name is exactly that incarnation knows the row is already dead: a delete is
// terminal for its incarnation (corrosion.incarnationTombstoneDecision). It
// first waits, bounded, for its replica to apply the tombstone, which brings
// everything the deleting host wrote before it (the released addresses among
// them); if the tombstone does not arrive in time, it retires its copy itself
// (corrosion.DeleteVMIncarnation) rather than lose the VM. A live row of any
// other incarnation is still refused AlreadyExists.

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

// replacedVM is the VM a create re-creates: its name and incarnation.
type replacedVM struct {
	name, createdAt string
}

// withReplacedVM returns ctx carrying vm's identity into the create that
// re-creates it. Call it only once vm's delete has been committed.
func withReplacedVM(ctx context.Context, vm *corrosion.VMRecord) context.Context {
	if vm == nil || vm.Name == "" || vm.CreatedAt == "" {
		return ctx
	}
	return context.WithValue(ctx, replacedVMKey{}, replacedVM{name: vm.Name, createdAt: vm.CreatedAt})
}

// replacedVMFor returns the replaced VM ctx carries when it is named name.
func replacedVMFor(ctx context.Context, name string) (replacedVM, bool) {
	r, ok := ctx.Value(replacedVMKey{}).(replacedVM)
	if !ok || name == "" || r.name != name || r.createdAt == "" {
		return replacedVM{}, false
	}
	return r, true
}

// replacedVMMD is the metadata key that hands a replacedVM to the host a
// re-create is forwarded to. That host honours it only from a peer host
// (acceptReplacedVMMD), which hands one over only for a VM it has deleted.
const replacedVMMD = "x-litevirt-recreate-replaces"

type replacedVMWire struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// withReplacedVMMD returns ctx with the replaced VM ctx holds for name added
// to its outgoing metadata, or ctx unchanged when it holds none.
func withReplacedVMMD(ctx context.Context, name string) context.Context {
	r, ok := replacedVMFor(ctx, name)
	if !ok {
		return ctx
	}
	b, err := json.Marshal(replacedVMWire{Name: r.name, CreatedAt: r.createdAt})
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
	if err := json.Unmarshal([]byte(vals[0]), &w); err != nil || w.Name == "" || w.CreatedAt == "" {
		return ctx
	}
	return context.WithValue(ctx, replacedVMKey{}, replacedVM{name: w.Name, createdAt: w.CreatedAt})
}

func (s *Server) replacedTombstoneWaitBound() time.Duration {
	if s.replacedTombstoneWait > 0 {
		return s.replacedTombstoneWait
	}
	return defaultReplacedTombstoneWait
}

// settleReplacedVM decides a create's existence check when this host's
// replica holds a live row (existing) for the name being created. It reports
// true when that row is the incarnation the create replaces and is now gone
// from this replica — the tombstone arrived, or this host retired the row
// itself after waiting — and false when the row is anything else, which the
// create refuses AlreadyExists as before.
func (s *Server) settleReplacedVM(ctx context.Context, existing *corrosion.VMRecord) (bool, error) {
	r, ok := replacedVMFor(ctx, existing.Name)
	if !ok || existing.CreatedAt != r.createdAt {
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
			return true, nil
		}
		if cur.CreatedAt != r.createdAt {
			return false, nil
		}
	}
	slog.Warn("re-create: this host's replica has not applied the tombstone of the VM it replaces; retiring its copy here",
		"vm", existing.Name, "incarnation", r.createdAt, "waited", s.replacedTombstoneWaitBound())
	err := corrosion.DeleteVMIncarnation(ctx, s.db, existing.Name, r.createdAt)
	if errors.Is(err, corrosion.ErrVMIncarnationMismatch) {
		return false, nil
	}
	if err != nil {
		return false, err
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

// keepRecreateSpec writes spec, the one a failed re-create was given, to a
// file only root can read on this host, and returns a sentence naming it.
func (s *Server) keepRecreateSpec(op, name string, spec *pb.VMSpec) string {
	if s.dataDir == "" || spec == nil {
		return "Its spec was not kept; re-create it from your own copy."
	}
	dir := filepath.Join(s.dataDir, "recreate-failed")
	b, err := protojson.MarshalOptions{Multiline: true}.Marshal(spec)
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s-%s.json", name, op, time.Now().UTC().Format("20060102T150405Z")))
	if err == nil {
		err = os.WriteFile(path, b, 0o600)
	}
	if err != nil {
		slog.Error(op+": could not keep the spec of a VM whose re-create failed", "vm", name, "error", err)
		return "Its spec could not be kept (" + err.Error() + "); re-create it from your own copy."
	}
	return fmt.Sprintf("Its spec is kept on %s at %s; re-create the VM from it.", s.hostName, path)
}
