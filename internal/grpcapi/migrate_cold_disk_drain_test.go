package grpcapi

// The disk copy's rules that host drain's cold move of a RUNNING VM relies on:
// the target takes the owner's word that the domain is shut off while its own
// copy of the VM row still says running (replication lag), and a check-only
// call runs the target's checks before the VM is shut down, writing nothing.
// The fleet runs every node on one shared database, so it cannot lag; these
// fixtures give source and target separate databases.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// ownerPeerCtx is the VM's owner (the host its row names) calling the target.
func ownerPeerCtx(t *testing.T, f *coldDiskFixture) context.Context {
	t.Helper()
	ctx := context.WithValue(peerCtxFor(t, f.dst, f.src.hostName), ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

// lagTargetRow makes the target's copy of the VM row say running, as it does
// for a moment after the owner records it stopped for a drain: the stopped
// write has not replicated there yet. The source's copy stays stopped.
func lagTargetRow(t *testing.T, f *coldDiskFixture) {
	t.Helper()
	if err := corrosion.UpdateVMState(adminCtx(), f.dst.db, "os1", "running", ""); err != nil {
		t.Fatalf("UpdateVMState: %v", err)
	}
}

// The owner's copy goes through although the target's row still says running:
// the owner says its domain is shut off, and it is the host the row names.
//
// Mutation: drop the owner's word (accept only a stopped row) — the copy is
// refused with "VM "os1" is running" and goes red.
func TestReceiveMigrationDisk_OwnerCoversALaggingRow(t *testing.T) {
	f := newColdDiskFixture(t)
	lagTargetRow(t, f)
	f.client.up.ctx = ownerPeerCtx(t, f)
	data := []byte(strings.Repeat("disk data ", 1000))
	f.writeSource(t, data)

	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("copy from the owner while the target's row lags = %v, want it taken", err)
	}
	if got, err := os.ReadFile(f.path); err != nil || string(got) != string(data) {
		t.Fatalf("target file = %d bytes (%v), want the source's %d", len(got), err, len(data))
	}
}

// Only the owner can vouch for its domain, and only by saying so: a running
// row is refused for any other peer, and for the owner when the header does
// not say the domain is shut off.
//
// Mutation: accept the word of any peer (drop the owner comparison) — the
// non-owner's copy is taken and goes red.
func TestReceiveMigrationDisk_RunningRowNeedsTheOwnersWord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		owner    bool
		attested bool
	}{
		{"another peer says so", false, true},
		{"the owner does not say so", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newColdDiskFixture(t)
			lagTargetRow(t, f)
			ctx := f.peer
			if tc.owner {
				ctx = ownerPeerCtx(t, f)
			}
			srv := &diskRecvStream{ctx: ctx, frames: []*pb.ReceiveMigrationDiskRequest{
				{VmName: "os1", Path: f.path, SizeBytes: 4, OwnerDomainShutOff: tc.attested},
				{Offset: 0, Data: []byte("data")},
			}}
			err := f.dst.ReceiveMigrationDisk(srv)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "os1" is running`) {
				t.Fatalf("copy = %v, want FailedPrecondition: VM \"os1\" is running", err)
			}
			if _, serr := os.Stat(f.path); !os.IsNotExist(serr) {
				t.Errorf("a refused copy left a file at %s (stat: %v)", f.path, serr)
			}
		})
	}
}

// A check-only call runs while the VM still runs, from the owner before it
// shuts the VM down: it passes, and writes nothing — no file, no scratch, no
// record of a copy.
//
// Mutation: drop the check-only return — the call goes on to wait for data,
// fails with "ended without its digest", and goes red.
func TestReceiveMigrationDisk_CheckOnlyWritesNothing(t *testing.T) {
	f := newColdDiskFixture(t)
	lagTargetRow(t, f)
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: 4 << 20, AllocatedBytes: 1 << 20, CheckOnly: true},
	}}
	if err := f.dst.ReceiveMigrationDisk(srv); err != nil {
		t.Fatalf("check-only call = %v, want it to pass", err)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Errorf("a check-only call left a file at %s (stat: %v)", f.path, err)
	}
	if left := scratchLeft(t, filepath.Dir(f.path)); len(left) > 0 {
		t.Errorf("a check-only call left scratch files: %v", left)
	}
	if f.dst.migrationStubs.owns("os1", f.path) {
		t.Error("a check-only call recorded a copy")
	}
}

// A check-only call refuses what the copy would refuse: here a file already at
// the disk's path, which the copy must never overwrite.
//
// Mutation: return before the existing-file check for check-only calls — the
// check passes and goes red.
func TestReceiveMigrationDisk_CheckOnlyRefusesWhatTheCopyWould(t *testing.T) {
	f := newColdDiskFixture(t)
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte("an earlier stay's disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: 4, CheckOnly: true},
	}}
	if err := f.dst.ReceiveMigrationDisk(srv); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("check-only call over an existing file = %v, want FailedPrecondition: already exists", err)
	}
	if got, _ := os.ReadFile(f.path); string(got) != "an earlier stay's disk" {
		t.Errorf("the existing file was changed: %q", got)
	}
}

// An overlay whose backing image is not qcow2 (a promoted replica's raw base)
// cannot be flattened by the copy; the source says so before anything is done,
// which is what lets a drain refuse it while the VM still runs.
//
// Mutation: skip flattenableChain — the check passes and goes red.
func TestColdDiskSourceCheck_RawBackingCannotBeFlattened(t *testing.T) {
	f := newColdDiskFixture(t)
	const size = 1 << 20
	base := filepath.Join(t.TempDir(), "base.raw")
	if err := qcow2.Create(base, size, nil); err != nil {
		t.Fatal(err)
	}
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(sp, base, size, nil); err != nil {
		t.Fatalf("create overlay: %v", err)
	}
	// The base becomes a raw image.
	if err := os.WriteFile(base, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.src.coldDiskSourceCheck(f.disk, "qcow2")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot be flattened") {
		t.Fatalf("source check of a raw-backed overlay = %v, want FailedPrecondition: cannot be flattened", err)
	}
}
