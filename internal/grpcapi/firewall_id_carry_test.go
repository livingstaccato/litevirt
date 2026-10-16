package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// R3-I1: a VM restored into a freed name is a new workload. The deleted
// incarnation's tags row is still there (its clear failed) and the backup's
// spec holds its identity; the restored VM holds none, and the restore says
// which tags the deleted VM left and the command that sets them again.
//
// Mutation: carry the identity from the deleted incarnation (or keep the
// backup's) — red.
func TestRestoreLive_IntoAFreedNameGetsNoFirewallIDAndSaysWhatWasLeft(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.virt = libvirtfake.New()
	ctx := context.Background()
	const id = "0123456789abcdef0123456789abcdef"

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{"name":"vm1","cpu":2,"memory_mib":2048}`,
		FirewallCarry: corrosion.CarryFirewallIDOf(corrosion.TagMemberVM, id),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.DB().ExecContext(ctx,
		`INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'test', ?)`,
		corrosion.FirewallTagsKeyPrefix+"vm/"+id, `{"tags":{"role":"web","env":"prod"},"name":"vm1"}`, s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "vm1"); err != nil {
		t.Fatal(err)
	}

	var spec map[string]any
	if err := json.Unmarshal([]byte(testSpecJSON(t, "vm1")), &spec); err != nil {
		t.Fatal(err)
	}
	spec["firewall_id"] = id
	b, _ := json.Marshal(spec)
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(b))
	stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer func() { cancel(); <-done }()

	rec, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || rec == nil {
		t.Fatalf("restored row: %v %v", rec, err)
	}
	if strings.Contains(rec.Spec, id) {
		t.Fatalf("the restored VM holds the deleted incarnation's identity: %s", rec.Spec)
	}
	stream.mu.Lock()
	var said []string
	for _, p := range stream.out {
		said = append(said, p.Status)
	}
	stream.mu.Unlock()
	all := strings.Join(said, "\n")
	for _, want := range []string{"env=prod", "role=web", "lv firewall tag set vm1 env=prod role=web"} {
		if !strings.Contains(all, want) {
			t.Fatalf("the restore did not say %q; it said:\n%s", want, all)
		}
	}
}

// replacedFirewallCarry carries the identity the replaced VM ctx holds for
// that name only — a full or row-only re-create alike — and nothing once
// withoutReplacedFirewallID has dropped it (a rebuild whose delete found no
// row), for another name, or with no replaced VM at all.
//
// Mutation: make withoutReplacedFirewallID a no-op — red.
func TestReplacedFirewallCarry(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	vm := &corrosion.VMRecord{Name: "web", CreatedAt: "c1", HostName: "h1", Spec: `{"name":"web","firewall_id":"` + id + `"}`}
	want := corrosion.CarryFirewallIDOf(corrosion.TagMemberVM, id)
	none := corrosion.FirewallIDCarry{}
	for what, ctx := range map[string]context.Context{
		"re-create": withReplacedVM(context.Background(), vm),
		"row-only":  withReplacedRow(context.Background(), vm),
	} {
		if got := replacedFirewallCarry(ctx, "web"); got != want {
			t.Errorf("%s: carries %+v, want %+v", what, got, want)
		}
		if got := replacedFirewallCarry(ctx, "other"); got != none {
			t.Errorf("%s: a create of another name carries %+v", what, got)
		}
		dropped := withoutReplacedFirewallID(ctx, "web")
		if got := replacedFirewallCarry(dropped, "web"); got != none {
			t.Errorf("%s: carries %+v after the identity was dropped", what, got)
		}
		if _, ok := replacedRowFor(dropped, "web"); !ok {
			t.Errorf("%s: dropping the identity dropped the replaced row", what)
		}
	}
	if got := replacedFirewallCarry(context.Background(), "web"); got != none {
		t.Errorf("a plain create carries %+v", got)
	}
}

// headerSpy is an owner that reports a tombstoned row in the deleted-VM
// header and answers err.
type headerSpy struct {
	pb.LiteVirtClient
	md  metadata.MD
	err error
}

func (h *headerSpy) DeleteVM(_ context.Context, _ *pb.DeleteVMRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	for _, o := range opts {
		if hc, ok := o.(grpc.HeaderCallOption); ok {
			*hc.HeaderAddr = h.md
		}
	}
	if h.err != nil {
		return nil, h.err
	}
	return &emptypb.Empty{}, nil
}

// The invariant the inline recreate's LUN strip rests on (D2b re-review 2,
// concern 1): a forwarded delete that fails fills no sink, so a re-create's
// carry never rests on a delete that did not tear its row down. The owner's
// header names the very row the caller meant; only a delete that answered OK
// is taken.
//
// Mutation: take the header before the error check — the NotFound case fills
// the sink: red.
func TestDeleteVM_AFailedForwardedDeleteFillsNoSink(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		what   string
		err    error
		filled bool
	}{
		{"NotFound", status.Error(codes.NotFound, "gone"), false},
		{"OK (control)", nil, true},
	} {
		s := hotplugDiskServer(t)
		insertTestVM(t, adminCtx(), s.db, "remote", "other-host", "running")
		rec, err := corrosion.GetVM(context.Background(), s.db, "remote")
		if err != nil || rec == nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(replacedVMWire{Name: "remote", CreatedAt: rec.CreatedAt, HostName: "other-host",
			IdentityHash: "h", FirewallID: id})
		spy := &headerSpy{md: metadata.Pairs(deletedVMMD, string(b)), err: tc.err}
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return spy, func() {}, nil }
		ctx, sink := withDeletedVMSink(adminCtx(), "remote", rec.CreatedAt)
		_, _ = s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "remote"})
		if got := sink.snap != nil; got != tc.filled {
			t.Fatalf("%s: sink filled = %v, want %v", tc.what, got, tc.filled)
		}
	}
}
