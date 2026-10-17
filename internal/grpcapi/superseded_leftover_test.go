package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// supersededLeftoverHost is leftoverHost with a shut-off domain os1 defined
// here at owner epoch 3 (the host-local marker's), and the record at
// rowEpoch on owner-host, tombstoned. caughtUp: this host's replica has
// caught up with a peer.
func supersededLeftoverHost(t *testing.T, rowEpoch int64, caughtUp bool) *leftoverHost {
	t.Helper()
	h := newLeftoverHost(t)
	if caughtUp {
		h.s.db.MarkReplicaCaughtUpForTests("owner-host")
	}
	if _, err := h.s.db.ExecuteRows(adminCtx(), `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'os1'`, rowEpoch); err != nil {
		t.Fatal(err)
	}
	h.fake.SetState("os1", libvirtfake.StateShutdown)
	if err := h.fake.SetDomainOwnerEpoch("os1", 3, false); err != nil {
		t.Fatal(err)
	}
	h.tombstone(t)
	return h
}

// The delete's leftover request reaches the old host already back (lab 2,
// pakg: the delete came 3 s after node-4 went active): a shut-off domain the
// deleted record superseded at a newer owner epoch is undefined there,
// firmware state kept, and the marker removed, instead of the request being
// declined.
//
// Red on b4ef9fe9: FailedPrecondition, the domain and the marker kept.
// Mutations: `>` to `>=` on the epochs — "row epoch equal" is undefined;
// drop the replica check — "replica not caught up" is.
func TestCleanupMigrationArtifacts_VMDeletedUndefinesASupersededStoppedDomain(t *testing.T) {
	h := supersededLeftoverHost(t, 4, true)
	if err := h.cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if h.fake.DomainExists("os1") {
		t.Fatal("the superseded shut-off domain is still defined")
	}
	var notes []string
	for _, e := range h.fake.EventLog() {
		if e.Op == "undefine" && e.Domain == "os1" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) != 1 || notes[0] != "keep_state=true" {
		t.Fatalf("undefines = %v, want one keeping the firmware state", notes)
	}
	if fileExists(h.marker) {
		t.Fatal("the owner-epoch marker is still there")
	}
	if !fileExists(h.disk) {
		t.Fatal("a disk not named in the request was removed")
	}

	t.Run("row epoch equal", func(t *testing.T) {
		h := supersededLeftoverHost(t, 3, true)
		// No host-local marker, so the domain's own epoch alone decides.
		if err := os.Remove(h.marker); err != nil {
			t.Fatal(err)
		}
		err := h.cleanup()
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not newer") {
			t.Fatalf("cleanup = %v, want FailedPrecondition naming the epochs", err)
		}
		if !h.fake.DomainExists("os1") {
			t.Fatal("a domain at the record's own epoch was removed")
		}
	})
	t.Run("replica not caught up", func(t *testing.T) {
		h := supersededLeftoverHost(t, 4, false)
		err := h.cleanup()
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not caught up") {
			t.Fatalf("cleanup = %v, want FailedPrecondition naming the replica", err)
		}
		if !h.fake.DomainExists("os1") || !fileExists(h.marker) {
			t.Fatal("a domain was removed on a replica that has not caught up, or its marker")
		}
	})
}

// A host that declines because a domain of the name is defined there, and a
// host that has not answered when the delete returns, are named in the
// delete's response (LeftoverDomainMD), which `lv rm` prints. A host that
// removed its leftovers is not.
//
// Red on b4ef9fe9: the header is never set (the request runs after the
// delete returns, and its refusal is a WARN on the owner only).
func TestDeleteVM_NamesTheHostsThatKeepADefinition(t *testing.T) {
	defer func(w time.Duration) { deletedVMCleanupReportWait = w }(deletedVMCleanupReportWait)
	deletedVMCleanupReportWait = 300 * time.Millisecond
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	for _, h := range []corrosion.HostRecord{
		{Name: "node-3", Address: "10.0.0.3", State: "active"},
		{Name: "node-4", Address: "10.0.0.4", State: "active"},
		{Name: "node-5", Address: "10.0.0.5", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatal(err)
		}
	}
	release := make(chan struct{})
	defer close(release)
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		return declaringPeer{host: host, release: release}, func() {}, nil
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "os1", HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake.SetState("os1", libvirtfake.StateShutdown)

	hs := &headerStream{}
	if _, err := s.DeleteVM(grpc.NewContextWithServerTransportStream(ctx, hs), &pb.DeleteVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	type leftover struct {
		Host    string `json:"host"`
		Pending bool   `json:"pending"`
		Detail  string `json:"detail"`
	}
	got := map[string]leftover{}
	for _, v := range hs.hdr.Get("x-litevirt-leftover-domain") {
		var l leftover
		if err := json.Unmarshal([]byte(v), &l); err != nil {
			t.Fatalf("header value %q: %v", v, err)
		}
		got[l.Host] = l
	}
	if l, ok := got["node-3"]; !ok || l.Pending || !strings.Contains(l.Detail, "is defined on node-3") {
		t.Errorf("node-3 (declined) = %+v, %v", l, ok)
	}
	if l, ok := got["node-4"]; !ok || !l.Pending {
		t.Errorf("node-4 (not answered) = %+v, %v", l, ok)
	}
	if l, ok := got["node-5"]; ok {
		t.Errorf("node-5 removed its leftovers, yet is named: %+v", l)
	}
}

// declaringPeer: node-3 declines (a domain is defined there), node-4 answers
// only once released, node-5 removes its leftovers.
type declaringPeer struct {
	pb.LiteVirtClient
	host    string
	release chan struct{}
}

func (p declaringPeer) CleanupMigrationArtifacts(ctx context.Context, r *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	switch p.host {
	case "node-3":
		return nil, status.Errorf(codes.FailedPrecondition,
			"a domain named %q is defined on node-3; nothing of it is removed: (running, running) the domain is not shut off", r.VmName)
	case "node-4":
		select {
		case <-p.release:
		case <-ctx.Done():
		}
		return &emptypb.Empty{}, nil
	}
	return &emptypb.Empty{}, nil
}
