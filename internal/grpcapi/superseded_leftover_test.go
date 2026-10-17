package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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

// deleteFixture: os1 runs on this host; node-3, node-4 and node-5 recorded
// events of it (the VM was there), node-6 never did. node-3 declines (a
// domain is defined there), node-4 and node-6 answer only once released,
// node-5 removes its leftovers.
func deleteFixture(t *testing.T, wait time.Duration) (*Server, chan struct{}, chan string) {
	t.Helper()
	old := deletedVMCleanupReportWait
	t.Cleanup(func() { deletedVMCleanupReportWait = old })
	deletedVMCleanupReportWait = wait
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	for _, h := range []string{"node-3", "node-4", "node-5", "node-6"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.9", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	locks := make(chan string, 8)
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		return declaringPeer{s: s, host: host, release: release, locks: locks}, func() {}, nil
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "os1", HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"node-3", "node-4", "node-5"} {
		if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{VMName: "os1", HostName: h, Type: "vm.started", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	fake.SetState("os1", libvirtfake.StateShutdown)
	return s, release, locks
}

// A host the VM was on that declines because a domain of the name is defined
// there, and one that has not answered when the wait ends, are named in the
// delete's response (LeftoverDomainMD), which `lv rm` prints. A host that
// removed its leftovers is not, and neither is a host the VM never was on,
// slow as it may be: it is asked, not waited for. The wait holds neither the
// VM's lock nor its start lease.
//
// Red on b4ef9fe9: the header is never set. Red on a021a6d3: node-6 is named
// pending, and the lock and lease are held during the wait.
// Mutations: wait inside deleteVM (before its deferred releases) — the lock
// and lease are held; wait for every asked host — node-6 is pending.
func TestDeleteVM_NamesTheHostsThatKeepADefinition(t *testing.T) {
	s, _, locks := deleteFixture(t, 300*time.Millisecond)
	hs := &headerStream{}
	if _, err := s.DeleteVM(grpc.NewContextWithServerTransportStream(adminCtx(), hs), &pb.DeleteVMRequest{Name: "os1"}); err != nil {
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
		t.Errorf("node-4 (the VM was there, not answered) = %+v, %v", l, ok)
	}
	for _, h := range []string{"node-5", "node-6"} {
		if l, ok := got[h]; ok {
			t.Errorf("%s is named: %+v", h, l)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case l := <-locks:
			if l != "" {
				t.Error(l)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the blocking hosts were never asked")
		}
	}
}

// A delete made in-process (a stack teardown deletes its members one by one)
// waits for no host: a slow host the VM was on costs it nothing.
//
// Red on a021a6d3: every member delete waits deletedVMCleanupReportWait.
func TestDeleteVM_InProcessDeleteWaitsForNoHost(t *testing.T) {
	s, _, _ := deleteFixture(t, 2*time.Second)
	start := time.Now()
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if d := time.Since(start); d >= time.Second {
		t.Fatalf("an in-process delete took %s: it waited for a host", d)
	}
}

// A peer-search probe (x-lv-delete-local-only) waits for no host: the
// probing host holds the VM's lock and start lease until it answers, and is
// itself among the hosts the VM left, so a wait there would stall the full
// deletedVMCleanupReportWait on the prober's own lock and name it pending.
//
// Red on a28d65c4: the probe takes the full wait and names node-4 pending.
// Mutation: drop the deleteLocalOnly check in withLeftoverSink — red.
func TestDeleteVM_LocalOnlyProbeWaitsForNoHost(t *testing.T) {
	s, _, _ := deleteFixture(t, 2*time.Second)
	// node-4 is the probing host: the row names it, and it recorded events
	// of the VM, so it is in plan.left; its CleanupMigrationArtifacts blocks
	// as the prober's own lockVM would.
	if _, err := s.db.ExecuteRows(adminCtx(), `UPDATE vms SET host_name = 'node-4' WHERE name = 'os1'`); err != nil {
		t.Fatal(err)
	}
	hs := &headerStream{}
	ctx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs("x-lv-delete-local-only", "1"))
	ctx = grpc.NewContextWithServerTransportStream(ctx, hs)
	start := time.Now()
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("DeleteVM (probe): %v", err)
	}
	if d := time.Since(start); d >= time.Second {
		t.Fatalf("a peer-search probe took %s: it waited for a host", d)
	}
	if v := hs.hdr.Get(LeftoverDomainMD); len(v) != 0 {
		t.Fatalf("a peer-search probe named hosts: %v", v)
	}
}

// The hosts a delete waits for include one whose event of this incarnation
// came within created_at's second, however created_at is written: vm_events.ts
// is fixed-width, created_at bare or with trailing zeros trimmed, and the two
// are compared as text.
//
// Red on a28d65c4: both hosts are missing. Mutation: compare against
// created_at as written — red.
func TestVMLeftHosts_ComparesCreatedAtInTheEventsLayout(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	for _, tc := range []struct{ createdAt, host, ts string }{
		{"2026-10-17T10:00:00Z", "node-5", "2026-10-17T10:00:00.500000000Z"},
		{"2026-10-17T11:00:00.12Z", "node-6", "2026-10-17T11:00:00.120000001Z"},
	} {
		name := "vm-" + tc.host
		if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{VMName: name, HostName: tc.host, Type: "vm.started", Result: "ok", TS: tc.ts}); err != nil {
			t.Fatal(err)
		}
		left := s.vmLeftHosts(ctx, &corrosion.VMRecord{Name: name, CreatedAt: tc.createdAt}, deletedVMLeftovers{hosts: []string{tc.host}})
		if !left[tc.host] {
			t.Errorf("created_at %s, event at %s on %s: left = %v", tc.createdAt, tc.ts, tc.host, left)
		}
	}
}

var probeMu sync.Mutex

type declaringPeer struct {
	pb.LiteVirtClient
	s       *Server
	host    string
	release chan struct{}
	locks   chan string
}

func (p declaringPeer) CleanupMigrationArtifacts(ctx context.Context, r *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	switch p.host {
	case "node-3":
		return nil, status.Errorf(codes.FailedPrecondition,
			"a domain named %q is defined on node-3; nothing of it is removed: (running, running) the domain is not shut off", r.VmName)
	case "node-4", "node-6":
		// Asked while the delete waits: its lock and start lease are free.
		// One probe at a time, so two hosts' probes do not see each other's.
		probeMu.Lock()
		why := ""
		if unlock, ok := p.s.tryLockVM(r.VmName); !ok {
			why = p.host + " was asked while the VM's lock was held"
		} else {
			unlock()
			if held, err := health.TryVMStartLease(context.Background(), p.s.db, "probe-"+p.host, r.VmName, time.Now()); err != nil || held != "probe-"+p.host {
				why = fmt.Sprintf("%s was asked while the start lease was held by %q (%v)", p.host, held, err)
			} else {
				health.ReleaseVMStartLease(context.Background(), p.s.db, held, r.VmName)
			}
		}
		probeMu.Unlock()
		select {
		case p.locks <- why:
		default:
		}
		select {
		case <-p.release:
		case <-ctx.Done():
		}
		return &emptypb.Empty{}, nil
	}
	return &emptypb.Empty{}, nil
}

// reapedSBHost: this host holds a stopped Secure Boot definition of os1 at
// owner epoch 3, its UEFI vars at the name-keyed path, while the record was
// tombstoned on owner-host at epoch 4; the deleting host's leftover request
// has undefined it.
func reapedSBHost(t *testing.T) (*Server, *libvirtfake.Fake, string, []byte) {
	t.Helper()
	s, fake := provableCreateServer(t)
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	old := health.LibvirtNvramDir
	health.LibvirtNvramDir = t.TempDir()
	t.Cleanup(func() { health.LibvirtNvramDir = old })
	ctx := adminCtx()
	if err := corrosion.SetHostLabels(ctx, s.db, s.hostName, map[string]string{corrosion.LabelSecureBootCapable: "true"}, nil); err != nil {
		t.Fatal(err)
	}
	_ = peerCtxFor(t, s, "owner-host")
	s.db.MarkReplicaCaughtUpForTests("owner-host")
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "os1", HostName: "owner-host", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecuteRows(ctx, `UPDATE vms SET vm_owner_epoch = 4 WHERE name = 'os1'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "os1"); err != nil {
		t.Fatal(err)
	}
	vars := lv.NvramPath(s.dataDir, "os1")
	oldVars := []byte("os1's own Secure Boot vars")
	if err := os.MkdirAll(filepath.Dir(vars), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vars, oldVars, 0o600); err != nil {
		t.Fatal(err)
	}
	fake.SetState("os1", libvirtfake.StateShutdown)
	fake.SetInactiveXML("os1", `<domain type="kvm"><name>os1</name><uuid>11111111-2222-4333-8444-555555555555</uuid>`+
		`<os><nvram>`+vars+`</nvram></os></domain>`)
	if err := fake.SetDomainOwnerEpoch("os1", 3, false); err != nil {
		t.Fatal(err)
	}
	return s, fake, vars, oldVars
}

func cleanupDeleted(s *Server, name string) error {
	_, err := s.CleanupMigrationArtifacts(systemPeerCtx("owner-host"), &pb.CleanupMigrationArtifactsRequest{VmName: name, VmDeleted: true})
	return err
}

// After the reap, a Secure Boot VM of the same name can be created on this
// host, and the deleted VM's UEFI vars are kept under a .superseded- name,
// which `lv host superseded-disks` lists with the VM's name.
//
// Red on a021a6d3: the vars stay at the name-keyed path, and the create is
// refused ("UEFI vars already exist").
// Mutation: drop the vars set-aside — the create is refused and no
// .superseded- file exists.
func TestReapedSupersededDomain_SecureBootCreateOfTheNameSucceeds(t *testing.T) {
	s, fake, vars, oldVars := reapedSBHost(t)
	if err := cleanupDeleted(s, "os1"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if fake.DomainExists("os1") {
		t.Fatal("the superseded domain is still defined")
	}
	set, _ := filepath.Glob(vars + ".superseded-*")
	if len(set) != 1 {
		t.Fatalf("set-aside vars = %v, want one", set)
	}
	if b, err := os.ReadFile(set[0]); err != nil || !bytes.Equal(b, oldVars) {
		t.Fatalf("set-aside vars hold %q (%v), want the deleted VM's", b, err)
	}

	resp, err := s.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{})
	if err != nil {
		t.Fatalf("SupersededDisks: %v", err)
	}
	listed := false
	for _, d := range resp.Disks {
		if d.Path == set[0] {
			listed = d.UefiVars && d.Kept && d.VmName == "os1" && d.DiskPath == vars && d.Held != ""
			if !listed {
				t.Fatalf("listed as %+v", d)
			}
		}
	}
	if !listed {
		t.Fatalf("superseded-disks does not list %s: %+v", set[0], resp.Disks)
	}

	req := disklessCreateRequest("os1")
	req.Spec.Machine, req.Spec.Firmware, req.Spec.SecureBoot = "q35", "uefi", true
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("a Secure Boot create of the name after the reap: %v", err)
	}
	if b, err := os.ReadFile(set[0]); err != nil || !bytes.Equal(b, oldVars) {
		t.Fatalf("after the create, the set-aside vars hold %q (%v)", b, err)
	}
}

// A domain that starts between the rule's check and the undefine survives the
// undefine as a transient, running domain: the request declines, and the
// marker and the UEFI vars stay.
//
// Mutation: drop the post-undefine DomainExists check — the request succeeds
// and the marker and vars go.
func TestCleanupMigrationArtifacts_VMDeletedDomainStartedAtTheUndefine(t *testing.T) {
	s, fake, vars, _ := reapedSBHost(t)
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "os1", 3); err != nil {
		t.Fatal(err)
	}
	fake.FailUndefinePreserv = func(name string) error {
		fake.SetState(name, libvirtfake.StateRunning)
		return nil
	}
	err := cleanupDeleted(s, "os1")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "running at its undefine") {
		t.Fatalf("cleanup = %v, want FailedPrecondition naming the start", err)
	}
	if !fake.DomainExists("os1") {
		t.Fatal("the started domain is gone")
	}
	if !fileExists(filepath.Join(s.dataDir, "vms", "os1", "owner_epoch")) || !fileExists(vars) {
		t.Fatal("the marker or the vars of a running domain were moved")
	}
}
