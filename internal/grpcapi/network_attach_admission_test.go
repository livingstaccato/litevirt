package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Network admission on every path that attaches a network. CreateVM and
// container create always refused a network another project owns; these pin
// the same rule (tenancy.AdmitAttach through admitNetworkAttach /
// admitCopiedNetworks) on the other paths that attach one: AttachDevice NIC,
// CloneVM, CloneContainer, promote, live-restore, ImportVM, container restore
// and a stack NIC retarget. Each test also shows a GLOBAL network still works.

// seedAdmissionNetworks creates the three networks every test here uses: one
// owned by acme, one owned by beta, and a global (shared) one.
func seedAdmissionNetworks(t *testing.T, s *Server) {
	t.Helper()
	mkProjectNetwork(t, s, "acme-net", "acme")
	mkProjectNetwork(t, s, "beta-net", "beta")
	mkProjectNetwork(t, s, "shared-net", "")
	// A no-op provisioner: the allowed cases reach network provisioning, which
	// must not touch the test machine's interfaces.
	s.SetNetworkProvisioner(&bridgeRemovalProv{})
}

// wantNetworkRefused fails unless err is the PermissionDenied refusal naming
// network and, when op is set, the operation.
func wantNetworkRefused(t *testing.T, err error, op, network string) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied refusing network %q", err, network)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, strconv.Quote(network)) || !strings.Contains(msg, "may not attach") {
		t.Fatalf("refusal %q does not say which network (%q) and why", msg, network)
	}
	if op != "" && !strings.HasPrefix(msg, op+": ") {
		t.Fatalf("refusal %q does not name the operation %q", msg, op)
	}
}

// ── AttachDevice NIC ─────────────────────────────────────────────────────────

func TestAttachDeviceNIC_NetworkProjectAdmission(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedAdmissionNetworks(t, s)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "stopped", Project: "acme",
		CPUActual: 2, MemActual: 4096,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 4096, Project: "acme"}),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "beta-net", Mac: "52:54:00:aa:10:01"},
	})
	wantNetworkRefused(t, err, "", "beta-net")
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if len(nics) != 0 {
		t.Fatalf("a refused attach wrote NIC rows: %+v", nics)
	}
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("a refused attach left an operation open: %q", vm.ActiveOperationID)
	}

	for i, network := range []string{"acme-net", "shared-net"} {
		mac := []string{"52:54:00:aa:10:02", "52:54:00:aa:10:03"}[i]
		if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: "vm1", Nic: &pb.NetworkAttachment{Name: network, Mac: mac},
		}); err != nil {
			t.Fatalf("attach to %s: %v", network, err)
		}
	}
}

// The owner leg of a forwarded attach re-runs the managed-network check, so an
// older entry node that admitted nothing cannot hand it another project's network.
func TestAttachDeviceNIC_OwnerLegChecksManagedNetwork(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	seedAdmissionNetworks(t, s)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.8", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "stopped", Project: "acme",
		CPUActual: 2, MemActual: 4096,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 4096, Project: "acme"}),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	peer := func(opID string) context.Context {
		return metadata.NewIncomingContext(mtlsAdminCtx("peer-1"),
			metadata.Pairs(deviceOpIDMDKey, opID, deviceOpHashMDKey, "hash-"+opID))
	}
	if _, _, ok := s.deviceOpFromPeer(peer("op-x")); !ok {
		t.Fatal("test context does not classify as a peer-forwarded owner leg")
	}

	_, err := s.AttachDevice(peer("op-1"), &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "beta-net", Mac: "52:54:00:aa:30:01"},
	})
	wantNetworkRefused(t, err, "", "beta-net")
	if nics, _ := corrosion.MergedVMNICs(adminCtx(), s.db, "vm1"); len(nics) != 0 {
		t.Fatalf("a refused owner-leg attach wrote NIC rows: %+v", nics)
	}
	if _, err := s.AttachDevice(peer("op-2"), &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "shared-net", Mac: "52:54:00:aa:30:02"},
	}); err != nil {
		t.Fatalf("owner-leg attach to a global network: %v", err)
	}
}

// A completed keyed attach replays its stored response even if admission would
// now refuse it: the replay lookup runs before admission.
func TestAttachDeviceNIC_ReplayPrecedesAdmission(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedAdmissionNetworks(t, s)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "stopped", Project: "acme",
		CPUActual: 2, MemActual: 4096,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 4096, Project: "acme"}),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	req := &pb.AttachDeviceRequest{
		VmName: "vm1", IdempotencyKey: "attach-once",
		Nic: &pb.NetworkAttachment{Name: "shared-net", Mac: "52:54:00:aa:40:01"},
	}
	if _, err := s.AttachDevice(ctx, req); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	mkProjectNetwork(t, s, "shared-net", "beta") // ownership changes after the attach
	if _, err := s.AttachDevice(ctx, req); err != nil {
		t.Fatalf("replay of a completed attach must return its stored response, got %v", err)
	}
}

// ── CloneVM ──────────────────────────────────────────────────────────────────

// seedNetCloneSource inserts a stopped VM named name in project with one NIC on
// network and a real qcow2 root disk, ready for CloneVM.
func seedNetCloneSource(t *testing.T, s *Server, name, project, network string) {
	t.Helper()
	srcDisk := s.images.DiskPath(name, "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 512, Project: project,
		Network: []*pb.NetworkAttachment{{Name: network}},
	})
	if err := corrosion.InsertVM(adminCtx(), s.db,
		corrosion.VMRecord{Name: name, HostName: "test-host", State: "stopped", Project: project, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

func TestCloneVM_NetworkProjectAdmission(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	ctx := adminCtx()
	seedAdmissionNetworks(t, s)
	seedNetCloneSource(t, s, "src-owned", "acme", "acme-net")
	seedNetCloneSource(t, s, "src-shared", "acme", "shared-net")

	// Into another project, the source's owned network is refused before any disk.
	_, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src-owned", Target: "c-cross", Project: "beta", Mode: "full"})
	wantNetworkRefused(t, err, "clone", "acme-net")
	if rec, _ := corrosion.GetVM(ctx, s.db, "c-cross"); rec != nil {
		t.Fatalf("refused clone persisted a row: %+v", rec)
	}
	if _, serr := os.Stat(s.images.DiskPath("c-cross", "root")); serr == nil {
		t.Fatal("refused clone wrote a disk")
	}

	// Same project: the owned network is the clone's own project's.
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src-owned", Target: "c-same", Mode: "full"}); err != nil {
		t.Fatalf("same-project clone: %v", err)
	}
	// A global network is shared: cloning onto it into another project works.
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src-shared", Target: "c-shared", Project: "beta", Mode: "full"}); err != nil {
		t.Fatalf("cross-project clone on a global network: %v", err)
	}
}

// ── CloneContainer ───────────────────────────────────────────────────────────

func TestCloneContainer_NetworkProjectAdmission(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	seedAdmissionNetworks(t, s)
	for _, c := range []struct{ name, network string }{{"ct-owned", "acme-net"}, {"ct-shared", "shared-net"}} {
		if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
			Name: c.name, Template: "download", Distro: "alpine", Project: "acme",
			Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: c.network}},
		}); err != nil {
			t.Fatalf("CreateContainer(%s): %v", c.name, err)
		}
	}

	_, err := s.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "ct-owned", Target: "cc-cross", HostName: "test-host", Project: "beta"})
	wantNetworkRefused(t, err, "clone", "acme-net")
	if rec, _ := corrosion.GetContainer(ctx, s.db, "test-host", "cc-cross"); rec != nil {
		t.Fatalf("refused clone persisted a row: %+v", rec)
	}

	if _, err := s.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "ct-owned", Target: "cc-same", HostName: "test-host"}); err != nil {
		t.Fatalf("same-project container clone: %v", err)
	}
	if _, err := s.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "ct-shared", Target: "cc-shared", HostName: "test-host", Project: "beta"}); err != nil {
		t.Fatalf("cross-project container clone on a global network: %v", err)
	}
}

// ── promote ──────────────────────────────────────────────────────────────────

// setPromotableNetwork rewrites vm1's spec (seeded by seedPromotableVM) to carry
// one NIC on network.
func setPromotableNetwork(t *testing.T, s *Server, network string) {
	t.Helper()
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: network, Mac: "52:54:00:aa:20:01"}},
	})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'vm1'`, string(specJSON)); err != nil {
		t.Fatal(err)
	}
}

func TestPromoteReplica_NetworkProjectAdmission(t *testing.T) {
	t.Run("renamed promotion onto a foreign network refused", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		seedAdmissionNetworks(t, s)
		poolDir := seedPromotableVM(t, s, "dead-host", "failed", "acme", 1, 512)
		setPromotableNetwork(t, s, "beta-net")

		err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1", NewName: "vm1-copy"})
		wantNetworkRefused(t, err, "promote", "beta-net")
		assertNoPromotedArtifacts(t, s, poolDir, "vm1-copy")
		if rec, _ := corrosion.GetVM(context.Background(), s.db, "vm1-copy"); rec != nil {
			t.Fatalf("refused renamed promotion persisted a row: %+v", rec)
		}
		if rec, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); rec == nil || rec.HostName != "dead-host" {
			t.Fatalf("refused promotion disturbed the durable record: %+v", rec)
		}
	})
	// A takeover re-homes the existing VM and its existing NICs. Refusing would
	// leave a fenced host's VM down without removing the attachment, so it
	// promotes and leaves an audit record instead.
	t.Run("takeover onto a foreign network promotes and audits", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		seedAdmissionNetworks(t, s)
		seedPromotableVM(t, s, "dead-host", "failed", "acme", 1, 512)
		setPromotableNetwork(t, s, "beta-net")

		if err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"}); err != nil {
			t.Fatalf("takeover promotion must not be blocked by network admission: %v", err)
		}
		if rec, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); rec == nil || rec.HostName != s.hostName {
			t.Fatalf("takeover did not re-home vm1: %+v", rec)
		}
		wantForeignNetworkAudit(t, s, "vm.promote", "vm1", "beta-net")
	})
	t.Run("global network promotes", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		seedAdmissionNetworks(t, s)
		seedPromotableVM(t, s, "dead-host", "failed", "acme", 1, 512)
		setPromotableNetwork(t, s, "shared-net")

		if err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"}); err != nil {
			t.Fatalf("promotion of a VM on a global network: %v", err)
		}
	})
}

// ── live restore (auto-define) ───────────────────────────────────────────────

func TestAutoDefineRestoredVM_NetworkProjectAdmission(t *testing.T) {
	newServer := func(t *testing.T) (*Server, *pbsstore.Repo, *libvirtfake.Fake) {
		s := testServer(t)
		fake := libvirtfake.New()
		s.virt = fake
		s.dataDir = t.TempDir()
		seedAdmissionNetworks(t, s)
		repo, err := pbsstore.Init(t.TempDir())
		if err != nil {
			t.Fatalf("Init repo: %v", err)
		}
		return s, repo, fake
	}
	noSend := func(*pb.RestoreLiveProgress) error { return nil }
	specFor := func(project, network string) *pb.VMSpec {
		return &pb.VMSpec{Name: "r1", Cpu: 1, MemoryMib: 512, Project: project,
			Network: []*pb.NetworkAttachment{{Name: network}}}
	}
	manifestWith := func(spec *pb.VMSpec) *pbsstore.Manifest {
		b, _ := json.Marshal(spec)
		return &pbsstore.Manifest{VMName: "r1", DiskName: "root", TotalSize: 1 << 20, VMSpecJSON: string(b)}
	}

	t.Run("caller spec on a foreign network", func(t *testing.T) {
		s, repo, _ := newServer(t)
		req := &pb.RestoreLiveRequest{VmName: "r1", Spec: specFor("acme", "beta-net")}
		_, _, err := s.autoDefineRestoredVM(adminCtx(), req, repo, &pbsstore.Manifest{VMName: "r1", DiskName: "root", TotalSize: 1 << 20}, "/tmp/o.qcow2", "acme", noSend)
		wantNetworkRefused(t, err, "", "beta-net")
	})
	t.Run("backed-up spec into another project", func(t *testing.T) {
		s, repo, _ := newServer(t)
		req := &pb.RestoreLiveRequest{VmName: "r1"}
		_, _, err := s.autoDefineRestoredVM(adminCtx(), req, repo, manifestWith(specFor("acme", "acme-net")), "/tmp/o.qcow2", "beta", noSend)
		wantNetworkRefused(t, err, "", "acme-net")
		if rec, _ := corrosion.GetVM(context.Background(), s.db, "r1"); rec != nil {
			t.Fatalf("refused restore persisted a row: %+v", rec)
		}
	})
	t.Run("backed-up spec on a foreign network", func(t *testing.T) {
		s, repo, _ := newServer(t)
		req := &pb.RestoreLiveRequest{VmName: "r1"}
		_, _, err := s.autoDefineRestoredVM(adminCtx(), req, repo, manifestWith(specFor("acme", "beta-net")), "/tmp/o.qcow2", "acme", noSend)
		wantNetworkRefused(t, err, "", "beta-net")
	})
	t.Run("caller spec on a raw bridge takes the create gate", func(t *testing.T) {
		s, repo, _ := newServer(t)
		// Same project on both sides, so only the strict (create) branch can
		// refuse this: a backed-up spec would carry the raw bridge.
		req := &pb.RestoreLiveRequest{VmName: "r1", Spec: specFor("acme", "br-raw")}
		_, _, err := s.autoDefineRestoredVM(viewerCtx(), req, repo, &pbsstore.Manifest{VMName: "r1", DiskName: "root", TotalSize: 1 << 20}, "/tmp/o.qcow2", "acme", noSend)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "raw/unmanaged bridge") {
			t.Fatalf("a caller-supplied spec on a raw bridge from a non-root caller: got %v, want the raw-bridge refusal", err)
		}
	})
	t.Run("manifest spec on a raw bridge takes the create gate", func(t *testing.T) {
		s, repo, _ := newServer(t)
		// The manifest is untrusted backup data: its project field must not buy a
		// raw bridge the same-project carry.
		req := &pb.RestoreLiveRequest{VmName: "r1"}
		_, _, err := s.autoDefineRestoredVM(viewerCtx(), req, repo, manifestWith(specFor("acme", "br-raw")), "/tmp/o.qcow2", "acme", noSend)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "raw/unmanaged bridge") {
			t.Fatalf("a manifest spec on a raw bridge from a non-root caller: got %v, want the raw-bridge refusal", err)
		}
	})
	t.Run("from-existing spec", func(t *testing.T) {
		s, repo, _ := newServer(t)
		seed := func(name, project, network string) {
			b, _ := json.Marshal(specFor(project, network))
			if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
				Name: name, HostName: "test-host", State: "stopped", Project: project, Spec: string(b),
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
		}
		seed("ex-raw", "acme", "br-raw")
		seed("ex-owned", "acme", "acme-net")
		empty := &pbsstore.Manifest{DiskName: "root", TotalSize: 1 << 20}

		// The cluster's own row is trusted: a same-project raw bridge is carried,
		// so the non-root caller is stopped by vm.create, not by the bridge.
		_, _, err := s.autoDefineRestoredVM(viewerCtx(), &pb.RestoreLiveRequest{VmName: "ex-raw", FromExisting: true, NewName: "ex-raw-2"},
			repo, empty, "/tmp/o.qcow2", "acme", noSend)
		if err == nil || strings.Contains(err.Error(), "raw/unmanaged bridge") {
			t.Fatalf("a from-existing same-project raw bridge must be carried past network admission, got %v", err)
		}
		// Into another project it is still judged.
		_, _, err = s.autoDefineRestoredVM(adminCtx(), &pb.RestoreLiveRequest{VmName: "ex-owned", FromExisting: true, NewName: "ex-owned-2"},
			repo, empty, "/tmp/o.qcow2", "beta", noSend)
		wantNetworkRefused(t, err, "restore", "acme-net")
	})
	t.Run("global network gets past admission", func(t *testing.T) {
		s, repo, fake := newServer(t)
		// A define failure is the marker that network admission let it through.
		fake.FailDefineDomain = func(string) error { return errors.New("define reached") }
		for _, req := range []*pb.RestoreLiveRequest{
			{VmName: "r1", Spec: specFor("acme", "shared-net")},
			{VmName: "r1"},
		} {
			_, _, err := s.autoDefineRestoredVM(adminCtx(), req, repo, manifestWith(specFor("acme", "shared-net")), "/tmp/o.qcow2", "beta", noSend)
			if err == nil || !strings.Contains(err.Error(), "define reached") {
				t.Fatalf("restore on a global network should reach DefineDomain, got %v", err)
			}
		}
	})
}

// ── ImportVM ─────────────────────────────────────────────────────────────────

func TestImportVM_NetworkProjectAdmission(t *testing.T) {
	newServer := func(t *testing.T) *Server {
		s := testServer(t)
		s.dataDir = t.TempDir()
		admissionHost(t, s)
		s.virt = libvirtfake.New()
		seedAdmissionNetworks(t, s)
		quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{})
		return s
	}
	s := newServer(t)
	err := importSmallVM(t, s, "imp-foreign", "acme", 512, false, "net0: virtio=AA:BB:CC:DD:EE:10,bridge=beta-net")
	wantNetworkRefused(t, err, "", "beta-net")
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-foreign"); rec != nil {
		t.Fatalf("refused import persisted a row: %+v", rec)
	}

	s = newServer(t)
	if err := importSmallVM(t, s, "imp-shared", "acme", 512, false, "net0: virtio=AA:BB:CC:DD:EE:11,bridge=shared-net"); err != nil {
		t.Fatalf("import onto a global network: %v", err)
	}
}

// ── container restore ────────────────────────────────────────────────────────

// wantForeignNetworkAudit fails unless exactly one "allowed-foreign-network"
// audit row exists for action/target, naming network.
func wantForeignNetworkAudit(t *testing.T, s *Server, action, target, network string) {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT detail FROM audit_log WHERE action = ? AND target = ? AND result = 'allowed-foreign-network'`, action, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].String("detail"), strconv.Quote(network)) {
		t.Fatalf("want one allowed-foreign-network audit for %s %s naming %q, got %d rows", action, target, network, len(rows))
	}
}

// A failover relocation re-homes the existing container: it proceeds onto a
// network its project may not use, and leaves an audit record.
func TestRestoreContainer_RelocationOnForeignNetworkProceedsAndAudits(t *testing.T) {
	s := newPeerAuthServer(t) // hostName "self", knows peer "peer-1"
	s.dataDir = t.TempDir()
	s.gate = fakeServerGate{execOK: true}
	seedAdmissionNetworks(t, s)
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)
	repo, ts, token, proofID := ctTestRepo(t), "2026-07-03T10:00:00Z", "reloc-token-1", "restore-proof-1"
	ctx := adminCtx()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "self", Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Template: "download", Distro: "alpine",
			Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "beta-net"}},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "ct1", HostName: "self", RepoPath: repo, Timestamp: ts},
		&progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "self", "ct1")

	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: ts, Proof: relocProof(proofID, token),
	}, &progressStream[pb.RestoreContainerProgress]{ctx: proofRestoreCtx(token)}); err != nil {
		t.Fatalf("a relocation must not be blocked by network admission: %v", err)
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "self", "ct1"); row == nil {
		t.Fatal("relocation did not land the container row")
	}
	wantForeignNetworkAudit(t, s, "ct.restore", "ct1", "beta-net")
}

func TestRestoreContainer_NetworkProjectAdmission(t *testing.T) {
	run := func(t *testing.T, network string) (*Server, error) {
		s := testServer(t)
		s.hostName = "host-a"
		s.dataDir = t.TempDir()
		ctx := context.Background()
		seedAdmissionNetworks(t, s)
		repo := ctTestRepo(t)
		s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: "host-a", Name: "ct1", State: "stopped", Project: "acme",
			CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
				Template: "download", Distro: "alpine",
				Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: network}},
			}),
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.BackupContainer(&pb.BackupContainerRequest{
			Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-23T12:00:00Z",
		}, &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}); err != nil {
			t.Fatalf("BackupContainer: %v", err)
		}
		_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
		return s, s.RestoreContainer(&pb.RestoreContainerRequest{
			Name: "ct1", RepoPath: repo, Timestamp: "2026-06-23T12:00:00Z",
		}, &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()})
	}

	s, err := run(t, "beta-net")
	wantNetworkRefused(t, err, "restore", "beta-net")
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1"); row != nil {
		t.Fatalf("refused restore persisted a row: %+v", row)
	}

	if _, err := run(t, "shared-net"); err != nil {
		t.Fatalf("restore of a container on a global network: %v", err)
	}
}

// ── stack NIC retarget ───────────────────────────────────────────────────────

func TestRetargetVMNICs_MissingVMIsNotFound(t *testing.T) {
	s := testServer(t)
	_, err := s.retargetVMNICs(adminCtx(), "ghost", []compose.NICRetarget{{Ordinal: 0, From: "stk_lan", To: "lan"}})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("retarget of a missing VM: got %v, want NotFound", err)
	}
}

func TestCheckNICRetarget_NetworkProjectAdmission(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	seedAdmissionNetworks(t, s)
	rt := func(to string) compose.NICRetarget {
		return compose.NICRetarget{Ordinal: 0, From: "stk_lan", To: to}
	}

	err := s.checkNICRetarget(ctx, "vm1", "acme", rt("beta-net"))
	if !errors.Is(err, errNICRetargetRefused) || !strings.Contains(err.Error(), `"beta-net"`) ||
		!strings.Contains(err.Error(), "may not attach") {
		t.Fatalf("a retarget onto another project's network: got %v, want a refusal naming it", err)
	}
	for _, to := range []string{"acme-net", "shared-net"} {
		if err := s.checkNICRetarget(ctx, "vm1", "acme", rt(to)); err != nil {
			t.Fatalf("retarget onto %s: %v", to, err)
		}
	}
}

// ── admitCopiedNetworks: the raw-bridge rule ─────────────────────────────────

// A copy into the SAME project carries a raw bridge (its create already passed
// the gate, and the automated paths have no caller); a copy into a DIFFERENT
// project is a new attachment and needs cluster-root authority, as a create does.
func TestAdmitCopiedNetworks_RawBridge(t *testing.T) {
	s := testServer(t)
	seedAdmissionNetworks(t, s)
	if err := s.admitCopiedNetworks(viewerCtx(), "clone", "acme", "acme", []string{"br-raw"}); err != nil {
		t.Fatalf("same-project copy of a raw bridge must be carried: %v", err)
	}
	err := s.admitCopiedNetworks(viewerCtx(), "clone", "beta", "acme", []string{"br-raw"})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "raw/unmanaged bridge") ||
		!strings.Contains(status.Convert(err).Message(), "clone: ") {
		t.Fatalf("cross-project copy of a raw bridge by a non-root caller: got %v, want the raw-bridge refusal", err)
	}
	if err := s.admitCopiedNetworks(adminCtx(), "clone", "beta", "acme", []string{"br-raw"}); err != nil {
		t.Fatalf("cross-project copy of a raw bridge by a root caller: %v", err)
	}
	if err := s.admitCopiedNetworks(viewerCtx(), "clone", "beta", "acme", []string{"shared-net"}); err != nil {
		t.Fatalf("cross-project copy onto a global network: %v", err)
	}
}
