package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// C-C (final-rereview-integrate-3.md): the ISO grant a rebuild or a rolling
// recreate carries into its create is process-local. A create that placement
// sends to another host arrives there without it, and with
// auth.forwarded_identity on the owner judges the legacy host-path ISO as the
// Operator — and refuses, after the teardown. The re-create is pinned to the
// host whose preflight judged it, or refused before anything is torn down.

// fwdIdentityOwner stands in for another host with auth.forwarded_identity
// on: a create forwarded to it is judged as the relayed Operator, in a
// process that holds no grant (authorizeVMISO is the owner's ISO gate).
type fwdIdentityOwner struct {
	pb.LiteVirtClient
	s        *Server
	host     string
	operator context.Context
	creates  int
}

func (o *fwdIdentityOwner) judge(spec *pb.VMSpec) error {
	o.creates++
	spec = proto.Clone(spec).(*pb.VMSpec)
	if err := o.s.authorizeVMISO(o.operator, spec.GetProject(), o.host, spec); err != nil {
		return err
	}
	return status.Error(codes.Unavailable, "the test's other host creates nothing")
}

func (o *fwdIdentityOwner) CreateVM(_ context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return nil, o.judge(in.GetSpec())
}

// CleanupMigrationArtifacts answers a delete's leftover sweep: nothing here.
func (o *fwdIdentityOwner) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (o *fwdIdentityOwner) ExecuteCreateVM(_ context.Context, in *pb.ExecuteCreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return nil, o.judge(in.GetRequest().GetSpec())
}

// rebuildAcrossHosts is an Operator's legacy host-path ISO VM "old" on this
// host (test-host), unpinned, beside a far emptier active host "host-b" that
// placement prefers; a create forwarded there meets fwdIdentityOwner.
func rebuildAcrossHosts(t *testing.T) (*Server, *libvirtfake.Fake, *fwdIdentityOwner, context.Context) {
	t.Helper()
	s, fake, _ := isoServer(t)
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))
	legacyVM(t, s, fake, "old", iso)
	spec := vmSpecFor(vmRecord(t, s, "old"))
	spec.Placement = nil
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = ?`, string(b), "old"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{
		Name: "host-b", Address: "10.0.0.2", State: "active", CPUTotal: 256, MemTotal: 1 << 20,
	}); err != nil {
		t.Fatal(err)
	}
	op := userCtx("op", "operator")
	owner := &fwdIdentityOwner{s: s, host: "host-b", operator: op}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != "host-b" {
			return nil, nil, status.Errorf(codes.Unavailable, "no host %s", host)
		}
		return owner, func() {}, nil
	}
	return s, fake, owner, op
}

func TestISOFinal_ARebuildIsNotSentToAHostWithoutItsGrant(t *testing.T) {
	s, _, owner, op := rebuildAcrossHosts(t)
	if _, err := s.RebuildVM(op, &pb.RebuildVMRequest{Name: "old"}); err != nil {
		vmExists(t, s, "old", "after a rebuild that failed with "+err.Error())
		t.Fatalf("an Operator's rebuild of a legacy host-path ISO VM, with an emptier host beside it: %v (the other host was asked %d time(s))", err, owner.creates)
	}
	rec := vmExists(t, s, "old", "after the rebuild")
	if rec.HostName != s.hostName || owner.creates != 0 {
		t.Fatalf("the rebuild re-created the VM on %q (the other host was asked %d time(s)), want %q, the host that judged its ISO",
			rec.HostName, owner.creates, s.hostName)
	}
	if spec := vmSpecFor(rec); spec.GetPlacement().GetHost() != "" {
		t.Errorf("the rebuild persisted a placement pin %q into the VM's spec", spec.GetPlacement().GetHost())
	}
}

func TestISOFinal_ARollingRecreateIsNotSentToAHostWithoutItsGrant(t *testing.T) {
	s, _, owner, op := rebuildAcrossHosts(t)
	ops := &serverOps{s: s}
	if err := ops.RecreateVM(op, "old", vmSpecFor(vmExists(t, s, "old", "before"))); err != nil {
		vmExists(t, s, "old", "after a recreate that failed with "+err.Error())
		t.Fatalf("an Operator's rolling recreate of a legacy host-path ISO VM, with an emptier host beside it: %v (the other host was asked %d time(s))", err, owner.creates)
	}
	if rec := vmExists(t, s, "old", "after the recreate"); rec.HostName != s.hostName || owner.creates != 0 {
		t.Fatalf("the recreate re-created the VM on %q (the other host was asked %d time(s)), want %q", rec.HostName, owner.creates, s.hostName)
	}
}

// When this host cannot take the VM back (here: it is in maintenance), the
// rebuild and the recreate are refused before anything is torn down.
func TestISOFinal_ARebuildThatCannotStayIsRefusedBeforeTheTeardown(t *testing.T) {
	for _, via := range []string{"rebuild", "recreate"} {
		t.Run(via, func(t *testing.T) {
			s, fake, owner, op := rebuildAcrossHosts(t)
			if err := s.db.Execute(context.Background(), `UPDATE hosts SET state = 'maintenance' WHERE name = ?`, s.hostName); err != nil {
				t.Fatal(err)
			}
			before := fake.DefinedXML("old")
			var err error
			if via == "rebuild" {
				_, err = s.RebuildVM(op, &pb.RebuildVMRequest{Name: "old"})
			} else {
				err = (&serverOps{s: s}).RecreateVM(op, "old", vmSpecFor(vmExists(t, s, "old", "before")))
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("%s pinned to a host in maintenance: got %v, want FailedPrecondition", via, err)
			}
			vmExists(t, s, "old", "after the refused "+via)
			if fake.DefinedXML("old") != before || before == "" || owner.creates != 0 {
				t.Fatalf("the refused %s changed the VM's domain or asked the other host (%d)", via, owner.creates)
			}
		})
	}
}

// A running VM that fills most of its host is rebuilt in place: the pinned
// check releases what the VM holds there (it is torn down first) rather than
// counting it twice and refusing.
func TestISOFinal_ARunningVMFillingItsHostIsRebuiltInPlace(t *testing.T) {
	s, _, owner, op := rebuildAcrossHosts(t)
	ctx := context.Background()
	spec := vmSpecFor(vmRecord(t, s, "old"))
	spec.Cpu = 3
	b, _ := json.Marshal(spec)
	// 1 core x 4 overcommit - 1 reserved = 3 vCPU: one 3-vCPU VM fits, two do not.
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ?, state = 'running', cpu_actual = 3, mem_actual = 512 WHERE name = ?`, string(b), "old"); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET cpu_total = 1 WHERE name = ?`, s.hostName); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildVM(op, &pb.RebuildVMRequest{Name: "old"}); err != nil {
		t.Fatalf("rebuilding a running VM that fills its host: %v", err)
	}
	if rec := vmExists(t, s, "old", "after the rebuild"); rec.HostName != s.hostName || owner.creates != 0 {
		t.Fatalf("rebuilt on %q (other host asked %d time(s)), want %q", rec.HostName, owner.creates, s.hostName)
	}
}

// A spec pinned to another host (a VM migrated off its pin) cannot be
// re-created where its ISO was judged: refused before the teardown.
func TestISOFinal_ARebuildPinnedElsewhereIsRefusedBeforeTheTeardown(t *testing.T) {
	s, fake, owner, op := rebuildAcrossHosts(t)
	spec := vmSpecFor(vmRecord(t, s, "old"))
	spec.Placement = &pb.PlacementSpec{Host: "host-b"}
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = ?`, string(b), "old"); err != nil {
		t.Fatal(err)
	}
	before := fake.DefinedXML("old")
	_, err := s.RebuildVM(op, &pb.RebuildVMRequest{Name: "old"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rebuild of an ISO VM pinned to another host: got %v, want FailedPrecondition", err)
	}
	vmExists(t, s, "old", "after the refused rebuild")
	if fake.DefinedXML("old") != before || owner.creates != 0 {
		t.Fatalf("the refused rebuild changed the domain or asked the other host (%d)", owner.creates)
	}
}
