package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// vmExists fails the test when the VM's row or its domain is gone.
func vmExists(t *testing.T, s *Server, name, what string) *corrosion.VMRecord {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || rec == nil {
		t.Fatalf("%s: VM %q is gone (%v)", what, name, err)
	}
	return rec
}

// C-3: a VM made on main with a host-path ISO keeps starting on this build
// (a legacy spec is a host path, judged in full at every start). An Operator
// rebuilding it gets it back, with that ISO, as on main — the rebuild does
// not refuse it for want of an Admin's authority after the teardown.
//
// Mutation: drop the recreateISOGrant from RebuildVM — the create is refused
// PermissionDenied and the test goes red.
func TestISOFinal_AnOperatorRebuildsALegacyHostPathISOVM(t *testing.T) {
	s, fake, _ := isoServer(t)
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))
	legacyVM(t, s, fake, "old", iso)
	op := userCtx("op", "operator")
	if _, err := s.RebuildVM(op, &pb.RebuildVMRequest{Name: "old"}); err != nil {
		t.Fatalf("an operator's rebuild of a legacy host-path ISO VM: %v", err)
	}
	rec := vmExists(t, s, "old", "after the rebuild")
	if spec := vmSpecFor(rec); spec.GetIso() != iso || spec.GetIsoScope() != "" {
		t.Fatalf("the rebuilt VM's ISO = %q (scope %q), want %q as it was (legacy)", spec.GetIso(), spec.GetIsoScope(), iso)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), rec); err != nil {
		t.Fatalf("start of the rebuilt VM: %v", err)
	}
}

// C-3, red: a VM whose stored ISO is now refused (it names the host key) is
// not torn down by a rebuild that cannot create it again; the refusal comes
// first and the VM is left as it was.
//
// Mutation: drop recreatePreflight from RebuildVM — the VM is gone after the
// refusal and the test goes red.
func TestISOFinal_ARebuildWithARefusedISOLeavesTheVM(t *testing.T) {
	s, fake, key := isoServer(t)
	legacyVM(t, s, fake, "old", key)
	before := fake.DefinedXML("old")
	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "old"})
	if err == nil {
		t.Fatal("a rebuild with the host key as its ISO was not refused")
	}
	vmExists(t, s, "old", "after the refused rebuild")
	if fake.DefinedXML("old") != before || before == "" {
		t.Fatal("the refused rebuild changed or removed the VM's domain")
	}
}

// C-3, rolling: a recreate-class rollout of a legacy host-path ISO VM by an
// Operator recreates it with that ISO; one whose ISO is now refused is
// refused before the delete, and the VM stays.
//
// Mutation: drop the grant from recreateAs — the first leg goes red; drop the
// preflight — the second.
func TestISOFinal_ARollingRecreateKeepsTheVMsISO(t *testing.T) {
	s, fake, key := isoServer(t)
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))
	legacyVM(t, s, fake, "web", iso)
	op := userCtx("op", "operator")
	ops := &serverOps{s: s}
	desired := vmSpecFor(vmExists(t, s, "web", "before"))
	if err := ops.RecreateVM(op, "web", desired); err != nil {
		t.Fatalf("an operator's rolling recreate of a legacy host-path ISO VM: %v", err)
	}
	if spec := vmSpecFor(vmExists(t, s, "web", "after the recreate")); spec.GetIso() != iso {
		t.Fatalf("the recreated VM's ISO = %q, want %q", spec.GetIso(), iso)
	}

	legacyVM(t, s, fake, "bad", key)
	desired = vmSpecFor(vmExists(t, s, "bad", "before"))
	err := ops.RecreateVM(adminCtx(), "bad", desired)
	if err == nil {
		t.Fatal("a rolling recreate with the host key as its ISO was not refused")
	}
	if c := status.Code(err); c == codes.OK || c == codes.Unknown {
		t.Errorf("refusal carries no status code: %v", err)
	}
	vmExists(t, s, "bad", "after the refused recreate")
}
