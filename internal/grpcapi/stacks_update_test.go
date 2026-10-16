package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A compose update applies a hooks change as a spec patch now, not through
// CreateVM — and defining a hook still needs admin (hooks run as root on the
// host), so an operator's deploy cannot change one.
func TestApplyLiveMetadata_HooksNeedAdmin(t *testing.T) {
	s := testServerWithLocks(t)
	insertTestVM(t, context.Background(), s.db, "web", "test-host", "running")
	desired := &pb.VMSpec{Hooks: &pb.HooksSpec{PreStart: "touch /tmp/x"}}

	operator := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")
	err := s.applyLiveMetadata(operator, "web", desired, []string{"hooks"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator changing hooks: err=%v, want PermissionDenied", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm != nil && vmHooks(vm) != nil {
		t.Errorf("hooks were written despite the refusal")
	}

	if err := s.applyLiveMetadata(adminCtx(), "web", desired, []string{"hooks"}); err != nil {
		t.Fatalf("admin changing hooks: %v", err)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	if vm == nil || vmHooks(vm).GetPreStart() != "touch /tmp/x" {
		t.Errorf("admin's hooks change was not applied: %+v", vm)
	}
}

// F2 (lab 2): a compose update that changes migrate.on-host-failure on an
// existing VM is applied in place, and must store the policy where the
// failover coordinator reads it — the spec's top-level on_host_failure, the
// same shape a create stores, which is also what an older peer reads. It
// stored only the migrate block: restart-any is that block's zero value, so
// `lv inspect` showed `migrate: {}` and failover skipped the VM as "none".
//
// Mutation: drop the on_host_failure copy from applyLiveMetadata's "migrate"
// case — every arm goes red (the policy stays as created).
func TestApplyUpdateKeepingVM_StoresTheHostFailurePolicy(t *testing.T) {
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{}}
	build := func(policy string) *pb.VMSpec {
		spec, err := compose.BuildVMSpec("web", "web", &compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512,
			Migrate: &compose.MigrateDef{OnHostFailure: policy, Priority: 7}}, f)
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	for _, c := range []struct{ from, to string }{
		{"none", "restart-any"},
		{"none", "restart-same"},
		{"restart-any", "none"},
		{"restart-same", "restart-any"},
	} {
		t.Run(c.from+"->"+c.to, func(t *testing.T) {
			s := testServerWithLocks(t)
			ctx := context.Background()
			stored := build(c.from)
			stored.Uuid = "u-1"
			blob, _ := json.Marshal(stored)
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", StackName: "st", HostName: s.hostName,
				State: "running", Spec: string(blob)}, nil, nil); err != nil {
				t.Fatal(err)
			}
			rec, _ := corrosion.GetVM(ctx, s.db, "web")
			read := &pb.VMSpec{}
			if err := json.Unmarshal([]byte(rec.Spec), read); err != nil {
				t.Fatal(err)
			}
			desired := build(c.to)
			plan := compose.Classify(desired, read, compose.StoredDisksFromSpec(read))
			if plan.Max() != compose.ActionLive {
				t.Fatalf("plan %v (%s), want a live update", plan.Max(), plan.Reasons())
			}
			if err := s.applyUpdateKeepingVM(adminCtx(), "web", desired, plan, plan.Max()); err != nil {
				t.Fatalf("apply: %v", err)
			}
			rec, _ = corrosion.GetVM(ctx, s.db, "web")
			if got := corrosion.VMFailurePolicy(*rec); got != c.to {
				t.Fatalf("stored on_host_failure = %q after the update, want %q (spec %s)", got, c.to, rec.Spec)
			}
			if want := c.to != "none"; corrosion.VMRecoverableOnHostFailure(*rec, false) != want {
				t.Errorf("recoverable on host failure = %v, want %v", !want, want)
			}
			after := &pb.VMSpec{}
			if err := json.Unmarshal([]byte(rec.Spec), after); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(after.Migrate, desired.Migrate) || after.Uuid != "u-1" {
				t.Errorf("stored migrate %v uuid %q, want %v and the uuid kept", after.Migrate, after.Uuid, desired.Migrate)
			}
			// Applied, the file now plans as no change.
			if again := compose.Classify(desired, after, compose.StoredDisksFromSpec(after)); again.Max() != compose.ActionNoChange {
				t.Errorf("redeploying the same file plans %v (%s), want no change", again.Max(), again.Reasons())
			}
		})
	}
}
