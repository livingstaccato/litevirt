package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestValidateSpecNICNetworks(t *testing.T) {
	for _, tc := range []struct {
		nets []string
		ok   bool
	}{
		{nil, true},
		{[]string{"a"}, true},
		{[]string{"a", "b"}, true},
		{[]string{"a", "b", "a"}, false},
		{[]string{"a", "a"}, false},
	} {
		spec := &pb.VMSpec{Name: "v"}
		for _, n := range tc.nets {
			spec.Network = append(spec.Network, &pb.NetworkAttachment{Name: n})
		}
		if err := validateSpecNICNetworks(spec); (err == nil) != tc.ok {
			t.Errorf("%v: %v, want ok=%v", tc.nets, err, tc.ok)
		}
	}
}

// TestCreateVM_TwoNICsOnOneNetworkRefusedBeforeDefine (lab 2, F-A): the NIC
// records of the second NIC would collide with the first's after the domain
// started; the create is refused as invalid before the domain is defined.
func TestCreateVM_TwoNICsOnOneNetworkRefusedBeforeDefine(t *testing.T) {
	s, fake := provableCreateServer(t)
	defined := false
	fake.FailDefineDomain = func(string) error { defined = true; return nil }
	req := disklessCreateRequest("dup")
	req.Spec.Network = append(req.Spec.Network, &pb.NetworkAttachment{Name: "lo", Model: "e1000"})
	_, err := s.CreateVM(adminCtx(), req)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "one NIC per network") {
		t.Errorf("CreateVM = %v; want InvalidArgument naming the rule", err)
	}
	if defined || fake.DomainExists("dup") {
		t.Error("the refused create defined a domain")
	}
}

// TestCreateVM_RecordWriteFailureUndoesTheCreate (lab 2, F-A): a create whose
// VM row cannot be written once its domain runs fails at the client with the
// write's error and leaves no domain behind — not "created" with a running
// domain that litevirt does not see, and a NotFound at the client.
func TestCreateVM_RecordWriteFailureUndoesTheCreate(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER vm_insert_fail BEFORE INSERT ON vms BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
	_, err := s.CreateVM(ctx, disklessCreateRequest("vm1"))
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "persist VM state") {
		t.Fatalf("CreateVM = %v; want Internal naming the failed write", err)
	}
	started := false
	for _, ev := range fake.EventLog() {
		started = started || (ev.Domain == "vm1" && ev.Op == "start")
	}
	if !started {
		t.Fatal("the domain never started, so the failure is not after the start")
	}
	if fake.DomainExists("vm1") {
		t.Error("the failed create left its domain defined")
	}
}

// TestCreateVM_StartFailureUndoesTheCreate: a domain that fails its first
// start is undefined.
func TestCreateVM_StartFailureUndoesTheCreate(t *testing.T) {
	s, fake := provableCreateServer(t)
	fake.FailStartDomain = func(string) error { return errors.New("boom") }
	_, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1"))
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "start domain") {
		t.Fatalf("CreateVM = %v; want Internal naming the failed start", err)
	}
	if fake.DomainExists("vm1") {
		t.Error("the failed create left its domain defined")
	}
	if row, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); row != nil {
		t.Errorf("the failed create wrote a row: %+v", row)
	}
}

// TestCreateVM_DomainThatCannotBeStoppedIsReported: when the failed create's
// domain cannot be stopped, it is left defined (its disks are not removed
// under a running guest) and the error says so.
func TestCreateVM_DomainThatCannotBeStoppedIsReported(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER vm_insert_fail BEFORE INSERT ON vms BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
	fake.FailDestroyDomain = func(string) error { return errors.New("destroy refused") }
	_, err := s.CreateVM(ctx, disklessCreateRequest("vm1"))
	if err == nil || !strings.Contains(err.Error(), "could not be stopped") || !strings.Contains(err.Error(), "persist VM state") {
		t.Fatalf("CreateVM = %v; want the failed write and the domain left behind, both named", err)
	}
	if !fake.DomainExists("vm1") {
		t.Error("a domain that could not be stopped was undefined under its running guest")
	}
}
