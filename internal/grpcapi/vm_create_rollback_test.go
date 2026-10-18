package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
// start is undefined. This characterises behaviour main already had (its
// start-failure path undefined the domain); the fleet subtest "start fails"
// is what proves the guard records go with it.
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

// failInsert makes every VM row insert on s fail.
func failInsert(t *testing.T, s *Server) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`CREATE TRIGGER vm_insert_fail BEFORE INSERT ON vms BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
}

// withDataDisk is req with a data disk, so the create makes a file.
func withDataDisk(req *pb.CreateVMRequest) *pb.CreateVMRequest {
	req.Spec.Disks = []*pb.DiskSpec{{Name: "data", Size: "64M"}}
	return req
}

// TestCreateVM_DomainThatCannotBeStoppedIsReported: when the failed create's
// domain cannot be stopped, it is left defined with its disks (they are not
// removed under a running guest) and the error says so.
func TestCreateVM_DomainThatCannotBeStoppedIsReported(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	failInsert(t, s)
	fake.FailDestroyDomain = func(string) error { return errors.New("destroy refused") }
	_, err := s.CreateVM(ctx, withDataDisk(disklessCreateRequest("vm1")))
	if err == nil || !strings.Contains(err.Error(), "could not be stopped") || !strings.Contains(err.Error(), "persist VM state") {
		t.Fatalf("CreateVM = %v; want the failed write and the domain left behind, both named", err)
	}
	if !fake.DomainExists("vm1") {
		t.Error("a domain that could not be stopped was undefined under its running guest")
	}
	if _, serr := os.Stat(s.images.DiskPath("vm1", "data")); serr != nil {
		t.Errorf("the disk of a guest still running was removed: %v", serr)
	}
}

// TestCreateVM_AnUndefineFailureIsReported (review M3): a stopped domain the
// abort could not undefine is named in the error.
func TestCreateVM_AnUndefineFailureIsReported(t *testing.T) {
	s, fake := provableCreateServer(t)
	failInsert(t, s)
	fake.FailUndefineDomain = func(string, bool) error { return errors.New("undefine refused") }
	fake.FailUndefinePreserv = func(string) error { return errors.New("undefine refused") }
	_, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1"))
	if err == nil || !strings.Contains(err.Error(), "left defined") {
		t.Fatalf("CreateVM = %v; want the domain left defined named", err)
	}
}

// TestCreateVM_TheClientGivingUpAfterTheCommitGetsTheVM (review I1): once
// the row has committed, the create has happened; a caller context cancelled
// after that does not turn it into a failure.
func TestCreateVM_TheClientGivingUpAfterTheCommitGetsTheVM(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	s.SetCreateCommittedHook(func(string) error { cancel(); return nil })
	vm, err := s.CreateVM(ctx, disklessCreateRequest("vm1"))
	if err != nil || vm.GetName() != "vm1" {
		t.Fatalf("CreateVM = %v, %v; want the created VM", vm, err)
	}
	if !fake.DomainExists("vm1") {
		t.Error("the created VM's domain is gone")
	}
}

// TestCreateVM_AFailedCreateKeepsFirmwareStateItDidNotMake (review I2): UEFI
// vars and the retained-firmware marker a `delete --keep-disks` left under
// the name survive a failed create of the name. A Secure Boot create is
// refused before anything with the vars there; with only the marker, its
// failure removes the vars it made and keeps the marker.
func TestCreateVM_AFailedCreateKeepsFirmwareStateItDidNotMake(t *testing.T) {
	kept := func(t *testing.T, s *Server, name string, vars bool) {
		t.Helper()
		if vars {
			p := lv.NvramPath(s.dataDir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("kept vars"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.fw().WriteRetainedFirmwareMarker(name, "kept-uuid"); err != nil {
			t.Fatal(err)
		}
	}
	survives := func(t *testing.T, s *Server, name string, vars bool) {
		t.Helper()
		if vars && !s.fw().HasNvram(name) {
			t.Error("the kept UEFI vars were removed")
		}
		if u, ok := s.fw().ReadRetainedFirmwareMarker(name); !ok || u != "kept-uuid" {
			t.Errorf("the retained-firmware marker = %q, %v; want it kept", u, ok)
		}
	}
	for _, failAt := range []string{"start", "insert"} {
		t.Run("plain/"+failAt, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			kept(t, s, "win", true)
			if failAt == "start" {
				fake.FailStartDomain = func(string) error { return errors.New("boom") }
			} else {
				failInsert(t, s)
			}
			if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("win")); err == nil {
				t.Fatal("the create succeeded with the failure injected")
			}
			survives(t, s, "win", true)
		})
	}
	t.Run("secure boot, kept vars", func(t *testing.T) {
		s, fake := provableCreateServer(t)
		sbHost(t, s)
		kept(t, s, "win", true)
		req := disklessCreateRequest("win")
		req.Spec.Firmware, req.Spec.SecureBoot = "uefi", true
		if _, err := s.CreateVM(adminCtx(), req); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("CreateVM = %v; want the kept vars refusing it", err)
		}
		if fake.DomainExists("win") {
			t.Error("a domain was defined over kept vars")
		}
		survives(t, s, "win", true)
	})
	t.Run("secure boot, kept marker only", func(t *testing.T) {
		s, fake := provableCreateServer(t)
		sbHost(t, s)
		kept(t, s, "win", false)
		// libvirt makes the vars from the template at the first start.
		fake.FailStartDomain = func(name string) error {
			return os.WriteFile(lv.NvramPath(s.dataDir, name), []byte("new vars"), 0o600)
		}
		failInsert(t, s)
		req := disklessCreateRequest("win")
		req.Spec.Firmware, req.Spec.SecureBoot = "uefi", true
		if _, err := s.CreateVM(adminCtx(), req); err == nil {
			t.Fatal("the create succeeded with the failure injected")
		}
		survives(t, s, "win", false)
		if s.fw().HasNvram("win") {
			t.Error("the vars this failed create made were left behind")
		}
	})
}

// sbHost makes s's host one a Secure Boot VM is placed on.
func sbHost(t *testing.T, s *Server) {
	t.Helper()
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	if err := corrosion.SetHostLabel(context.Background(), s.db, "test-host", corrosion.LabelSecureBootCapable, "true"); err != nil {
		t.Fatal(err)
	}
}

// TestCreateVM_AbortLeavesAnotherIncarnationsDomain (review M1): a failed
// create whose name's domain is no longer the one it defined (a concurrent
// create of the name replaced it) touches neither that domain nor the disks.
func TestCreateVM_AbortLeavesAnotherIncarnationsDomain(t *testing.T) {
	s, fake := provableCreateServer(t)
	failInsert(t, s)
	const other = "00000000-0000-4000-8000-0000000000aa"
	fake.FailStartDomain = func(name string) error {
		x, err := fake.DumpXMLInactive(name)
		if err != nil {
			return err
		}
		own := domainUUIDFromXML(x)
		if err := fake.UndefineDomain(name, false); err != nil {
			return err
		}
		return fake.DefineDomain(strings.Replace(x, own, other, 1))
	}
	_, err := s.CreateVM(adminCtx(), withDataDisk(disklessCreateRequest("vm1")))
	if err == nil || !strings.Contains(err.Error(), "persist VM state") {
		t.Fatalf("CreateVM = %v; want the failed write", err)
	}
	if !fake.DomainExists("vm1") {
		t.Fatal("the abort removed another incarnation's domain")
	}
	if x, _ := fake.DumpXMLInactive("vm1"); domainUUIDFromXML(x) != other {
		t.Errorf("the domain left is not the other incarnation's: %s", domainUUIDFromXML(x))
	}
	if _, serr := os.Stat(s.images.DiskPath("vm1", "data")); serr != nil {
		t.Errorf("the abort removed disks another incarnation may use: %v", serr)
	}
}
