package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// runningNoDomainServer is VM "a", recorded running on this host with one
// local disk, and no domain here (nor on any other host: there is none).
func runningNoDomainServer(t *testing.T) (*Server, *libvirtfake.Fake, string) {
	t.Helper()
	disk := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, fake := deleteDiskServerWith(t, false,
		corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: disk, StorageType: "local", DeleteWithVM: true})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'running' WHERE name = 'a'`); err != nil {
		t.Fatal(err)
	}
	return s, fake, disk
}

// assertNoDomainDeleteDidNothing checks that a refused no-domain delete left
// VM "a" as it was: its row live and running, its disk there.
func assertNoDomainDeleteDidNothing(t *testing.T, s *Server, disk string) {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, "a")
	if err != nil || vm == nil {
		t.Fatalf("the refused delete dropped the record: %+v (%v)", vm, err)
	}
	if vm.State != "running" {
		t.Errorf("the refused delete left the row %q; want it untouched (running)", vm.State)
	}
	if !exists(disk) {
		t.Error("the refused delete removed the disk")
	}
}

// A running row whose domain libvirt says is gone here, and no other host
// has, is recorded stopped before the cleanup acts; one libvirt cannot answer
// for (its state read fails) may still run here, so the delete refuses with
// nothing written: stopped over a live guest would never be synced back.
//
// Mutation: write the stop without asking libvirt — the "libvirt error"
// case goes red (the row says stopped).
func TestDeleteVM_ARunningRowWithNoDomainIsRecordedStoppedOnlyWhenLibvirtConfirmsIt(t *testing.T) {
	t.Run("libvirt confirms no domain", func(t *testing.T) {
		s, _, disk := runningNoDomainServer(t)
		var mu sync.Mutex
		var wrote []string
		s.stateWriteHook = func(name, state string) error {
			mu.Lock()
			defer mu.Unlock()
			wrote = append(wrote, name+"="+state)
			return nil
		}
		if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err != nil {
			t.Fatalf("DeleteVM: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if strings.Join(wrote, ",") != "a=stopped" {
			t.Errorf("state writes %v; want the stop recorded before the cleanup", wrote)
		}
		if exists(disk) {
			t.Error("the delete left the VM's disk")
		}
	})
	t.Run("libvirt error", func(t *testing.T) {
		s, fake, disk := runningNoDomainServer(t)
		fake.FailDomainState = func(string) error { return errors.New("injected: libvirt connection reset") }
		_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "nothing was done") {
			t.Fatalf("DeleteVM while libvirt cannot answer: %v; want Unavailable, nothing done", err)
		}
		assertNoDomainDeleteDidNothing(t, s, disk)
	})
}

// The stop of a running row with no domain is written before anything else
// the cleanup does; when that write fails, nothing is done: the row stays
// running and live, its disk stays, and no device or record is touched.
//
// Mutation: carry on past a failed stop write — red: the record is
// tombstoned and the disk removed.
func TestDeleteVM_AFailedStopWriteOnTheNoDomainPathDoesNothing(t *testing.T) {
	s, _, disk := runningNoDomainServer(t)
	s.stateWriteHook = func(name, state string) error { return errors.New("injected: store unavailable") }
	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil || !strings.Contains(err.Error(), "nothing was done") {
		t.Fatalf("DeleteVM with the stop write failing: %v; want a refusal that did nothing", err)
	}
	s.stateWriteHook = nil
	assertNoDomainDeleteDidNothing(t, s, disk)
}
