package grpcapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A rebuild stops the VM's domain whenever libvirt says it runs, not only
// when the row says "running": a row still "creating" or behind an
// out-of-band start names a running guest too. Undefining that one left a
// transient qemu on the disks the rebuild deletes, with no record, and the
// create then refused to replace it (dupcreate review I-1). A domain that
// cannot be stopped refuses the rebuild with the VM as it was.
//
// Mutation: stop only when the row says running — the domain is undefined
// while it runs, red.
func TestRebuildVM_StopsAnActiveDomainWhateverItsRowSays(t *testing.T) {
	for _, state := range []string{"creating", "stopped"} {
		t.Run(state, func(t *testing.T) {
			stageGenisoimage(t)
			s, fake, _ := isoServer(t)
			const name = "rb1"
			if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			if err := s.db.Execute(context.Background(), `UPDATE vms SET state = ? WHERE name = ?`, state, name); err != nil {
				t.Fatal(err)
			}
			undefinedActive := false
			fake.FailUndefineDomain = func(n string, _ bool) error {
				if active, _ := fake.DomainIsActive(n); active {
					undefinedActive = true
				}
				return nil
			}
			if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name}); err != nil {
				t.Fatalf("RebuildVM: %v", err)
			}
			if undefinedActive {
				t.Error("the rebuild undefined the VM's domain while it ran")
			}
			row, err := corrosion.GetVM(adminCtx(), s.db, name)
			if err != nil || row == nil {
				t.Fatalf("the rebuilt VM's row: %v %v", row, err)
			}
			x, xerr := fake.DumpXMLInactive(name)
			if u := domainUUIDFromXML(x); xerr != nil || u == "" || !strings.Contains(row.Spec, u) {
				t.Errorf("the rebuilt VM's domain (%v) is not the persistent one its row records", xerr)
			}
		})
	}
}

func TestRebuildVM_ADomainThatCannotBeStoppedRefusesTheRebuild(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "rb2"
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = ?`, name); err != nil {
		t.Fatal(err)
	}
	before, _ := corrosion.GetVM(adminCtx(), s.db, name)
	disks, _ := corrosion.GetVMDisks(adminCtx(), s.db, name)
	fake.FailDestroyDomain = func(string) error { return errors.New("injected: destroy refused") }
	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("rebuild over a domain that cannot be stopped: %v, want FailedPrecondition, nothing was changed", err)
	}
	if u, _ := undefinesOf(fake, name); u != 0 {
		t.Errorf("the refused rebuild undefined the domain %d times", u)
	}
	if active, _ := fake.DomainIsActive(name); !active {
		t.Error("the refused rebuild's VM no longer runs")
	}
	row, _ := corrosion.GetVM(adminCtx(), s.db, name)
	if row == nil || row.Spec != before.Spec {
		t.Error("the refused rebuild changed or removed the VM's row")
	}
	for _, d := range disks {
		if _, err := os.Stat(d.Path); err != nil {
			t.Errorf("the refused rebuild removed disk %s: %v", d.Path, err)
		}
	}
}
