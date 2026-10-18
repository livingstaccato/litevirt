package grpcapi

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// undefinesOf counts the fake's undefine and destroy events of domain name.
func undefinesOf(fake *libvirtfake.Fake, name string) (undefines, destroys int) {
	for _, e := range fake.EventLog() {
		if e.Domain != name {
			continue
		}
		switch e.Op {
		case "undefine":
			undefines++
		case "destroy":
			destroys++
		}
	}
	return undefines, destroys
}

// Lab 2 delcancel r5, item 4 (rc-1..3): a `compose up` killed mid re-create
// and run again at once put two CreateVMs of one name on the owner. The
// second's orphan sweep took the first's domain, not yet recorded, for the
// leftover of an incomplete delete and undefined it; its debris sweep removed
// the first's disk; its failed-create cleanup removed the files at the name's
// paths. The first create still finished: one qemu, one row, a transient
// domain whose disk and seed were unlinked, lost at the next stop.
//
// The second create of a name while one is in flight on its host is refused
// with an error that says so, and touches nothing: the first keeps its
// domain, defined and running, and the disk and seed it made.
//
// Mutations (each red):
//   - drop the in-flight refusal (beginCreate): "held before its define" goes
//     red (the second's debris sweep removes the first's disk); once the
//     first's domain is defined it stays whole through the orphan sweep's own
//     refusal (liveCreateDefined);
//   - drop it AND the sweep's live-create/running refusals: the first's domain
//     is undefined and its disk removed or replaced.
func TestCreateVM_ASecondCreateOfTheNameWhileOneIsInFlightIsRefusedAndTouchesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		// hold installs the hook that runs the second create while the
		// first is between its define and its row.
		hold func(fake *libvirtfake.Fake, second func())
		// defined: the first's domain is defined at the hold.
		defined bool
	}{
		// Before the define nothing of the first is in libvirt, so only the
		// in-flight refusal can tell the second there is a create.
		{"held before its define", func(fake *libvirtfake.Fake, second func()) {
			var first atomic.Bool
			fake.FailDefineDomain = func(string) error {
				if first.CompareAndSwap(false, true) {
					second()
				}
				return nil
			}
		}, false},
		{"held before its start", func(fake *libvirtfake.Fake, second func()) {
			var first atomic.Bool
			fake.FailStartDomain = func(string) error {
				if first.CompareAndSwap(false, true) {
					second()
				}
				return nil
			}
		}, true},
		{"held once it runs", func(fake *libvirtfake.Fake, second func()) {
			var first atomic.Bool
			fake.OnRunning = func(string) {
				if first.CompareAndSwap(false, true) {
					second()
				}
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageGenisoimage(t)
			s, fake, _ := isoServer(t)
			const name = "ug1"
			disk := s.images.DiskPath(name, "root")
			seed := lv.CloudInitISOPath(s.dataDir, name)

			var (
				ran                   bool
				secondErr             error
				diskFirst, seedFirst  os.FileInfo
				domainUUIDAtHold      string
				diskStatErr, seedStat error
			)
			tc.hold(fake, func() {
				ran = true
				diskFirst, diskStatErr = os.Stat(disk)
				seedFirst, seedStat = os.Stat(seed)
				if x, err := fake.DumpXMLInactive(name); err == nil {
					domainUUIDAtHold = domainUUIDFromXML(x)
				}
				_, secondErr = s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "#cloud-config\npassword: second\n"))
			})
			out, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "#cloud-config\npassword: first\n"))
			if !ran {
				t.Fatal("setup: the second create never ran inside the first")
			}
			if diskStatErr != nil || seedStat != nil || tc.defined != (domainUUIDAtHold != "") {
				t.Fatalf("setup: at the hold the first create had no disk (%v), seed (%v) or domain (%q)",
					diskStatErr, seedStat, domainUUIDAtHold)
			}

			// The second is refused, and says why.
			if secondErr == nil {
				t.Error("the second create of the name succeeded while the first was in flight")
			} else {
				if c := status.Code(secondErr); c != codes.Aborted {
					t.Errorf("the second create's code = %v, want Aborted: %v", c, secondErr)
				}
				if !strings.Contains(secondErr.Error(), "in progress") {
					t.Errorf("the second create's error does not say a create is in progress: %v", secondErr)
				}
			}

			// The first is whole.
			if err != nil {
				t.Fatalf("the first create failed: %v", err)
			}
			if out.GetName() != name {
				t.Fatalf("the first create answered %v", out)
			}
			row, rerr := corrosion.GetVM(adminCtx(), s.db, name)
			if rerr != nil || row == nil {
				t.Fatalf("the first create's row: %v %v", row, rerr)
			}
			if u, d := undefinesOf(fake, name); u != 0 || d != 0 {
				t.Errorf("the first create's domain was undefined %d and destroyed %d times by the second create", u, d)
			}
			if active, aerr := fake.DomainIsActive(name); aerr != nil || !active {
				t.Errorf("the first create's domain is not running: %v %v", active, aerr)
			}
			x, xerr := fake.DumpXMLInactive(name)
			if xerr != nil {
				t.Errorf("the first create's domain has no persistent definition: %v", xerr)
			} else if u := domainUUIDFromXML(x); tc.defined && u != domainUUIDAtHold {
				t.Errorf("the domain of %s is %s, not the first create's %s", name, u, domainUUIDAtHold)
			} else if u == "" || !strings.Contains(row.Spec, u) {
				t.Errorf("the domain of %s (uuid %q) is not the one its row records", name, u)
			}
			if fi, serr := os.Stat(disk); serr != nil || !os.SameFile(fi, diskFirst) {
				t.Errorf("the first create's disk %s was removed or replaced (err=%v)", disk, serr)
			}
			if fi, serr := os.Stat(seed); serr != nil || !os.SameFile(fi, seedFirst) {
				t.Errorf("the first create's seed %s was removed or replaced (err=%v)", seed, serr)
			}

			// Once the first has returned, a create of the name is refused
			// for the VM it made, not for a create in flight.
			_, again := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, ""))
			if status.Code(again) != codes.AlreadyExists {
				t.Errorf("a create after the first returned: %v, want AlreadyExists", again)
			}
		})
	}
}

// The orphan sweep removes a domain of the name only when it is a leftover:
// stopped, and not one a create in flight defined. A RUNNING domain with no
// VM record is a guest, whatever left it there: the create is refused and the
// domain, its definition and its disk stay as they are. It used to be
// destroyed and undefined.
//
// Mutation: destroy a running leftover again — red.
func TestCreateVM_ARunningDomainOfTheNameWithNoRecordRefusesTheCreate(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name, uuid = "ug2", "11111111-2222-3333-4444-555555555555"
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>", name, uuid)); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain(name); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, ""))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "running") {
		t.Fatalf("create over a running domain with no record: %v, want FailedPrecondition naming it running", err)
	}
	if u, d := undefinesOf(fake, name); u != 0 || d != 0 {
		t.Errorf("the running domain was undefined %d and destroyed %d times", u, d)
	}
	if active, _ := fake.DomainIsActive(name); !active {
		t.Error("the running domain no longer runs")
	}
	if x, xerr := fake.DumpXMLInactive(name); xerr != nil || domainUUIDFromXML(x) != uuid {
		t.Errorf("the running domain lost its definition: %q %v", x, xerr)
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, name); row != nil {
		t.Error("a refused create wrote a row")
	}
}

// A stopped leftover with no record is still removed, and the create goes
// ahead: the sweep's narrowing above does not strand the case it exists for.
func TestCreateVM_AStoppedLeftoverDomainIsStillRemoved(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name, uuid = "ug3", "11111111-2222-3333-4444-666666666666"
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>", name, uuid)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("create over a stopped leftover: %v", err)
	}
	x, err := fake.DumpXMLInactive(name)
	if err != nil || domainUUIDFromXML(x) == uuid {
		t.Errorf("the leftover was not replaced: %v", err)
	}
}

// A failed create removes a disk only when the file at its path is still the
// one it made: by then another may be there, and that is not this create's to
// remove (lab 2 delcancel r5: a failed create's cleanup unlinked the disk a
// running qemu had open).
//
// Mutation: remove by path alone — the other file goes, red.
func TestCreateVM_AFailedCreateLeavesADiskItDidNotMake(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "ug4"
	disk := s.images.DiskPath(name, "root")
	fake.FailStartDomain = func(string) error {
		if err := os.Remove(disk); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(disk, []byte("another's disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		return errors.New("start failed")
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if b, err := os.ReadFile(disk); err != nil || string(b) != "another's disk" {
		t.Errorf("the failed create removed a disk it did not make: %q %v", b, err)
	}
	// The plain case still cleans up.
	fake.FailStartDomain = func(string) error { return errors.New("start failed") }
	const name2 = "ug5"
	disk2 := s.images.DiskPath(name2, "root")
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name2, "")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if _, err := os.Lstat(disk2); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a failed create left the disk it made: %v", err)
	}
}

// A failed create leaves a disk a domain of the name it did not define names,
// even one it made itself: by then that domain's guest may have it open.
//
// Mutation: drop the foreign-domain check from the cleanup — the disk goes,
// red.
func TestCreateVM_AFailedCreateLeavesADiskAnotherDomainOfTheNameNames(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "ug6"
	disk := s.images.DiskPath(name, "root")
	fake.FailDefineDomain = func(string) error {
		fake.FailDefineDomain = nil
		if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>",
			name, "11111111-2222-3333-4444-777777777777")); err != nil {
			t.Fatal(err)
		}
		fake.SetDiskSource(name, "vda", disk)
		return errors.New("operation failed: domain '" + name + "' already exists")
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err == nil {
		t.Fatal("the create was meant to fail at its define")
	}
	if _, err := os.Stat(disk); err != nil {
		t.Errorf("the failed create removed the disk another domain of the name names: %v", err)
	}
}
