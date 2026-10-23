package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// TestCreateVM_AGuestThatCannotBeStoppedKeepsItsDeviceAcrossARestart
// (re-review N1): a failed create whose guest could not be stopped leaves no
// device lease for startup recovery to roll back, so a restart does not
// unbind the device from the guest still running on it, nor release it.
func TestCreateVM_AGuestThatCannotBeStoppedKeepsItsDeviceAcrossARestart(t *testing.T) {
	const bdf = "0000:41:00.0"
	s := pciProducerServer(t)
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	seedPCIGPU(t, s, bdf, -1)
	failInsert(t, s)
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailDestroyDomain = func(string) error { return errors.New("destroy refused") }

	if err := createVMWithBDF(ctx, s, "gpu1", bdf); err == nil || !strings.Contains(err.Error(), "could not be stopped") {
		t.Fatalf("CreateVM = %v; want the guest left running named", err)
	}
	if !fake.DomainExists("gpu1") {
		t.Fatal("the guest that could not be stopped was undefined")
	}
	// The daemon restarts: startup recovery runs over the journal.
	s.RecoverDeviceLeases(context.Background())
	if o := pciOwnerOf(t, ctx, s, bdf); o != "gpu1" {
		t.Errorf("after a restart the device of the still-running guest is owned by %q, want gpu1", o)
	}
}

// TestCreateVM_DefineFailureKeepsVarsItDidNotMake (re-review N3): a create
// whose define fails made no UEFI vars (libvirt writes them at the first
// start); vars at the name's path then are another create's, and are kept.
func TestCreateVM_DefineFailureKeepsVarsItDidNotMake(t *testing.T) {
	s, fake := provableCreateServer(t)
	sbHost(t, s)
	fake.FailDefineDomain = func(string) error {
		// A concurrent create of the name started in this create's window.
		p := lv.NvramPath(s.dataDir, "win")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte("their vars"), 0o600); err != nil {
			return err
		}
		return errors.New(`domain "win" already exists`)
	}
	req := disklessCreateRequest("win")
	req.Spec.Firmware, req.Spec.SecureBoot = "uefi", true
	if _, err := s.CreateVM(adminCtx(), req); err == nil || !strings.Contains(err.Error(), "define domain") {
		t.Fatalf("CreateVM = %v; want the define failure", err)
	}
	if !s.fw().HasNvram("win") {
		t.Error("a failed define removed UEFI vars it did not make")
	}
}

// TestCreateVM_ARecordGoneAfterTheCommitIsNotReportedRunning (re-review N4):
// a VM whose row is gone by the time the create reads it back is not
// reported as running.
func TestCreateVM_ARecordGoneAfterTheCommitIsNotReportedRunning(t *testing.T) {
	s, _ := provableCreateServer(t)
	s.SetCreateCommittedHook(func(name string) error {
		return s.db.Execute(context.Background(), `DELETE FROM vms WHERE name = ?`, name)
	})
	vm, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1"))
	if err == nil || !strings.Contains(err.Error(), "record is gone") {
		t.Fatalf("CreateVM = %v, %v; want the missing record named", vm, err)
	}
}

// TestCreateVM_AbortOfADomainThatVanishedOrIsUnreadable (re-review N5): a
// domain gone by the time the abort reads it is gone, not unreadable; an
// unreadable one, or one whose definition names no uuid, is left as it is.
func TestCreateVM_AbortOfADomainThatVanishedOrIsUnreadable(t *testing.T) {
	setup := func(t *testing.T) (*Server, *libvirtfake.Fake, *bool) {
		s, fake := provableCreateServer(t)
		armed := false
		fake.FailStartDomain = func(string) error { armed = true; return errors.New("boom") }
		return s, fake, &armed
	}
	t.Run("vanished", func(t *testing.T) {
		s, fake, armed := setup(t)
		fake.FailDumpXMLInactive = func(name string) error {
			if !*armed {
				return nil
			}
			_ = fake.UndefineDomain(name, false)
			return fmt.Errorf("libvirtfake: domain %q not found", name)
		}
		_, err := s.CreateVM(adminCtx(), withDataDisk(disklessCreateRequest("vm1")))
		if err == nil || strings.Contains(err.Error(), "could not be read") || !strings.Contains(err.Error(), "no longer exists") {
			t.Fatalf("CreateVM = %v; want the vanished domain named as gone", err)
		}
		if _, serr := os.Stat(s.images.DiskPath("vm1", "data")); serr != nil {
			t.Errorf("disks at this create's paths were removed though the domain on them is not proven its own: %v", serr)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		s, fake, armed := setup(t)
		fake.FailDumpXMLInactive = func(string) error {
			if *armed {
				return errors.New("connection reset")
			}
			return nil
		}
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1"))
		if err == nil || !strings.Contains(err.Error(), "could not be read") {
			t.Fatalf("CreateVM = %v; want the unreadable definition named", err)
		}
		if !fake.DomainExists("vm1") {
			t.Error("a domain whose definition could not be read was removed")
		}
	})
	t.Run("no uuid", func(t *testing.T) {
		s, fake := provableCreateServer(t)
		fake.FailStartDomain = func(name string) error {
			x, err := fake.DumpXMLInactive(name)
			if err != nil {
				return err
			}
			if err := fake.UndefineDomain(name, false); err != nil {
				return err
			}
			own := domainUUIDFromXML(x)
			// The fake gives a definition with no uuid one, as libvirt does;
			// a definition that reads back with none is what this models, so
			// the uuid is taken out as it is stored.
			fake.FillDefine = func(x string) string { return strings.Replace(x, "<uuid>"+own+"</uuid>", "", 1) }
			defer func() { fake.FillDefine = nil }()
			if err := fake.DefineDomain(x); err != nil {
				return err
			}
			return errors.New("boom")
		}
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1"))
		if err == nil || !strings.Contains(err.Error(), "could not be read") {
			t.Fatalf("CreateVM = %v; want a definition naming no uuid treated as unreadable", err)
		}
		if !fake.DomainExists("vm1") {
			t.Error("a domain whose uuid could not be read was removed")
		}
	})
}

// TestCreateVM_AFailedPlainUEFICreateRemovesOnlyItsOwnLibvirtVars
// (re-review N7): the libvirt-managed vars a failed plain UEFI create made at
// its first start are removed; vars that were at that path before it (kept by
// a delete --keep-disks) are set aside before the start, not removed. The domain is undefined keeping its
// firmware state, so libvirt never removes them itself.
func TestCreateVM_AFailedPlainUEFICreateRemovesOnlyItsOwnLibvirtVars(t *testing.T) {
	for _, keptBefore := range []bool{false, true} {
		t.Run(fmt.Sprintf("kept=%v", keptBefore), func(t *testing.T) {
			s, fake := provableCreateServer(t)
			vars := filepath.Join(t.TempDir(), "qemu-nvram", "vm1_VARS.fd")
			if err := os.MkdirAll(filepath.Dir(vars), 0o700); err != nil {
				t.Fatal(err)
			}
			if keptBefore {
				if err := os.WriteFile(vars, []byte("kept"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fake.FillDefine = func(x string) string {
				return strings.Replace(x, "</os>", "<nvram>"+vars+"</nvram></os>", 1)
			}
			fake.FailStartDomain = func(string) error {
				return os.WriteFile(vars, []byte("written at start"), 0o600)
			}
			failInsert(t, s)
			if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1")); err == nil {
				t.Fatal("the create succeeded with the failure injected")
			}
			_, serr := os.Stat(vars)
			if keptBefore {
				// Set aside before the start, so the new VM never boots from
				// them; the bytes stay beside the path.
				kept, _ := filepath.Glob(vars + ".superseded-*")
				if len(kept) != 1 {
					t.Fatalf("vars that were there before the create: set-aside copies = %v, want one", kept)
				}
				if b, _ := os.ReadFile(kept[0]); string(b) != "kept" {
					t.Errorf("the set-aside copy holds %q, want the kept vars", b)
				}
			}
			if serr == nil {
				t.Error("the vars this failed create made were left behind")
			}
			preserved := false
			for _, ev := range fake.EventLog() {
				preserved = preserved || (ev.Domain == "vm1" && ev.Op == "undefine" && strings.Contains(ev.Note, "keep_state=true"))
			}
			if !preserved {
				t.Error("the abort did not undefine the domain keeping its firmware state")
			}
		})
	}
}
