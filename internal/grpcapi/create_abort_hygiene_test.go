package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// keptDataDisk leaves what `lv rm --keep-disks` leaves on this host of VM
// name's data disk: the file at its path, noted as kept. It returns the path
// and the bytes the operator kept.
func keptDataDisk(t *testing.T, s *Server, name string) (string, []byte) {
	t.Helper()
	p := s.images.DiskPath(name, "data")
	if err := os.MkdirAll(filepath.Dir(p), 0o711); err != nil {
		t.Fatal(err)
	}
	b := []byte("what the operator kept of " + name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptDisks(s.dataDir, name, []string{p}); err != nil {
		t.Fatal(err)
	}
	return p, b
}

func keptCopiesOf(t *testing.T, p string) []string {
	t.Helper()
	m, err := filepath.Glob(p + ".kept-*")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range m {
		if !strings.HasSuffix(f, ".owner") && !strings.HasSuffix(f, ".stale") {
			out = append(out, f)
		}
	}
	return out
}

func assertFileIs(t *testing.T, p string, want []byte, what string) {
	t.Helper()
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s at %s = %q, %v; want %q", what, p, got, err, want)
	}
}

// A create the firmware refuses (Secure Boot over the UEFI vars a
// `delete --keep-disks` kept) is refused before it moves the kept disk at
// the path its data disk would take: the disk stays where its VM recorded
// it (lab 2, O2; 5c).
//
// Mutation: drop firmwarePreflight — the disk is moved to .kept- before the
// refusal, red.
func TestCreateVM_ARefusedCreateLeavesTheKeptDiskWhereItsVMRecordedIt(t *testing.T) {
	s, fake := provableCreateServer(t)
	sbHost(t, s)
	path, kept := keptDataDisk(t, s, "win")
	vars := lv.NvramPath(s.dataDir, "win")
	if err := os.MkdirAll(filepath.Dir(vars), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vars, []byte("kept vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := withDataDisk(disklessCreateRequest("win"))
	req.Spec.Firmware, req.Spec.SecureBoot = "uefi", true
	if _, err := s.CreateVM(adminCtx(), req); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "UEFI vars already exist") {
		t.Fatalf("CreateVM = %v; want the kept vars refusing it", err)
	}
	if fake.DomainExists("win") {
		t.Error("a domain was defined")
	}
	assertFileIs(t, path, kept, "the kept disk")
	if k := keptCopiesOf(t, path); len(k) != 0 {
		t.Errorf("the refused create moved the kept disk: %v", k)
	}
	// Moved and put back reads the same on disk; the events say it moved.
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, "win", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range evs {
		if ev.Type == "vm.disk.kept" {
			t.Errorf("the refused create moved the kept disk: %s", ev.Detail)
		}
	}
}

// A create that fails after it moved a kept disk off its path puts the disk
// back there, noted again, so the next create of the name moves it as the
// failed one did (lab 2, O2): whichever step failed.
//
// Mutation: drop the deferred restoreKeptAfterFailedCreate — the disk stays
// at .kept- and its path is empty, red; restore without noting it again —
// the successful create clears it as debris, red.
func TestCreateVM_AFailedCreatePutsTheKeptDiskBack(t *testing.T) {
	for _, failAt := range []string{"define", "start", "insert"} {
		t.Run(failAt, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			path, kept := keptDataDisk(t, s, "vm1")
			switch failAt {
			case "define":
				fake.FailDefineDomain = func(string) error { return errors.New("define refused") }
			case "start":
				fake.FailStartDomain = func(string) error { return errors.New("boom") }
			case "insert":
				failInsert(t, s)
			}
			if _, err := s.CreateVM(adminCtx(), withDataDisk(disklessCreateRequest("vm1"))); err == nil {
				t.Fatal("the create succeeded with the failure injected")
			}
			assertFileIs(t, path, kept, "the kept disk after the failed create")
			if k := keptCopiesOf(t, path); len(k) != 0 {
				t.Errorf("the kept disk is still set aside after the failed create: %v", k)
			}

			fake.FailDefineDomain, fake.FailStartDomain = nil, nil
			if failAt == "insert" {
				if err := s.db.Execute(context.Background(), `DROP TRIGGER vm_insert_fail`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.CreateVM(adminCtx(), withDataDisk(disklessCreateRequest("vm1"))); err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			k := keptCopiesOf(t, path)
			if len(k) != 1 {
				t.Fatalf("kept copies after a create that succeeded = %v; want the kept disk", k)
			}
			assertFileIs(t, k[0], kept, "the kept disk after a create that succeeded")
		})
	}
}

// tombstonedVM leaves a deleted VM of name whose spec uuid is u.
func tombstonedVM(t *testing.T, s *Server, name, u string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: "test-host", State: "stopped",
		Spec: `{"name":"` + name + `","uuid":"` + u + `"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, name); err != nil {
		t.Fatal(err)
	}
}

// writeSeed places a seed at name's path, stamped for owner ("" unstamped).
func writeSeed(t *testing.T, s *Server, name, owner string, b []byte) string {
	t.Helper()
	iso := lv.CloudInitISOPath(s.dataDir, name)
	if err := os.MkdirAll(filepath.Dir(iso), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iso, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.StampSeed(iso, owner); err != nil {
		t.Fatal(err)
	}
	return iso
}

// The cloud-init seed of a deleted VM the operator kept is never removed by
// another create of the name: a create that fails leaves it at its path,
// stamped as it was, and one that succeeds moves it to .kept- (lab 2, O3). A
// seed of anything else there is removed, as before.
//
// Mutation: remove the seed at the name's path unconditionally again — the
// failed create's subtest goes red.
func TestCreateVM_TheKeptVMsSeedIsNeverRemovedByAnotherCreate(t *testing.T) {
	const keptUUID = "00000000-0000-4000-8000-00000000c0de"
	t.Run("kept", func(t *testing.T) {
		stageGenisoimage(t)
		s, fake, _ := isoServer(t)
		tombstonedVM(t, s, "w", keptUUID)
		kept := []byte("the kept VM's seed")
		iso := writeSeed(t, s, "w", keptUUID, kept)

		fake.FailStartDomain = func(string) error { return errors.New("boom") }
		if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", "#cloud-config\n")); err == nil {
			t.Fatal("the create was meant to fail")
		}
		assertFileIs(t, iso, kept, "the kept seed after the failed create")
		if o, ok, _ := cloudinit.SeedOwner(iso); !ok || o != keptUUID {
			t.Errorf("the kept seed's stamp = %q, %v; want %s", o, ok, keptUUID)
		}

		fake.FailStartDomain = nil
		if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", "#cloud-config\n")); err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		k := keptCopiesOf(t, iso)
		if len(k) != 1 {
			t.Fatalf("kept seeds after a create that succeeded = %v; want the kept VM's", k)
		}
		assertFileIs(t, k[0], kept, "the kept seed after a create that succeeded")
		if o, ok, _ := cloudinit.SeedOwner(k[0]); !ok || o != keptUUID {
			t.Errorf("the set-aside seed's stamp = %q, %v; want %s", o, ok, keptUUID)
		}
		if b, _ := os.ReadFile(iso); bytes.Equal(b, kept) {
			t.Error("the new VM runs on the kept VM's seed")
		}
	})
	t.Run("another's", func(t *testing.T) {
		stageGenisoimage(t)
		s, fake, _ := isoServer(t)
		tombstonedVM(t, s, "w", keptUUID)
		iso := writeSeed(t, s, "w", "00000000-0000-4000-8000-0000000000ff", []byte("a failed create's"))
		fake.FailStartDomain = func(string) error { return errors.New("boom") }
		if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", "#cloud-config\n")); err == nil {
			t.Fatal("the create was meant to fail")
		}
		if _, err := os.Lstat(iso); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a seed no kept VM owns is left at %s: %v", iso, err)
		}
		if k := keptCopiesOf(t, iso); len(k) != 0 {
			t.Errorf("a seed no kept VM owns was set aside: %v", k)
		}
	})
}

// A failed create removes what it made at its name's paths while its domain
// is still defined, then undefines it: a concurrent create of the name that
// starts once the domain is gone makes its own disk and vars at those paths,
// and the abort does not remove them (re-review N8).
//
// Mutation: undefine before the removals, as before — the other create's
// disk and vars are removed, red.
func TestCreateVM_TheAbortRemovesItsFilesBeforeItUndefines(t *testing.T) {
	s, fake := provableCreateServer(t)
	vars := filepath.Join(t.TempDir(), "qemu-nvram", "vm1_VARS.fd")
	if err := os.MkdirAll(filepath.Dir(vars), 0o700); err != nil {
		t.Fatal(err)
	}
	fake.FillDefine = func(x string) string {
		return strings.Replace(x, "</os>", "<nvram>"+vars+"</nvram></os>", 1)
	}
	fake.FailStartDomain = func(string) error {
		return os.WriteFile(vars, []byte("this create's vars"), 0o600)
	}
	failInsert(t, s)
	disk := s.images.DiskPath("vm1", "data")
	theirs := []byte("the other create's")
	fake.OnUndefined = func(string) {
		// Another create of vm1: its debris pass clears the path, and it
		// makes its own disk and vars there.
		for _, p := range []string{disk, vars} {
			_ = os.Remove(p)
			if err := os.WriteFile(p, theirs, 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	if _, err := s.CreateVM(adminCtx(), withDataDisk(disklessCreateRequest("vm1"))); err == nil {
		t.Fatal("the create succeeded with the failure injected")
	}
	assertFileIs(t, disk, theirs, "the other create's disk")
	assertFileIs(t, vars, theirs, "the other create's vars")
}

// A failed create whose domain vanished removes the seed it placed (it holds
// the user-data), as its other aborts do: removing it is guarded by the
// file's identity (re-review N10).
//
// Mutation: drop removeSeed from gone() — the seed stays, red.
func TestCreateVM_AnAbortOfAVanishedDomainRemovesItsSeed(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	armed := false
	fake.FailStartDomain = func(string) error { armed = true; return errors.New("boom") }
	fake.FailDumpXMLInactive = func(name string) error {
		if !armed {
			return nil
		}
		_ = fake.UndefineDomain(name, false)
		return fmt.Errorf("libvirtfake: domain %q not found", name)
	}
	_, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", "#cloud-config\npassword: hunter2\n"))
	if err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("CreateVM = %v; want the vanished domain named", err)
	}
	if _, serr := os.Lstat(lv.CloudInitISOPath(s.dataDir, "w")); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("the seed of the failed create is left: %v", serr)
	}
}

// createLogs collects the records createVM logs at WARN and above.
type createLogs struct {
	mu   sync.Mutex
	recs []map[string]string
}

func (h *createLogs) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelWarn }
func (h *createLogs) Handle(_ context.Context, r slog.Record) error {
	m := map[string]string{"msg": r.Message, "level": r.Level.String()}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
	h.mu.Lock()
	h.recs = append(h.recs, m)
	h.mu.Unlock()
	return nil
}
func (h *createLogs) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *createLogs) WithGroup(string) slog.Handler      { return h }

func (h *createLogs) find(msg string) map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.recs {
		if r["msg"] == msg {
			return r
		}
	}
	return nil
}

// The owner logs a failed create at WARN with its cause, and what its
// cleanup did (lab 2, O5).
//
// Mutation: drop the failure log — both lookups fail, red.
func TestCreateVM_TheOwnerLogsAFailedCreateAndItsCleanup(t *testing.T) {
	h := &createLogs{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s, fake := provableCreateServer(t)
	fake.FailStartDomain = func(string) error { return errors.New("qemu: cannot allocate memory") }
	if _, err := s.CreateVM(adminCtx(), withDataDisk(disklessCreateRequest("vm1"))); err == nil {
		t.Fatal("the create succeeded with the failure injected")
	}
	failed := h.find("vm create failed")
	if failed == nil || failed["level"] != "WARN" || failed["name"] != "vm1" || !strings.Contains(failed["cause"], "cannot allocate memory") {
		t.Errorf("failure log = %v; want a WARN naming vm1 and the cause", failed)
	}
	cleanup := h.find("vm create: cleanup after the failed create")
	if cleanup == nil || cleanup["level"] != "WARN" {
		t.Fatalf("cleanup log = %v; want a WARN", cleanup)
	}
	for _, want := range []string{"removed disk " + s.images.DiskPath("vm1", "data"), "domain undefined"} {
		if !strings.Contains(cleanup["result"], want) {
			t.Errorf("cleanup result %q does not say %q", cleanup["result"], want)
		}
	}
}
