package custody

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

func custodyScopeFixture() CustodyScope {
	return CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
}
func custodyRefFixture(epoch string) CustodyKeyRef {
	return CustodyKeyRef{Epoch: epoch, KeyID: "key", Generation: 8, ConfigDigest: "config"}
}
func custodyStore(t *testing.T) (*LocalCustody, string) {
	t.Helper()
	path := filepath.Join(custodyTempDir(t), "custody")
	store, err := CreateLocalCustody(path, custodyScopeFixture())
	if err != nil {
		t.Fatal("custody creation failed")
	}
	t.Cleanup(func() { store.Close() })
	return store, path
}
func custodyKeyFile(t *testing.T, root string) string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(root, "key-*", "material"))
	if err != nil || len(dirs) != 1 {
		t.Fatal("expected one key file")
	}
	return dirs[0]
}
func requireCustodyError(t *testing.T, err, errorKind error) {
	t.Helper()
	if !errors.Is(err, errorKind) {
		t.Fatal("wrong custody error category")
	}
	if strings.Contains(err.Error(), "MARKER") || strings.Contains(err.Error(), "AGE-SECRET") {
		t.Fatal("custody error leaked material")
	}
}
func TestAutomationCustodyIdentityRestartAndBinding(t *testing.T) {
	s, path := custodyStore(t)
	ref := custodyRefFixture("recipient-1")
	key, err := s.CreateVoterIdentity(ref)
	if err != nil || key == nil {
		t.Fatal("identity install failed")
	}
	recipient := key.Recipient()
	cipher, err := EncryptBootstrap(secretBindingFixture(), EffectiveBootstrap{UserData: []byte("PRIVATE-MARKER")}, []*age.X25519Recipient{key.identity.Recipient()})
	if err != nil {
		t.Fatal("encrypt fixture failed")
	}
	if err = s.Close(); err != nil {
		t.Fatal("close failed")
	}
	reopened, err := OpenLocalCustody(path, custodyScopeFixture())
	if err != nil {
		t.Fatal("restart open failed")
	}
	defer reopened.Close()
	restored, err := reopened.OpenVoterIdentity(ref, recipient)
	if err != nil {
		t.Fatal("restart key missing")
	}
	files, err := DecryptBootstrap(secretBindingFixture(), cipher, []*age.X25519Identity{restored.identity})
	if err != nil || !bytes.Equal(files.UserData, []byte("PRIVATE-MARKER")) {
		t.Fatal("restart did not retain native identity")
	}
	_, err = reopened.CreateVoterIdentity(ref)
	requireCustodyError(t, err, ErrCustodyConflict)
	_, err = reopened.OpenVoterIdentity(ref, secretIdentity(t).Recipient().String())
	requireCustodyError(t, err, ErrCustodyConflict)
	_, err = OpenLocalCustody(path, CustodyScope{ClusterUID: "other", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"})
	requireCustodyError(t, err, ErrCustodyConflict)
	for _, wrong := range []CustodyKeyRef{{Epoch: ref.Epoch, KeyID: ref.KeyID, Generation: 9, ConfigDigest: ref.ConfigDigest}, custodyRefFixture("missing")} {
		_, err = reopened.OpenVoterIdentity(wrong, recipient)
		requireCustodyError(t, err, ErrCustodyUnavailable)
	}
}
func TestAutomationCustodyEqualityImportGenerationAndHistory(t *testing.T) {
	s, path := custodyStore(t)
	old := custodyRefFixture("old")
	material := bytes.Repeat([]byte{5}, 32)
	key, err := s.ImportEqualityKey(old, material)
	if err != nil {
		t.Fatal("equality import failed")
	}
	scope := IntentScope{"cluster", "namespace", "method"}
	raw := RawBootstrapIntent{Present: true, UserData: []byte("PRIVATE-MARKER")}
	tag, err := key.IntentTag("old", scope, raw)
	if err != nil {
		t.Fatal("tag failed")
	}
	_, err = s.ImportEqualityKey(old, bytes.Repeat([]byte{6}, 32))
	requireCustodyError(t, err, ErrCustodyConflict)
	again, err := s.ImportEqualityKey(old, material)
	if err != nil {
		t.Fatal("identical import failed")
	}
	same, err := again.CompareIntent("old", scope, raw, tag)
	if err != nil || !same {
		t.Fatal("repeat import changed material")
	}
	newer := custodyRefFixture("new")
	fresh, err := s.GenerateEqualityKey(newer)
	if err != nil {
		t.Fatal("random equality generation failed")
	}
	if bytes.Equal(fresh.material[:], material) || bytes.Equal(fresh.material[:], make([]byte, 32)) {
		t.Fatal("equality material was not independently generated")
	}
	s.Close()
	r, err := OpenLocalCustody(path, custodyScopeFixture())
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer r.Close()
	historical, err := r.OpenEqualityKey(old)
	if err != nil {
		t.Fatal("historical epoch missing")
	}
	same, err = historical.CompareIntent("old", scope, raw, tag)
	if err != nil || !same {
		t.Fatal("historical equality lost")
	}
	_, err = r.OpenEqualityKey(custodyRefFixture("missing"))
	requireCustodyError(t, err, ErrCustodyUnavailable)
	_, err = r.GenerateEqualityKey(old)
	requireCustodyError(t, err, ErrCustodyConflict)
}
func TestAutomationCustodyRestrictiveModesAndNoReplacement(t *testing.T) {
	s, path := custodyStore(t)
	ref := custodyRefFixture("epoch")
	material := bytes.Repeat([]byte{7}, 32)
	if _, err := s.ImportEqualityKey(ref, material); err != nil {
		t.Fatal("import failed")
	}
	file := custodyKeyFile(t, path)
	for _, p := range []string{path, filepath.Dir(file)} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0700 {
			t.Fatal("custody directory is not private")
		}
	}
	fi, err := os.Stat(file)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("custody key is not private")
	}
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("fixture read failed")
	}
	if os.Chmod(file, 0400) != nil {
		t.Fatal("chmod failed")
	}
	if _, err = s.ImportEqualityKey(ref, material); err != nil {
		t.Fatal("strict existing mode refused")
	}
	fi, _ = os.Stat(file)
	if fi.Mode().Perm() != 0400 {
		t.Fatal("strict mode widened")
	}
	if os.Chmod(file, 0644) != nil {
		t.Fatal("chmod failed")
	}
	_, err = s.OpenEqualityKey(ref)
	requireCustodyError(t, err, ErrCustodyCorrupt)
	if os.Chmod(file, 0600) != nil {
		t.Fatal("chmod failed")
	}
	if os.WriteFile(file, []byte("CORRUPT-PRIVATE-MARKER"), 0600) != nil {
		t.Fatal("corrupt fixture failed")
	}
	_, err = s.ImportEqualityKey(ref, material)
	requireCustodyError(t, err, ErrCustodyCorrupt)
	after, _ := os.ReadFile(file)
	if !bytes.Equal(after, []byte("CORRUPT-PRIVATE-MARKER")) {
		t.Fatal("corrupt material replaced")
	}
	if os.WriteFile(file, original, 0600) != nil || os.Remove(file) != nil {
		t.Fatal("missing fixture failed")
	}
	_, err = s.OpenEqualityKey(ref)
	requireCustodyError(t, err, ErrCustodyRecoveryRequired)
	_, err = s.ImportEqualityKey(ref, material)
	requireCustodyError(t, err, ErrCustodyRecoveryRequired)
	if _, err = os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("missing material regenerated")
	}
}
func TestAutomationCustodyRejectsUnsafeFilesAndDetachedDirectories(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "directory", "oversize", "keydir-swap", "root-swap"} {
		t.Run(kind, func(t *testing.T) {
			s, path := custodyStore(t)
			ref := custodyRefFixture("epoch")
			if _, err := s.GenerateEqualityKey(ref); err != nil {
				t.Fatal("generate failed")
			}
			file := custodyKeyFile(t, path)
			switch kind {
			case "symlink":
				outside := filepath.Join(custodyTempDir(t), "outside")
				os.WriteFile(outside, []byte("PRIVATE-MARKER"), 0600)
				os.Remove(file)
				if os.Symlink(outside, file) != nil {
					t.Fatal("symlink fixture failed")
				}
			case "fifo":
				os.Remove(file)
				if unix.Mkfifo(file, 0600) != nil {
					t.Fatal("fifo fixture failed")
				}
			case "directory":
				os.Remove(file)
				if os.Mkdir(file, 0700) != nil {
					t.Fatal("directory fixture failed")
				}
			case "oversize":
				if os.WriteFile(file, make([]byte, 65537), 0600) != nil {
					t.Fatal("oversize fixture failed")
				}
			case "keydir-swap":
				moved := filepath.Dir(file) + "-moved"
				if os.Rename(filepath.Dir(file), moved) != nil || os.Symlink(moved, filepath.Dir(file)) != nil {
					t.Fatal("keydir swap failed")
				}
			case "root-swap":
				if os.Rename(path, path+"-moved") != nil || os.Mkdir(path, 0700) != nil {
					t.Fatal("root swap failed")
				}
			}
			if _, err := s.OpenEqualityKey(ref); err == nil {
				t.Fatal("unsafe custody was accepted")
			}
		})
	}
	parent := custodyTempDir(t)
	real := filepath.Join(parent, "real")
	if os.Mkdir(real, 0700) != nil {
		t.Fatal("mkdir failed")
	}
	alias := filepath.Join(parent, "alias")
	if os.Symlink(real, alias) != nil {
		t.Fatal("symlink failed")
	}
	if _, err := CreateLocalCustody(filepath.Join(alias, "new"), custodyScopeFixture()); err == nil {
		t.Fatal("symlink ancestor followed")
	}
	if _, err := OpenLocalCustody(filepath.Join(parent, "absent"), custodyScopeFixture()); err == nil {
		t.Fatal("missing root recreated")
	}
}
func TestAutomationCustodyDurabilityFailuresBeforeResult(t *testing.T) {
	scope := custodyScopeFixture()
	for _, stage := range []string{"file", "root", "parent"} {
		t.Run("bootstrap-"+stage, func(t *testing.T) {
			var calls int
			injected := false
			ops := custodyIO{}
			fail := func(f *os.File) error { injected = true; f.Close(); return f.Sync() }
			if stage == "file" {
				ops.syncFile = fail
			} else {
				ops.syncDir = func(f *os.File) error {
					calls++
					if (stage == "root" && calls == 1) || (stage == "parent" && calls == 2) {
						return fail(f)
					}
					return f.Sync()
				}
			}
			store, err := createLocalCustody(filepath.Join(custodyTempDir(t), "custody"), scope, ops)
			if err == nil || store != nil || !injected {
				t.Fatal("bootstrap acknowledged failure or missed durability seam")
			}
		})
	}
	for _, stage := range []string{"file", "reservation-parent", "keydir", "root"} {
		t.Run("key-"+stage, func(t *testing.T) {
			s, _ := custodyStore(t)
			ref := custodyRefFixture("epoch")
			material := bytes.Repeat([]byte{8}, 32)
			var calls int
			injected := false
			if stage == "file" {
				s.ops.syncFile = func(f *os.File) error { injected = true; f.Close(); return f.Sync() }
			} else {
				s.ops.syncDir = func(f *os.File) error {
					calls++
					target := map[string]int{"reservation-parent": 1, "keydir": 2, "root": 3}[stage]
					if calls == target {
						injected = true
						f.Close()
						return f.Sync()
					}
					return f.Sync()
				}
			}
			key, err := s.ImportEqualityKey(ref, material)
			if err == nil || key.epoch != "" || !injected {
				t.Fatal("key acknowledged failure or missed durability seam")
			}
		})
	}
	// An exact repeated import must check durability again, not return cached success.
	s, _ := custodyStore(t)
	ref := custodyRefFixture("epoch")
	material := bytes.Repeat([]byte{8}, 32)
	if _, err := s.ImportEqualityKey(ref, material); err != nil {
		t.Fatal("import failed")
	}
	s.ops.syncFile = func(f *os.File) error { f.Close(); return f.Sync() }
	key, err := s.ImportEqualityKey(ref, material)
	if err == nil || key.epoch != "" {
		t.Fatal("repeat import skipped durability")
	}
}
func TestAutomationCustodyConcurrentReservation(t *testing.T) {
	first, path := custodyStore(t)
	second, err := OpenLocalCustody(path, custodyScopeFixture())
	if err != nil {
		t.Fatal("second opener failed")
	}
	defer second.Close()
	ref := custodyRefFixture("epoch")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, s := range []*LocalCustody{first, second} {
		wg.Add(1)
		go func(s *LocalCustody) { defer wg.Done(); <-start; _, err := s.CreateVoterIdentity(ref); errs <- err }(s)
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("reservation did not select exactly one immutable creator")
	}
}
func TestAutomationCustodyErrorsDoNotDiscloseInput(t *testing.T) {
	s, _ := custodyStore(t)
	bad := CustodyKeyRef{Epoch: "MARKER", KeyID: "MARKER", Generation: 0, ConfigDigest: "MARKER"}
	_, err := s.ImportEqualityKey(bad, []byte("PRIVATE-MARKER"))
	if err == nil || strings.Contains(fmt.Sprint(err), "MARKER") {
		t.Fatal("invalid input leaked")
	}
}

// Unprivileged tests cannot chown a file to another UID. Preserve real fstat
// metadata except its owner to exercise exactly the production ownership rule.
type custodyForeignOwnerInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info custodyForeignOwnerInfo) Sys() any { return &info.stat }
func TestAutomationCustodyForeignOwnershipRule(t *testing.T) {
	f, err := os.CreateTemp(custodyTempDir(t), "owner")
	if err != nil {
		t.Fatal("owner fixture failed")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !custodyOwned(info) {
		t.Fatal("actual process-owned descriptor refused")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("owner metadata unavailable")
	}
	foreign := custodyForeignOwnerInfo{FileInfo: info, stat: *stat}
	foreign.stat.Uid++
	if custodyOwned(foreign) {
		t.Fatal("foreign owner accepted")
	}
}
func TestAutomationCustodySubprocessReopen(t *testing.T) {
	if path := os.Getenv("LITEVIRT_CUSTODY_REOPEN_DIR"); path != "" {
		store, err := OpenLocalCustody(path, custodyScopeFixture())
		if err != nil {
			t.Fatal("child root reopen failed")
		}
		defer store.Close()
		if _, err = store.OpenVoterIdentity(custodyRefFixture("recipient"), os.Getenv("LITEVIRT_CUSTODY_RECIPIENT")); err != nil {
			t.Fatal("child native identity reopen failed")
		}
		key, err := store.OpenEqualityKey(custodyRefFixture("equality"))
		if err != nil || !bytes.Equal(key.material[:], bytes.Repeat([]byte{11}, 32)) {
			t.Fatal("child equality retention failed")
		}
		return
	}
	store, path := custodyStore(t)
	voter, err := store.CreateVoterIdentity(custodyRefFixture("recipient"))
	if err != nil {
		t.Fatal("parent identity create failed")
	}
	if _, err = store.ImportEqualityKey(custodyRefFixture("equality"), bytes.Repeat([]byte{11}, 32)); err != nil {
		t.Fatal("parent equality install failed")
	}
	if store.Close() != nil {
		t.Fatal("parent close failed")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	cmd := exec.Command(exe, "-test.run=^TestAutomationCustodySubprocessReopen$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "LITEVIRT_CUSTODY_REOPEN_DIR="+path, "LITEVIRT_CUSTODY_RECIPIENT="+voter.Recipient())
	if _, err = cmd.CombinedOutput(); err != nil {
		t.Fatal("separate process did not retain custody")
	}
}

func custodyTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private custody parent setup failed")
	}
	return dir
}
func TestAutomationCustodyRejectsOversizedBindingBeforeReservation(t *testing.T) {
	s, path := custodyStore(t)
	ref := CustodyKeyRef{Epoch: strings.Repeat("\x00", 4096), KeyID: strings.Repeat("\x00", 4096), Generation: 1, ConfigDigest: strings.Repeat("\x00", 4096)}
	_, err := s.GenerateEqualityKey(ref)
	requireCustodyError(t, err, ErrCustodyCorrupt)
	names, err := filepath.Glob(filepath.Join(path, "key-*"))
	if err != nil || len(names) != 0 {
		t.Fatal("oversized binding left a key reservation")
	}
}
func TestAutomationCustodyRefusesDetachDuringReopen(t *testing.T) {
	for _, target := range []string{"root", "keydir"} {
		t.Run(target, func(t *testing.T) {
			s, path := custodyStore(t)
			ref := custodyRefFixture("epoch")
			if _, err := s.GenerateEqualityKey(ref); err != nil {
				t.Fatal("install failed")
			}
			dir := path
			if target == "keydir" {
				dir = filepath.Dir(custodyKeyFile(t, path))
			}
			detached := false
			s.ops.syncFile = func(f *os.File) error {
				if err := f.Sync(); err != nil {
					return err
				}
				if err := os.Rename(dir, dir+"-detached"); err != nil {
					return err
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					return err
				}
				detached = true
				return nil
			}
			key, err := s.OpenEqualityKey(ref)
			if !detached || err == nil || key.epoch != "" {
				t.Fatal("reopen acknowledged detached custody")
			}
		})
	}
}
func TestAutomationCustodyIncompleteRootRequiresRecovery(t *testing.T) {
	path := filepath.Join(custodyTempDir(t), "custody")
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("incomplete root fixture failed")
	}
	_, err := OpenLocalCustody(path, custodyScopeFixture())
	requireCustodyError(t, err, ErrCustodyRecoveryRequired)
	_, err = CreateLocalCustody(path, custodyScopeFixture())
	requireCustodyError(t, err, ErrCustodyConflict)
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
		t.Fatal("incomplete root was silently replaced")
	}
}

func TestAutomationCustodyIncompleteKeyReservationRequiresRecovery(t *testing.T) {
	for _, purpose := range []string{custodyVoterPurpose, custodyEqualityPurpose} {
		t.Run(purpose, func(t *testing.T) {
			s, path := custodyStore(t)
			ref := custodyRefFixture("epoch")
			// Stop after the actual durable reservation, before generating any material.
			dir, _, err := s.reserve(purpose, ref)
			if err != nil {
				t.Fatal("reservation setup failed")
			}
			dir.Close()
			if purpose == custodyVoterPurpose {
				_, err = s.CreateVoterIdentity(ref)
			} else {
				_, err = s.GenerateEqualityKey(ref)
			}
			requireCustodyError(t, err, ErrCustodyRecoveryRequired)
			material, err := filepath.Glob(filepath.Join(path, "key-*", "material"))
			if err != nil || len(material) != 0 {
				t.Fatal("incomplete reservation regenerated material")
			}
		})
	}
}

func TestAutomationCustodyAbruptReservationAndMaterialSync(t *testing.T) {
	if path := os.Getenv("LITEVIRT_CUSTODY_ABRUPT_DIR"); path != "" {
		store, err := OpenLocalCustody(path, custodyScopeFixture())
		if err != nil {
			t.Fatal("abrupt child root reopen failed")
		}
		defer store.Close()
		switch os.Getenv("LITEVIRT_CUSTODY_ABRUPT_STAGE") {
		case "reservation":
			store.ops.syncDir = func(f *os.File) error {
				if err := f.Sync(); err != nil {
					return err
				}
				os.Exit(42)
				return nil
			}
		case "material":
			store.ops.syncFile = func(f *os.File) error {
				if err := f.Sync(); err != nil {
					return err
				}
				os.Exit(43)
				return nil
			}
		default:
			t.Fatal("unknown abrupt child stage")
		}
		store.ImportEqualityKey(custodyRefFixture("abrupt"), bytes.Repeat([]byte{23}, 32))
		t.Fatal("abrupt child did not exit at durability seam")
	}
	for stage, exitCode := range map[string]int{"reservation": 42, "material": 43} {
		t.Run(stage, func(t *testing.T) {
			store, path := custodyStore(t)
			if store.Close() != nil {
				t.Fatal("abrupt parent close failed")
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal("abrupt test executable unavailable")
			}
			cmd := exec.Command(exe, "-test.run=^TestAutomationCustodyAbruptReservationAndMaterialSync$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "LITEVIRT_CUSTODY_ABRUPT_DIR="+path, "LITEVIRT_CUSTODY_ABRUPT_STAGE="+stage)
			var exited *exec.ExitError
			if err := cmd.Run(); !errors.As(err, &exited) || exited.ExitCode() != exitCode {
				t.Fatal("child did not reach the intended abrupt durability exit")
			}
			opened, err := OpenLocalCustody(path, custodyScopeFixture())
			if err != nil {
				t.Fatal("abrupt root reopen failed")
			}
			defer opened.Close()
			ref := custodyRefFixture("abrupt")
			if stage == "reservation" {
				_, err := opened.OpenEqualityKey(ref)
				requireCustodyError(t, err, ErrCustodyRecoveryRequired)
				_, err = opened.GenerateEqualityKey(ref)
				requireCustodyError(t, err, ErrCustodyRecoveryRequired)
				if files, err := filepath.Glob(filepath.Join(path, "key-*", "material")); err != nil || len(files) != 0 {
					t.Fatal("abrupt reservation regenerated missing material")
				}
			} else {
				file := custodyKeyFile(t, path)
				before, err := os.ReadFile(file)
				if err != nil {
					t.Fatal("abrupt material fixture unreadable")
				}
				key, err := opened.OpenEqualityKey(ref)
				if err != nil || !bytes.Equal(key.material[:], bytes.Repeat([]byte{23}, 32)) {
					t.Fatal("abrupt material sync lost original equality bytes")
				}
				after, err := os.ReadFile(file)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("abrupt material reopen rewrote the original record")
				}
			}
		})
	}
}

func TestCustodyProvisionDurabilityBeforePublication(t *testing.T) {
	for _, stage := range []string{"file", "directory"} {
		t.Run(stage, func(t *testing.T) {
			store, _ := custodyStore(t)
			ref := CustodyProvisionRef{Attempt: "provision", Voter: custodyRefFixture("recipient"), Equality: custodyRefFixture("equality")}
			injected := false
			fail := func(*os.File) error { injected = true; return syscall.EIO }
			if stage == "file" {
				store.ops.syncFile = fail
			} else {
				store.ops.syncDir = fail
			}
			body := []byte(`{"durable":true}`)
			if err := store.SaveProvisionRecord(ref, "plan", body); err == nil || !injected {
				t.Fatal("metadata published without durable sync")
			}
			store.ops = custodyIO{}
			if err := store.SaveProvisionRecord(ref, "plan", body); err != nil {
				t.Fatalf("exact retry did not revalidate/sync: %v", err)
			}
			got, err := store.ReadProvisionRecord(ref, "plan")
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("durable reopened metadata differs")
			}
			if err = store.SaveProvisionRecord(ref, "plan", []byte(`{"durable":false}`)); err == nil {
				t.Fatal("retry replaced immutable continuation")
			}
		})
	}
}
