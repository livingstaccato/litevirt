package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"
)

const undoTestSuffix = ".pre-add-20261024T010203Z-0123456789ab"

func undoFixture(t *testing.T, linked bool) (string, *HostEnrollment, *HostDomainLease) {
	t.Helper()
	dir := setupPKI(t)
	if linked {
		if err := InstallHostEnrollment(context.Background(), dir, enrollmentMaterial(t, dir)); err != nil {
			t.Fatal(err)
		}
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "ca.crt"), mustReadFile(t, filepath.Join(dir, "ca.crt")), 0644); err != nil {
		t.Fatal(err)
	}
	mintInto(t, dir, source, "test-host")
	m := enrollmentMaterial(t, source)
	l, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Release)
	return dir, m, l
}

// Independently observe fixed active endpoints, including type, modes, raw
// pointer and dereferenced bytes. Never derive wants from the receipt.
func undoObserved(t *testing.T, dir string) [4]string {
	t.Helper()
	var result [4]string
	for i, name := range []string{"ca.crt", "host.crt", "host.key", "host.d/current"} {
		p := filepath.Join(dir, name)
		fi, err := os.Lstat(p)
		if os.IsNotExist(err) {
			result[i] = "absent"
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				t.Fatal(err)
			}
			result[i] = fmt.Sprintf("link:%v:%s", fi.Mode(), link)
			if i != 3 {
				b, err := os.ReadFile(p)
				result[i] += fmt.Sprintf(":%x:%v", b, err)
			}
		} else {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			result[i] = fmt.Sprintf("file:%v:%x", fi.Mode(), b)
		}
	}
	return result
}

func TestHostEnrollmentUndoRequiresActualAdmission(t *testing.T) {
	dir, m, l := undoFixture(t, false)
	before := undoObserved(t, dir)
	copied := &HostDomainLease{self: l.self, dir: l.dir, file: l.file, exclusive: true}
	wrong, err := AcquireHostReinitialization(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Release()
	for _, bad := range []*HostDomainLease{nil, {}, copied, wrong} {
		u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, bad, undoTestSuffix)
		if err == nil || u != nil {
			t.Fatal("accepted invalid admission")
		}
		if undoObserved(t, dir) != before {
			t.Fatal("invalid admission changed active state")
		}
	}
	for _, suffix := range []string{"", "../escape", ".pre-add-20261024T010203Z-0123456789abcdef", ".pre-add-20261024T010203Z-abc/def", ".pre-add-20261024T010203Z-x;touch", ".pre-add-20261340T990000Z-0123456789ab"} {
		if u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, suffix); err == nil || u != nil {
			t.Fatal("unsafe backup suffix accepted", suffix)
		}
	}
	l.Release()
	if u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix); err == nil || u != nil {
		t.Fatal("released lease admitted")
	}
	shared, err := AcquireHostDomain(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, shared, undoTestSuffix); err == nil || u != nil {
		t.Fatal("shared lease admitted")
	}
	shared.Release()
	fresh, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Release()
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, fresh, undoTestSuffix)
	if err != nil || u == nil {
		t.Fatal("genuine EX install failed", err)
	}
	if err := u.Restore(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	if undoObserved(t, dir) != before {
		t.Fatal("restore changed preimage")
	}
}

func TestHostEnrollmentUndoRestoresExactOwnPrefix(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, stage := range []string{"success", "copied-legacy", "current-created", "linked-host.key", "linked-host.crt", "active-current"} {
			if linked && stage != "success" && stage != "active-current" {
				continue
			}
			t.Run(fmt.Sprintf("linked=%v/%s", linked, stage), func(t *testing.T) {
				dir, m, l := undoFixture(t, linked)
				before := undoObserved(t, dir)
				oldCert := mustReadFile(t, filepath.Join(dir, "host.crt"))
				oldKey := mustReadFile(t, filepath.Join(dir, "host.key"))
				oldSerial := readLeaf(t, filepath.Join(dir, "host.crt")).SerialNumber.Text(16)
				injected := errors.New("actual own prefix")
				hit := false
				swapCrashHook = func(at string) error {
					if at == stage {
						hit = true
						return injected
					}
					return nil
				}
				defer func() { swapCrashHook = nil; trustDurabilitySeam = nil }()
				if stage == "active-current" {
					trustDurabilitySeam = func(at string) error {
						current, _ := os.Readlink(filepath.Join(dir, "host.d/current"))
						if at == "directory-sync:"+filepath.Join(dir, "host.d") && current == m.leaf.SerialNumber.Text(16) {
							hit = true
							return injected
						}
						return nil
					}
				}
				u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
				if stage == "success" {
					if err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, injected) || !hit {
					t.Fatalf("did not reach actual prefix %s: %v", stage, err)
				}
				if u == nil {
					t.Fatal("possible landed write lost undo receipt")
				}
				swapCrashHook = nil
				trustDurabilitySeam = nil
				l.Release()
				fresh, e := AcquireHostReinitialization(context.Background(), dir)
				if e != nil {
					t.Fatal(e)
				}
				defer fresh.Release()
				if err := u.Restore(context.Background(), fresh); err != nil {
					t.Fatal(err)
				}
				if undoObserved(t, dir) != before {
					t.Fatal("restore did not recover exact topology/bytes/mode")
				}
				if err := u.Restore(context.Background(), fresh); err != nil {
					t.Fatal("exact restored retry failed", err)
				}
				for _, item := range []struct {
					serial, name string
					body         []byte
				}{{oldSerial, "host.crt", oldCert}, {oldSerial, "host.key", oldKey}, {m.leaf.SerialNumber.Text(16), "host.crt", m.cert}, {m.leaf.SerialNumber.Text(16), "host.key", m.key}} {
					if b, err := os.ReadFile(filepath.Join(dir, "host.d", item.serial, item.name)); err != nil || !bytes.Equal(b, item.body) {
						t.Fatal("retained serial lost", item.serial, item.name, err)
					}
				}
				for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
					fi, err := os.Stat(filepath.Join(dir, name+undoTestSuffix))
					if err != nil || fi.Mode().Perm() != 0600 {
						t.Fatal("backup not durable private regular file", name, err)
					}
				}
			})
		}
	}
	t.Run("previous-serial-collision", func(t *testing.T) {
		dir, m, l := undoFixture(t, false)
		serial := readLeaf(t, filepath.Join(dir, "host.crt")).SerialNumber.Text(16)
		p := filepath.Join(dir, "host.d", serial)
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"host.crt", "host.key"} {
			if err := os.WriteFile(filepath.Join(p, name), []byte("foreign retained "+name), 0600); err != nil {
				t.Fatal(err)
			}
		}
		before := undoObserved(t, dir)
		u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
		if err == nil {
			t.Fatal("previous serial collision overwritten")
		}
		if u != nil {
			if err := u.Restore(context.Background(), l); err != nil {
				t.Fatal(err)
			}
		}
		if undoObserved(t, dir) != before {
			t.Fatal("collision changed active image")
		}
		if string(mustReadFile(t, filepath.Join(p, "host.key"))) != "foreign retained host.key" {
			t.Fatal("old collision erased")
		}
	})
	t.Run("first-enrollment", func(t *testing.T) {
		dir := t.TempDir()
		m := enrollmentMaterial(t, setupPKI(t))
		l, err := AcquireHostReinitialization(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Release()
		before := undoObserved(t, dir)
		u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
		if err != nil || u == nil {
			t.Fatal(err)
		}
		if err := u.Restore(context.Background(), l); err != nil {
			t.Fatal(err)
		}
		if undoObserved(t, dir) != before {
			t.Fatal("first restore created absent endpoints")
		}
	})
}

func TestHostEnrollmentUndoRejectsForeignFootprint(t *testing.T) {
	for _, change := range []string{"key", "root", "pointer", "mode", "linked-target", "copied", "zero", "complete"} {
		t.Run(change, func(t *testing.T) {
			dir, m, l := undoFixture(t, true)
			oldSerial := readLeaf(t, filepath.Join(dir, "host.crt")).SerialNumber.Text(16)
			u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
			if err != nil || u == nil {
				t.Fatal(err)
			}
			switch change {
			case "key":
				err = os.WriteFile(filepath.Join(dir, "host.key"), []byte("different key under same serial"), 0600)
			case "root":
				err = os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("different root"), 0644)
			case "pointer":
				err = atomicSymlink(oldSerial, filepath.Join(dir, "host.d/current"))
			case "mode":
				err = os.Chmod(filepath.Join(dir, "host.key"), 0400)
			case "linked-target":
				err = os.WriteFile(filepath.Join(dir, "host.d", m.leaf.SerialNumber.Text(16), "host.crt"), []byte("changed target"), 0644)
			case "copied":
				u = &HostEnrollmentUndo{self: u}
			case "zero":
				u = &HostEnrollmentUndo{}
			case "complete":
				err = u.Complete()
			}
			if err != nil {
				t.Fatal(err)
			}
			before := undoObserved(t, dir)
			if err := u.Restore(context.Background(), l); err == nil {
				t.Fatal("foreign/invalid receipt restored")
			}
			if undoObserved(t, dir) != before {
				t.Fatal("refusal overwrote foreign footprint")
			}
		})
	}
}

func TestHostEnrollmentUndoUncertainDurability(t *testing.T) {
	// Enumerate every actual local durability position, including backups and all
	// conversion steps, then fail each one in a fresh independently owned tree.
	dir, m, l := undoFixture(t, false)
	var trace []string
	trustDurabilitySeam = func(at string) error { trace = append(trace, at); return nil }
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
	trustDurabilitySeam = nil
	if err != nil || u == nil {
		t.Fatal("trace install", err)
	}
	if len(trace) < 12 {
		t.Fatal("did not exercise real durability boundaries")
	}
	for failAt := range trace {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			dir, m, l := undoFixture(t, false)
			before := undoObserved(t, dir)
			n := 0
			injected := errors.New("local boundary failure")
			trustDurabilitySeam = func(string) error {
				n++
				if n == failAt+1 {
					return injected
				}
				return nil
			}
			defer func() { trustDurabilitySeam = nil }()
			u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
			trustDurabilitySeam = nil
			if !errors.Is(err, injected) {
				t.Fatalf("boundary %d did not fail: %v", failAt, err)
			}
			if u == nil {
				if undoObserved(t, dir) != before {
					t.Fatal("nil receipt despite active mutation")
				}
				return
			}
			if err := u.Restore(context.Background(), l); err != nil {
				t.Fatal("uncertain prefix not restorable", err)
			}
			if undoObserved(t, dir) != before {
				t.Fatal("uncertain write not undone exactly")
			}
		})
	}
	for _, stage := range []string{"rename", "reopen", "file-sync", "directory-sync"} {
		t.Run("restore-"+stage, func(t *testing.T) {
			dir, m, l := undoFixture(t, false)
			before := undoObserved(t, dir)
			u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("restore boundary")
			hit := false
			trustDurabilitySeam = func(at string) error {
				if at == stage && !hit {
					hit = true
					return injected
				}
				return nil
			}
			err = u.Restore(context.Background(), l)
			trustDurabilitySeam = nil
			if !errors.Is(err, injected) || !hit {
				t.Fatal("restore uncertainty reported success", err)
			}
			if err := u.Restore(context.Background(), l); err != nil {
				t.Fatal("restore retry rejected own prefix", err)
			}
			if undoObserved(t, dir) != before {
				t.Fatal("restore retry lost exact original")
			}
		})
	}
}

func TestHostEnrollmentUndoKeepsInactiveOriginal(t *testing.T) {
	dir, m, l := undoFixture(t, false)
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Add(-time.Minute)
	leaf.NotBefore = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	before := undoObserved(t, dir)
	o, err := trustOwnerFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	o.revokedFloor["d00d"] = true
	floor := bytes.Clone(o.root)
	revision := o.revision
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Restore(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if undoObserved(t, dir) != before {
		t.Fatal("expired original not exact")
	}
	if !o.revokedFloor["d00d"] || !reflect.DeepEqual(floor, o.root) || o.revision <= revision {
		t.Fatal("undo reset owner history")
	}
	if _, err := CaptureHostTrust(context.Background(), dir, "test-host"); err == nil {
		t.Fatal("expired restored original blessed as fresh trust")
	}
	if err := u.Complete(); err != nil {
		t.Fatal(err)
	}
	if err := u.Restore(context.Background(), l); err == nil {
		t.Fatal("completed receipt retained authority")
	}
}

func TestHostEnrollmentUndoMixedTopologyAndHardenedModes(t *testing.T) {
	for _, layout := range []string{"key-regular", "cert-regular", "hardened-mixed", "regular-with-inert-current"} {
		for _, stage := range []string{"success", "current-created", "linked-host.key", "linked-host.crt"} {
			t.Run(layout+"/"+stage, func(t *testing.T) {
				linked := layout != "regular-with-inert-current"
				dir, m, l := undoFixture(t, linked)
				originalCert := mustReadFile(t, filepath.Join(dir, "host.crt"))
				originalKey := mustReadFile(t, filepath.Join(dir, "host.key"))
				if linked {
					name, body := "host.key", originalKey
					if layout == "cert-regular" {
						name, body = "host.crt", originalCert
					}
					if err := os.Remove(filepath.Join(dir, name)); err != nil {
						t.Fatal(err)
					}
					mode := os.FileMode(0640)
					if name == "host.key" {
						mode = 0400
					}
					if err := os.WriteFile(filepath.Join(dir, name), body, mode); err != nil {
						t.Fatal(err)
					}
					if layout == "hardened-mixed" {
						current, err := os.Readlink(filepath.Join(dir, "host.d/current"))
						if err != nil {
							t.Fatal(err)
						}
						for _, name := range []string{"host.crt", "host.key"} {
							if err := os.Chmod(filepath.Join(dir, "host.d", current, name), 0400); err != nil {
								t.Fatal(err)
							}
						}
					}
				} else {
					other := t.TempDir()
					if err := os.WriteFile(filepath.Join(other, "ca.crt"), mustReadFile(t, filepath.Join(dir, "ca.crt")), 0644); err != nil {
						t.Fatal(err)
					}
					mintInto(t, dir, other, "test-host")
					serial := readLeaf(t, filepath.Join(other, "host.crt")).SerialNumber.Text(16)
					target := filepath.Join(dir, "host.d", serial)
					if err := os.MkdirAll(target, 0700); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"host.crt", "host.key"} {
						if err := os.WriteFile(filepath.Join(target, name), mustReadFile(t, filepath.Join(other, name)), 0400); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Symlink(serial, filepath.Join(dir, "host.d/current")); err != nil {
						t.Fatal(err)
					}
				}
				before := undoObserved(t, dir)
				injected := errors.New("mixed topology prefix")
				hit := false
				swapCrashHook = func(at string) error {
					if at == stage {
						hit = true
						return injected
					}
					return nil
				}
				defer func() { swapCrashHook = nil }()
				u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
				swapCrashHook = nil
				// A link already in the desired form has no corresponding conversion step.
				skipped := stage == "linked-host.key" && layout == "cert-regular" || stage == "linked-host.crt" && (layout == "key-regular" || layout == "hardened-mixed")
				if stage == "success" || skipped {
					if err != nil {
						t.Fatal(err)
					}
				} else if !hit || !errors.Is(err, injected) {
					t.Fatalf("missing mixed-prefix fault: %v", err)
				}
				if u == nil {
					t.Fatal("no receipt")
				}
				if err := u.Restore(context.Background(), l); err != nil {
					t.Fatal(err)
				}
				if undoObserved(t, dir) != before {
					t.Fatal("mixed topology/modes changed")
				}
			})
		}
	}
}

func TestHostEnrollmentUndoRefusesCanonicalPathAndBackupCollisions(t *testing.T) {
	for _, state := range []string{"new-serial-link", "backup-link", "backup-bytes", "replaced-admission", "directory-swap", "foreign-restore"} {
		t.Run(state, func(t *testing.T) {
			dir, m, l := undoFixture(t, false)
			before := undoObserved(t, dir)
			switch state {
			case "new-serial-link":
				target := t.TempDir()
				for _, item := range []struct {
					name string
					body []byte
				}{{"host.crt", m.cert}, {"host.key", m.key}} {
					if err := os.WriteFile(filepath.Join(target, item.name), item.body, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.MkdirAll(filepath.Join(dir, "host.d"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, "host.d", m.leaf.SerialNumber.Text(16))); err != nil {
					t.Fatal(err)
				}
			case "backup-link":
				if err := os.Symlink(filepath.Join(dir, "host.key"), filepath.Join(dir, "host.key")+undoTestSuffix); err != nil {
					t.Fatal(err)
				}
			case "backup-bytes":
				if err := os.WriteFile(filepath.Join(dir, "host.key")+undoTestSuffix, []byte("different backup"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced-admission":
				if err := os.Rename(filepath.Join(dir, activeDomainLockName), filepath.Join(dir, "saved-admission")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, activeDomainLockName), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-swap":
				moved := dir + "-moved"
				if err := os.Rename(dir, moved); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(moved)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(moved, activeDomainLockName), filepath.Join(dir, activeDomainLockName)); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
					if err := os.WriteFile(filepath.Join(dir, name), mustReadFile(t, filepath.Join(moved, name)), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before = undoObserved(t, dir)
			case "foreign-restore":
				u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
				if err != nil {
					t.Fatal(err)
				}
				other, err := AcquireHostReinitialization(context.Background(), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Release()
				image := undoObserved(t, dir)
				if err := u.Restore(context.Background(), other); err == nil {
					t.Fatal("other directory admitted undo")
				}
				if undoObserved(t, dir) != image {
					t.Fatal("other admission changed image")
				}
				return
			}
			u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
			if err == nil {
				t.Fatal("unsafe path/collision accepted")
			}
			if u != nil {
				if err := u.Restore(context.Background(), l); err != nil {
					t.Fatal("inert failure restore", err)
				}
			}
			if undoObserved(t, dir) != before {
				t.Fatal("refused path changed active image")
			}
		})
	}
}

// This helper is selected only by its actual parent. It proves a real
// cross-process owner lock excludes a current writer, not just a Go mutex.
func TestHostEnrollmentUndoWriterProcess(t *testing.T) {
	dir := os.Getenv("LITEVIRT_UNDO_WRITER_DIR")
	if dir == "" {
		t.Skip("subprocess only; exercised by owned parent control")
	}
	source := os.Getenv("LITEVIRT_UNDO_WRITER_SOURCE")
	fd, err := syscall.Open(filepath.Join(dir, trustLockName), syscall.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	syscall.Close(fd)
	if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
		t.Fatalf("snapshot/install owner not physically held: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	m := enrollmentMaterial(t, source)
	if err := InstallHostEnrollment(ctx, dir, m); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("competing writer crossed snapshot/install: %v", err)
	}
	fmt.Println("WRITER_EXCLUDED")
}

func TestHostEnrollmentUndoCaptureInstallHasOneActualOwner(t *testing.T) {
	dir, m, l := undoFixture(t, false)
	before := undoObserved(t, dir)
	source := t.TempDir()
	for _, item := range []struct {
		name string
		body []byte
	}{{"ca.crt", m.ca}, {"host.crt", m.cert}, {"host.key", m.key}} {
		if err := os.WriteFile(filepath.Join(source, item.name), item.body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fired := false
	trustDurabilitySeam = func(at string) error {
		if at != "reopen" || fired {
			return nil
		}
		fired = true
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHostEnrollmentUndoWriterProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), "LITEVIRT_UNDO_WRITER_DIR="+dir, "LITEVIRT_UNDO_WRITER_SOURCE="+source)
		out, err := cmd.CombinedOutput()
		t.Logf("actual writer pid=%d Wait=%v output=%s", cmd.Process.Pid, err, out)
		if err != nil {
			return err
		}
		if !bytes.Contains(out, []byte("WRITER_EXCLUDED")) {
			return errors.New("writer did not complete actual exclusion control")
		}
		return nil
	}
	defer func() { trustDurabilitySeam = nil }()
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
	trustDurabilitySeam = nil
	if err != nil || u == nil || !fired {
		t.Fatal("owner control not reached", err)
	}
	if err := u.Restore(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if undoObserved(t, dir) != before {
		t.Fatal("snapshot/install interleaved")
	}
}

func TestHostEnrollmentUndoDoesNotOverwriteLatePreviousCollision(t *testing.T) {
	dir, m, l := undoFixture(t, false)
	serial := readLeaf(t, filepath.Join(dir, "host.crt")).SerialNumber.Text(16)
	target := filepath.Join(dir, "host.d", serial)
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host.crt", "host.key"} {
		if err := os.WriteFile(filepath.Join(target, name), mustReadFile(t, filepath.Join(dir, name)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := undoObserved(t, dir)
	fired := false
	trustDurabilitySeam = func(at string) error {
		if at == "reopen" && !fired {
			fired = true
			return os.WriteFile(filepath.Join(target, "host.key"), []byte("foreign late key"), 0600)
		}
		return nil
	}
	defer func() { trustDurabilitySeam = nil }()
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
	trustDurabilitySeam = nil
	if err == nil {
		t.Fatal("late previous-serial collision was overwritten")
	}
	if string(mustReadFile(t, filepath.Join(target, "host.key"))) != "foreign late key" {
		t.Fatal("late foreign retained key overwritten")
	}
	if u != nil {
		if err := u.Restore(context.Background(), l); err != nil {
			t.Fatal(err)
		}
	}
	if undoObserved(t, dir) != before {
		t.Fatal("late foreign collision changed active preimage")
	}
}

func TestHostEnrollmentUndoRetainsOwnFilledInertCurrent(t *testing.T) {
	for _, layout := range []string{"previous-empty", "previous-partial", "next-empty"} {
		for _, stage := range []string{"success", "copied-legacy", "current-created", "linked-host.key", "linked-host.crt"} {
			t.Run(layout+"/"+stage, func(t *testing.T) {
				dir, m, l := undoFixture(t, false)
				serial := readLeaf(t, filepath.Join(dir, "host.crt")).SerialNumber.Text(16)
				if layout == "next-empty" {
					serial = m.leaf.SerialNumber.Text(16)
				}
				if err := os.MkdirAll(filepath.Join(dir, "host.d"), 0700); err != nil {
					t.Fatal(err)
				}
				if layout == "previous-partial" {
					if err := os.MkdirAll(filepath.Join(dir, "host.d", serial), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "host.d", serial, "host.crt"), mustReadFile(t, filepath.Join(dir, "host.crt")), 0644); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(serial, filepath.Join(dir, "host.d/current")); err != nil {
					t.Fatal(err)
				}
				before := undoObserved(t, dir)
				injected := errors.New("own filled inert current prefix")
				hit := false
				swapCrashHook = func(at string) error {
					if at == stage {
						hit = true
						return injected
					}
					return nil
				}
				defer func() { swapCrashHook = nil }()
				u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
				swapCrashHook = nil
				if stage == "success" {
					if err != nil {
						t.Fatal(err)
					}
				} else if !hit || !errors.Is(err, injected) {
					t.Fatal("missing own filled prefix", err)
				}
				if u == nil {
					t.Fatal("lost receipt")
				}
				if err := u.Restore(context.Background(), l); err != nil {
					t.Fatal("cannot retain own filled pair and restore fixed preimages", err)
				}
				if undoObserved(t, dir) != before {
					t.Fatal("raw original endpoints changed")
				}
				for _, name := range []string{"host.crt", "host.key"} {
					if _, err := os.Stat(filepath.Join(dir, "host.d", serial, name)); err != nil {
						t.Fatal("own filled retained pair erased", err)
					}
				}
			})
		}
	}
}

func TestHostEnrollmentUndoBoundsAllCapturedAndAdmittedBytes(t *testing.T) {
	dir, m, l := undoFixture(t, false)
	padded := func(b []byte) []byte { return append(bytes.Clone(b), bytes.Repeat([]byte(" "), (1<<20)-len(b))...) }
	large, err := ValidateHostEnrollment(m.host, padded(m.ca), padded(m.cert), padded(m.key))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), padded(mustReadFile(t, filepath.Join(dir, name))), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := undoObserved(t, dir)
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, large, l, undoTestSuffix)
	if err == nil || u != nil {
		t.Fatal("aggregate receipt accepted more than 5MiB captured plus admitted bytes")
	}
	if undoObserved(t, dir) != before {
		t.Fatal("oversized receipt changed active files")
	}
}

// Measure the distinct reachable credential payload byte ranges, rather than
// repeating prepare's input sum. Equal bytes in separate allocations count
// separately; aliases and overlapping views count once. Shared owner state and
// fixed Go bookkeeping are not receipt-owned credential payloads.
func reachableUndoPayload(u *HostEnrollmentUndo) int {
	type span struct{ start, end uintptr }
	var spans []span
	add := func(b []byte) {
		if len(b) > 0 {
			start := reflect.ValueOf(b).Pointer()
			spans = append(spans, span{start, start + uintptr(len(b))})
		}
	}
	image := func(v enrollmentImage) {
		for _, n := range v.paths {
			add(n.body)
		}
		for _, n := range v.current {
			add(n.body)
		}
	}
	add(u.ca)
	image(u.before)
	for _, v := range u.possible {
		image(v)
	}
	for _, n := range u.restoreCurrent {
		add(n.body)
	}
	for _, pair := range []enrollmentPair{u.previous, u.next} {
		add(pair.cert.body)
		add(pair.key.body)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	total := 0
	var end uintptr
	for _, s := range spans {
		if s.start >= end {
			total += int(s.end - s.start)
			end = s.end
		} else if s.end > end {
			total += int(s.end - end)
			end = s.end
		}
	}
	return total
}

func TestHostEnrollmentUndoNearLimitUsesOwnedPayloadStorage(t *testing.T) {
	dir, m, l := undoFixture(t, false)
	pad := func(b []byte, size int) []byte {
		return append(bytes.Clone(b), bytes.Repeat([]byte(" "), size-len(b))...)
	}
	near, err := ValidateHostEnrollment(m.host, pad(m.ca, (1<<20)-4096), pad(m.cert, (1<<20)-4096), pad(m.key, (1<<20)-4096))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		size int
	}{{"ca.crt", 1 << 20}, {"host.crt", (1 << 19) - 2048}, {"host.key", (1 << 19) - 2048}} {
		if err := os.WriteFile(filepath.Join(dir, item.name), pad(mustReadFile(t, filepath.Join(dir, item.name)), item.size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := undoObserved(t, dir)
	u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, near, l, undoTestSuffix)
	if err != nil || u == nil {
		t.Fatal("within-limit current install refused", err)
	}
	if !bytes.Equal(mustReadFile(t, filepath.Join(dir, "ca.crt")), near.ca) {
		t.Fatal("actual CA publication not reached")
	}
	afterInstall := reachableUndoPayload(u)
	t.Logf("distinct reachable payload after CA publication=%d limit=%d", afterInstall, 5<<20)
	if afterInstall > 5<<20 {
		t.Errorf("receipt retained payload exceeds 5MiB after CA publication: %d", afterInstall)
	}
	if err := u.Restore(context.Background(), l); err != nil {
		t.Fatal("near-limit undo failed", err)
	}
	if undoObserved(t, dir) != before {
		t.Fatal("near-limit undo changed original bytes/topology/modes")
	}
	afterRestore := reachableUndoPayload(u)
	t.Logf("distinct reachable payload after undo=%d", afterRestore)
	if afterRestore > 5<<20 {
		t.Errorf("receipt retained payload exceeds 5MiB after undo: %d", afterRestore)
	}
	if err := u.Complete(); err != nil {
		t.Fatal(err)
	}
}

func TestHostEnrollmentUndoCompleteRequiresCurrentDurableSuccess(t *testing.T) {
	t.Run("successful-install-dispose", func(t *testing.T) {
		dir, m, l := undoFixture(t, false)
		u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := u.Complete(); err != nil {
			t.Fatal("successful install cannot dispose", err)
		}
		if err := u.Restore(context.Background(), l); err == nil {
			t.Fatal("disposed successful install still restores")
		}
	})
	for _, state := range []string{"landed-restore-removal", "previous-restore-success"} {
		t.Run(state, func(t *testing.T) {
			dir, m, l := undoFixture(t, false)
			before := undoObserved(t, dir)
			u, err := InstallHostEnrollmentWithUndo(context.Background(), dir, m, l, undoTestSuffix)
			if err != nil {
				t.Fatal(err)
			}
			if state == "previous-restore-success" {
				if err := u.Restore(context.Background(), l); err != nil {
					t.Fatal(err)
				}
			}
			injected := errors.New("interrupted current restore")
			hit := false
			trustDurabilitySeam = func(at string) error {
				if state == "landed-restore-removal" && at == "directory-sync:"+dir {
					_, err := os.Lstat(filepath.Join(dir, "host.key"))
					if os.IsNotExist(err) {
						hit = true
						return injected
					}
				}
				if state == "previous-restore-success" && at == "file-sync" {
					hit = true
					return injected
				}
				return nil
			}
			defer func() { trustDurabilitySeam = nil }()
			err = u.Restore(context.Background(), l)
			trustDurabilitySeam = nil
			if !hit || !errors.Is(err, injected) {
				t.Fatalf("current restore did not fail at actual local boundary: %v", err)
			}
			if state == "landed-restore-removal" {
				if _, err := os.Lstat(filepath.Join(dir, "host.key")); !os.IsNotExist(err) {
					t.Fatal("restore failure did not follow landed removal", err)
				}
			}
			if err := u.Complete(); err == nil {
				t.Fatal("Complete accepted interrupted Restore and destroyed retry authority")
			}
			if err := u.Restore(context.Background(), l); err != nil {
				t.Fatal("failed restore lost retry authority", err)
			}
			if undoObserved(t, dir) != before {
				t.Fatal("restore retry did not recover exact original")
			}
			if err := u.Complete(); err != nil {
				t.Fatal("successful restore retry cannot dispose", err)
			}
			if err := u.Restore(context.Background(), l); err == nil {
				t.Fatal("completed restore retry still restores")
			}
		})
	}
}
