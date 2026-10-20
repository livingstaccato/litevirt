package libvirt

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testSwtpmBase is a swtpm root for the test (the real /var/lib/libvirt/swtpm
// is root-owned).
func testSwtpmBase(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// storeAt is the firmware store with these roots.
func storeAt(swtpmBase, dataDir string) *FirmwareStore {
	return &FirmwareStore{DataDir: dataDir, SwtpmBase: swtpmBase}
}

func seedFirmware(t *testing.T, st *FirmwareStore, vm, uuid string, nvram, tpm bool) {
	t.Helper()
	if nvram {
		p := st.NvramPath(vm)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("NVRAM-"+vm), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if tpm {
		d := filepath.Join(st.SwtpmDir(uuid), "tpm2")
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "tpm2-00.permall"), []byte("TPM-"+uuid), 0o600); err != nil {
			t.Fatal(err)
		}
		// swtpm leaves a runtime .lock file in the state dir; it must NOT be carried.
		if err := os.WriteFile(filepath.Join(d, ".lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFirmwareBundle_RoundTrip(t *testing.T) {
	base := testSwtpmBase(t)
	for _, tc := range []struct{ nvram, tpm bool }{
		{true, true}, {true, false}, {false, true},
	} {
		src := storeAt(base, t.TempDir())
		seedFirmware(t, src, "src", "uuid-src", tc.nvram, tc.tpm)

		var buf bytes.Buffer
		has, err := src.WriteFirmwareBundle("src", "uuid-src", &buf)
		if err != nil {
			t.Fatalf("write bundle (nvram=%v tpm=%v): %v", tc.nvram, tc.tpm, err)
		}
		if !has {
			t.Fatalf("expected state present (nvram=%v tpm=%v)", tc.nvram, tc.tpm)
		}

		// Restore into a DIFFERENT vm name + uuid (proves name/uuid re-addressing).
		dst := storeAt(base, t.TempDir())
		if err := dst.ReadFirmwareBundle(&buf, "dst", "uuid-dst"); err != nil {
			t.Fatalf("read bundle: %v", err)
		}
		if tc.nvram {
			got, _ := os.ReadFile(dst.NvramPath("dst"))
			if string(got) != "NVRAM-src" {
				t.Errorf("nvram restored = %q, want NVRAM-src", got)
			}
		}
		if tc.tpm {
			got, _ := os.ReadFile(filepath.Join(dst.SwtpmDir("uuid-dst"), "tpm2", "tpm2-00.permall"))
			if string(got) != "TPM-uuid-src" {
				t.Errorf("swtpm restored = %q, want TPM-uuid-src", got)
			}
			// The per-UUID dir must be world-traversable (0711) so the dropped-
			// privilege swtpm user can reach its state (live-drill regression).
			fi, err := os.Stat(dst.SwtpmDir("uuid-dst"))
			if err != nil {
				t.Fatalf("stat restored swtpm dir: %v", err)
			}
			if perm := fi.Mode().Perm(); perm != 0o711 {
				t.Errorf("restored swtpm dir mode = %o, want 711", perm)
			}
			// The runtime .lock must NOT have been carried into the restore.
			if _, err := os.Stat(filepath.Join(dst.SwtpmDir("uuid-dst"), "tpm2", ".lock")); !os.IsNotExist(err) {
				t.Errorf("restored swtpm state must not contain a .lock file (err=%v)", err)
			}
		}
	}
}

func TestWriteFirmwareBundle_NoState(t *testing.T) {
	has, err := storeAt(testSwtpmBase(t), t.TempDir()).WriteFirmwareBundle("novm", "nouuid", &bytes.Buffer{})
	if err != nil || has {
		t.Fatalf("expected (false,nil) for a VM with no firmware state, got (%v,%v)", has, err)
	}
}

func TestWipeFirmwareState(t *testing.T) {
	st := storeAt(testSwtpmBase(t), t.TempDir())
	seedFirmware(t, st, "vm", "uuid-w", true, true)
	if !st.HasNvram("vm") || !st.HasTPMState("uuid-w") {
		t.Fatal("seed failed")
	}
	st.WipeFirmwareState("vm", "uuid-w")
	if st.HasNvram("vm") {
		t.Error("nvram not wiped")
	}
	if st.HasTPMState("uuid-w") {
		t.Error("swtpm state not wiped")
	}
}

func TestReadFirmwareBundle_RejectsOversizedNvram(t *testing.T) {
	base := testSwtpmBase(t)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	// Header claims a huge size; actual data is small. The size check must fire.
	tw.WriteHeader(&tar.Header{Name: "nvram", Mode: 0o600, Size: 128 << 20, Typeflag: tar.TypeReg})
	tw.Write([]byte("small"))
	tw.Close()
	if err := storeAt(base, t.TempDir()).ReadFirmwareBundle(&b, "vm", "uuid"); err == nil {
		t.Fatal("expected rejection of oversized nvram member, got nil")
	}
}

func TestRestore_OverExistingState(t *testing.T) {
	base := testSwtpmBase(t)
	// Bundle from a source.
	src := storeAt(base, t.TempDir())
	seedFirmware(t, src, "src", "uuid-s", true, true)
	var buf bytes.Buffer
	if _, err := src.WriteFirmwareBundle("src", "uuid-s", &buf); err != nil {
		t.Fatal(err)
	}
	// Destination already has DIFFERENT firmware state — restore must swap it.
	dst := storeAt(base, t.TempDir())
	seedFirmware(t, dst, "dst", "uuid-d", true, true)
	os.WriteFile(dst.NvramPath("dst"), []byte("OLD-NVRAM"), 0o600)
	if err := dst.ReadFirmwareBundle(&buf, "dst", "uuid-d"); err != nil {
		t.Fatalf("restore over existing: %v", err)
	}
	got, _ := os.ReadFile(dst.NvramPath("dst"))
	if string(got) != "NVRAM-src" {
		t.Errorf("nvram after swap = %q, want NVRAM-src", got)
	}
	// No backup files left behind on success.
	if _, err := os.Stat(dst.NvramPath("dst") + ".bak"); err == nil {
		t.Error("nvram .bak left behind after successful swap")
	}
	if _, err := os.Stat(dst.SwtpmDir("uuid-d") + ".bak"); err == nil {
		t.Error("swtpm .bak left behind after successful swap")
	}
}

func TestRetainedFirmwareMarker(t *testing.T) {
	st := storeAt(testSwtpmBase(t), t.TempDir())
	if _, ok := st.ReadRetainedFirmwareMarker("vm"); ok {
		t.Fatal("unexpected marker before write")
	}
	if err := st.WriteRetainedFirmwareMarker("vm", "uuid-keep"); err != nil {
		t.Fatal(err)
	}
	got, ok := st.ReadRetainedFirmwareMarker("vm")
	if !ok || got != "uuid-keep" {
		t.Fatalf("marker = %q,%v, want uuid-keep,true", got, ok)
	}
	// WipeFirmwareState clears the marker too.
	st.WipeFirmwareState("vm", "uuid-keep")
	if _, ok := st.ReadRetainedFirmwareMarker("vm"); ok {
		t.Error("marker not removed by WipeFirmwareState")
	}
}

// ReadFirmwareBundle must reject untrusted/slip entries (a backup-repo bundle).
func TestReadFirmwareBundle_RejectsSlip(t *testing.T) {
	base := testSwtpmBase(t)
	mk := func(build func(tw *tar.Writer)) *bytes.Buffer {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		build(tw)
		tw.Close()
		return &b
	}
	cases := map[string]*bytes.Buffer{
		"escaping swtpm path": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "swtpm/../../etc/evil", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
		"dotdot-prefixed nvram": mk(func(tw *tar.Writer) {
			// Must be rejected, NOT silently re-rooted to "nvram".
			tw.WriteHeader(&tar.Header{Name: "../nvram", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
		"absolute nvram": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "/nvram", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
		"symlink member": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "nvram", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		}),
		"unexpected entry": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "evil", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
	}
	for name, buf := range cases {
		if err := storeAt(base, t.TempDir()).ReadFirmwareBundle(buf, "vm", "uuid-x"); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TestPermallSHA256_IgnoresLock (T-4): the TPM verdict of a live firmware move
// is the sha256 of tpm2-00.permall alone. swtpm's .lock and any other file in
// the tree are not part of it; a missing permall is os.ErrNotExist, so a
// caller can tell "no state" from "unreadable".
func TestPermallSHA256_IgnoresLock(t *testing.T) {
	st := storeAt(testSwtpmBase(t), t.TempDir())
	const uuid = "5113ced7-9006-4086-b7dd-9d1840181e03"
	tpm2 := filepath.Join(st.SwtpmDir(uuid), "tpm2")
	if err := os.MkdirAll(tpm2, 0o700); err != nil {
		t.Fatal(err)
	}
	permall := []byte("PERMALL-STATE-v1")
	write := func(p string, b []byte) {
		t.Helper()
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(tpm2, "tpm2-00.permall"), permall)
	write(filepath.Join(tpm2, ".lock"), []byte("lock-1"))
	write(filepath.Join(st.SwtpmDir(uuid), ".lock"), []byte("lock-1"))
	write(filepath.Join(tpm2, "tpm2-00.volatilestate"), []byte("volatile"))

	got, err := st.PermallSHA256(uuid)
	if err != nil {
		t.Fatalf("PermallSHA256: %v", err)
	}
	if want := sha256Hex(permall); got != want {
		t.Fatalf("PermallSHA256 = %s, want sha256(permall) = %s", got, want)
	}

	// The lock and the other files change; the hash does not.
	write(filepath.Join(tpm2, ".lock"), []byte("lock-2-longer"))
	write(filepath.Join(st.SwtpmDir(uuid), ".lock"), []byte("lock-2-longer"))
	write(filepath.Join(tpm2, "tpm2-00.volatilestate"), []byte("volatile-2"))
	if again, err := st.PermallSHA256(uuid); err != nil || again != got {
		t.Fatalf("hash moved with the lock/volatile files: %s, %v (was %s)", again, err, got)
	}

	// The permall changes by one byte; the hash does.
	write(filepath.Join(tpm2, "tpm2-00.permall"), []byte("PERMALL-STATE-v2"))
	if moved, err := st.PermallSHA256(uuid); err != nil || moved == got {
		t.Fatalf("hash did not follow the permall: %s, %v", moved, err)
	}

	// No permall: os.ErrNotExist, even with the tree present.
	if err := os.Remove(filepath.Join(tpm2, "tpm2-00.permall")); err != nil {
		t.Fatal(err)
	}
	if h, err := st.PermallSHA256(uuid); !errors.Is(err, os.ErrNotExist) || h != "" {
		t.Fatalf("missing permall: got %q, %v; want \"\", os.ErrNotExist", h, err)
	}
	if h, err := st.PermallSHA256("6113ced7-9006-4086-b7dd-9d1840181e03"); !errors.Is(err, os.ErrNotExist) || h != "" {
		t.Fatalf("missing tree: got %q, %v; want \"\", os.ErrNotExist", h, err)
	}

	// A key that is not one component under the base is refused, never read.
	for _, bad := range []string{"", ".", "..", "../" + uuid, uuid + "/tpm2"} {
		if h, err := st.PermallSHA256(bad); err == nil || errors.Is(err, os.ErrNotExist) || h != "" {
			t.Errorf("PermallSHA256(%q) = %q, %v; want a refusal that is not ErrNotExist", bad, h, err)
		}
	}

	// A permall that is not a regular file is not hashed through.
	elsewhere := filepath.Join(t.TempDir(), "other")
	write(elsewhere, permall)
	if err := os.Symlink(elsewhere, filepath.Join(tpm2, "tpm2-00.permall")); err != nil {
		t.Fatal(err)
	}
	if h, err := st.PermallSHA256(uuid); err == nil || h != "" {
		t.Fatalf("symlinked permall hashed: %q, %v", h, err)
	}
}

// TestNvramSHA256 (T-4): the NVRAM reader hashes the VM's vars file in this
// store and nothing else.
func TestNvramSHA256(t *testing.T) {
	st := storeAt(testSwtpmBase(t), t.TempDir())
	other := storeAt(testSwtpmBase(t), t.TempDir())
	seedFirmware(t, st, "vm", "", true, false)
	seedFirmware(t, other, "vm", "", true, false)
	if err := os.WriteFile(other.NvramPath("vm"), []byte("OTHER-HOST"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := st.NvramSHA256("vm")
	if err != nil {
		t.Fatalf("NvramSHA256: %v", err)
	}
	if want := sha256Hex([]byte("NVRAM-vm")); got != want {
		t.Fatalf("NvramSHA256 = %s, want %s", got, want)
	}
	if o, _ := other.NvramSHA256("vm"); o == got {
		t.Fatal("two stores gave one hash: the reader is not reading its own store")
	}

	if h, err := st.NvramSHA256("absent"); !errors.Is(err, os.ErrNotExist) || h != "" {
		t.Fatalf("missing NVRAM: got %q, %v; want \"\", os.ErrNotExist", h, err)
	}
	for _, bad := range []string{"", "..", "../vm", "a/b"} {
		if h, err := st.NvramSHA256(bad); err == nil || errors.Is(err, os.ErrNotExist) || h != "" {
			t.Errorf("NvramSHA256(%q) = %q, %v; want a refusal that is not ErrNotExist", bad, h, err)
		}
	}
}
