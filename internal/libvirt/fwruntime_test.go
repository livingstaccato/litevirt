package libvirt

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFirmwareRuntime_Parse pins the version strings a live firmware move
// compares, on the outputs measured on the lab (trackD-probe-results.md):
// libvirt 10.0.0, QEMU 8.2.2, swtpm 0.7.3, libtpms 0.9.3. Anything that is not
// an upstream X.Y.Z is an error, never a guess: libtpms equality rests on the
// mapped file name carrying the release (K-9), so a bare soname refuses.
func TestFirmwareRuntime_Parse(t *testing.T) {
	t.Run("libtpms", func(t *testing.T) {
		ok := map[string]string{
			"libtpms.so.0.9.3":                           "0.9.3",
			"/usr/lib/x86_64-linux-gnu/libtpms.so.0.9.3": "0.9.3",
			"/usr/lib64/libtpms.so.0.10.1":               "0.10.1",
		}
		for in, want := range ok {
			if got, err := ParseLibtpmsSoname(in); err != nil || got != want {
				t.Errorf("ParseLibtpmsSoname(%q) = %q, %v; want %q", in, got, err, want)
			}
		}
		for _, bad := range []string{
			"libtpms.so.0", "libtpms.so", "/usr/lib/x86_64-linux-gnu/libtpms.so.0",
			"libtpms.so.0.9", "libtpms.so.0.9.3.1", "libtpms.so.0.9.3 (deleted)",
			"libswtpm_libtpms.so.0.0.0x", "libtpms.so.0.9.x", "", "libtpms.so.00.9.3",
		} {
			if got, err := ParseLibtpmsSoname(bad); err == nil {
				t.Errorf("ParseLibtpmsSoname(%q) = %q, want an error", bad, got)
			}
		}
	})
	t.Run("qemu", func(t *testing.T) {
		ok := map[string]string{
			"QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)\nCopyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers\n": "8.2.2",
			"QEMU emulator version 9.0.0\n":                        "9.0.0",
			"QEMU emulator version 8.2.50 (v8.2.0-1234-gdeadbeef)": "8.2.50",
		}
		for in, want := range ok {
			if got, err := ParseQEMUVersion(in); err != nil || got != want {
				t.Errorf("ParseQEMUVersion(%q) = %q, %v; want %q", in, got, err, want)
			}
		}
		for _, bad := range []string{
			"", "QEMU emulator version 8.2\n", "QEMU emulator version\n", "qemu-img version 8.2.2\n",
			"something\nQEMU emulator version 8.2.2\n", "QEMU emulator version 8.2.2.1\n",
		} {
			if got, err := ParseQEMUVersion(bad); err == nil {
				t.Errorf("ParseQEMUVersion(%q) = %q, want an error", bad, got)
			}
		}
	})
	t.Run("swtpm", func(t *testing.T) {
		ok := map[string]string{
			"TPM emulator version 0.7.3, Copyright (c) 2014-2022 IBM Corp. and others\n": "0.7.3",
			"TPM emulator version 0.9.0, Copyright (c) 2014-2024 IBM Corp. and others":   "0.9.0",
		}
		for in, want := range ok {
			if got, err := ParseSwtpmVersion(in); err != nil || got != want {
				t.Errorf("ParseSwtpmVersion(%q) = %q, %v; want %q", in, got, err, want)
			}
		}
		for _, bad := range []string{"", "TPM emulator version 0.7, Copyright", "swtpm 0.7.3\n", "TPM emulator version 0.7.3x"} {
			if got, err := ParseSwtpmVersion(bad); err == nil {
				t.Errorf("ParseSwtpmVersion(%q) = %q, want an error", bad, got)
			}
		}
	})
	t.Run("libvirt", func(t *testing.T) {
		ok := map[uint64]string{10000000: "10.0.0", 8009000: "8.9.0", 10010002: "10.10.2"}
		for in, want := range ok {
			if got, err := FormatLibvirtVersion(in); err != nil || got != want {
				t.Errorf("FormatLibvirtVersion(%d) = %q, %v; want %q", in, got, err, want)
			}
		}
		if got, err := FormatLibvirtVersion(0); err == nil {
			t.Errorf("FormatLibvirtVersion(0) = %q, want an error", got)
		}
	})
}

// TestOVMFContentFingerprint: the OVMF fingerprint covers the CONTENT of the
// four firmware files, their paths and dataDir. Two hosts with the same paths
// but a different build of any one file differ; an unreadable configured file
// is an error, not a fingerprint of what could be read.
func TestOVMFContentFingerprint(t *testing.T) {
	dir := t.TempDir()
	mk := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fp := FirmwarePaths{
		Code: mk("OVMF_CODE_4M.fd", "code-2024.02"), Vars: mk("OVMF_VARS_4M.fd", "vars-2024.02"),
		SecbootCode: mk("OVMF_CODE_4M.secboot.fd", "sbcode-2024.02"), MsVars: mk("OVMF_VARS_4M.ms.fd", "msvars-2024.02"),
	}
	base, err := OVMFContentFingerprint(fp, "/var/lib/litevirt")
	if err != nil {
		t.Fatalf("OVMFContentFingerprint: %v", err)
	}
	if again, err := OVMFContentFingerprint(fp, "/var/lib/litevirt"); err != nil || again != base {
		t.Fatalf("not stable: %q, %v vs %q", again, err, base)
	}
	if len(base) != 64 {
		t.Fatalf("fingerprint %q is not a hex sha256", base)
	}

	// One byte of any one file moves it.
	for _, p := range []string{fp.Code, fp.Vars, fp.SecbootCode, fp.MsVars} {
		orig, _ := os.ReadFile(p)
		if err := os.WriteFile(p, append(append([]byte{}, orig[:len(orig)-1]...), orig[len(orig)-1]^1), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := OVMFContentFingerprint(fp, "/var/lib/litevirt"); err != nil || got == base {
			t.Errorf("content change in %s not reflected: %q, %v", filepath.Base(p), got, err)
		}
		if err := os.WriteFile(p, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// dataDir (the NVRAM path the domain names) is part of it.
	if got, _ := OVMFContentFingerprint(fp, "/srv/litevirt"); got == base {
		t.Error("dataDir not part of the fingerprint")
	}

	// A file the host does not have differs from one it has.
	noMs := fp
	noMs.MsVars = ""
	if got, err := OVMFContentFingerprint(noMs, "/var/lib/litevirt"); err != nil || got == base {
		t.Errorf("absent MsVars not reflected: %q, %v", got, err)
	}

	// Swapping two files' roles moves it, though the set of contents is equal.
	swapped := fp
	swapped.Code, swapped.SecbootCode = fp.SecbootCode, fp.Code
	if got, _ := OVMFContentFingerprint(swapped, "/var/lib/litevirt"); got == base {
		t.Error("file roles not part of the fingerprint")
	}

	// A configured file that cannot be read is an error.
	gone := fp
	gone.Vars = filepath.Join(dir, "missing.fd")
	if got, err := OVMFContentFingerprint(gone, "/var/lib/litevirt"); err == nil || got != "" {
		t.Errorf("unreadable Vars: got %q, %v; want an error", got, err)
	}
}
