package cloudinit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exactSeedTools(t *testing.T) (string, string) {
	t.Helper()
	builder, err := exec.LookPath("genisoimage")
	if err != nil {
		t.Fatal("required genisoimage unavailable")
	}
	inspector, err := exec.LookPath("isoinfo")
	if err != nil {
		t.Fatal("required isoinfo unavailable")
	}
	return builder, inspector
}

func exactSeedExtract(t *testing.T, inspector, iso string, want ExactSeed) {
	t.Helper()
	listing, err := exec.Command(inspector, "-R", "-i", iso, "-f").Output()
	if err != nil {
		t.Fatal("actual ISO directory extraction failed")
	}
	present := map[string]bool{}
	for _, name := range strings.Fields(string(listing)) {
		present[name] = true
	}
	expected := map[string][]byte{"user-data": want.UserData, "meta-data": want.MetaData, "network-config": want.NetworkConfig, "vendor-data": want.VendorData}
	count := 0
	for name, data := range expected {
		if data != nil {
			count++
		}
		if present["/"+name] != (data != nil) {
			t.Errorf("actual ISO file presence changed: %s", name)
			continue
		}
		if data == nil {
			continue
		}
		got, err := exec.Command(inspector, "-R", "-i", iso, "-x", "/"+name).Output()
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("actual ISO bytes changed: %s", name)
		}
	}
	if len(present) != count {
		t.Error("actual ISO has unexpected file count")
	}
}

func TestExactSeedFiles(t *testing.T) {
	_, inspector := exactSeedTools(t)
	cases := map[string]ExactSeed{
		"four-binary-crlf":   {UserData: []byte("USER-EXACT\x00\xff\r\n"), MetaData: []byte("instance-id: admitted-uid\r\nlocal-hostname: original\r\n"), NetworkConfig: []byte("NETWORK-EXACT\x00\xfe\r\n"), VendorData: []byte("VENDOR-EXACT\x00\xfd\r\n")},
		"optional-empty":     {UserData: []byte{}, MetaData: []byte("exact metadata\r\n"), NetworkConfig: []byte{}, VendorData: []byte{}},
		"optional-absent":    {UserData: []byte{}, MetaData: []byte{}},
		"network-only-empty": {UserData: []byte("u"), MetaData: []byte("m"), NetworkConfig: []byte{}},
		"vendor-only-empty":  {UserData: []byte("u"), MetaData: []byte("m"), VendorData: []byte{}},
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "seed.iso")
			steps := ObserveSeedWrites(t, filepath.Dir(out))
			if err := GenerateExactISO(seed, out); err != nil {
				t.Fatal("exact seed build failed")
			}
			exactSeedExtract(t, inspector, out, seed)
			isoWriteSteps(t, steps(), out)
			fi, err := os.Stat(out)
			if err != nil || fi.Mode().Perm() != 0600 {
				t.Error("final ISO not private")
			}
		})
	}
}

func TestExactSeedRequiredPresence(t *testing.T) {
	exactSeedTools(t)
	for _, seed := range []ExactSeed{{}, {UserData: []byte{}}, {MetaData: []byte{}}} {
		out := filepath.Join(t.TempDir(), "seed.iso")
		if err := GenerateExactISO(seed, out); err == nil {
			t.Error("absent required file accepted")
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Error("absent required file left an ISO")
		}
	}
}

func TestExactSeedPrivateSources(t *testing.T) {
	real, inspector := exactSeedTools(t)
	bin := t.TempDir()
	record := filepath.Join(bin, "observed")
	// Observe the real source files, then exec the installed ISO builder.
	script := "#!/bin/sh\nfor arg do dir=$arg; done\nprintf '%s\\n' \"$dir\" > \"$EXACT_SEED_RECORD\"\nstat -c %a \"$dir\" \"$dir/user-data\" \"$dir/meta-data\" \"$dir/network-config\" \"$dir/vendor-data\" >> \"$EXACT_SEED_RECORD\"\nexec \"$EXACT_SEED_REAL\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "genisoimage"), []byte(script), 0700); err != nil {
		t.Fatal("observer setup failed")
	}
	t.Setenv("EXACT_SEED_RECORD", record)
	t.Setenv("EXACT_SEED_REAL", real)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	seed := ExactSeed{UserData: []byte("private-user"), MetaData: []byte("private-meta"), NetworkConfig: []byte{}, VendorData: []byte("private-vendor")}
	out := filepath.Join(t.TempDir(), "seed.iso")
	if err := GenerateExactISO(seed, out); err != nil {
		t.Fatal("observed real build failed")
	}
	seen, err := os.ReadFile(record)
	if err != nil {
		t.Fatal("source observer was not reached")
	}
	lines := strings.Split(strings.TrimSpace(string(seen)), "\n")
	if len(lines) != 6 || strings.Join(lines[1:], ",") != "700,600,600,600,600" {
		t.Error("source directory or file modes not private")
	}
	if len(lines) > 0 {
		if _, err := os.Lstat(lines[0]); !os.IsNotExist(err) {
			t.Error("source directory left behind")
		}
	}
	exactSeedExtract(t, inspector, out, seed)
}

func TestExactSeedFailureRedaction(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\nfor arg do dir=$arg; done\ncat \"$dir/user-data\" \"$dir/meta-data\" \"$dir/network-config\" \"$dir/vendor-data\" >&2\nexit 9\n"
	if err := os.WriteFile(filepath.Join(bin, "genisoimage"), []byte(script), 0700); err != nil {
		t.Fatal("failure setup failed")
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	marker := "SUBMITTED-PRIVATE-MARKER"
	seed := ExactSeed{UserData: []byte(marker), MetaData: []byte(marker), NetworkConfig: []byte(marker), VendorData: []byte(marker)}
	out := filepath.Join(t.TempDir(), "seed.iso")
	err := GenerateExactISO(seed, out)
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Error("exact command failure not redacted")
	}
	if err == nil || err.Error() != "exact seed generation failed" {
		t.Error("exact command failure not fixed")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Error("failed build left ISO")
	}
	err = GenerateISO(Config{InstanceID: "legacy", UserData: marker, NetworkConfig: marker, VendorData: marker}, out)
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Error("shared command failure not redacted")
	}
	// A caller-supplied path can also contain private bytes; exact errors hide it.
	parent := filepath.Join(t.TempDir(), marker)
	if err := os.WriteFile(parent, nil, 0600); err != nil {
		t.Fatal("path failure setup failed")
	}
	err = GenerateExactISO(seed, filepath.Join(parent, "seed.iso"))
	if err == nil || err.Error() != "exact seed generation failed" {
		t.Error("exact filesystem failure not fixed")
	}
}

func TestExactSeedSyncFailureCleanup(t *testing.T) {
	exactSeedTools(t)
	for _, stage := range []string{"file", "directory"} {
		t.Run(stage, func(t *testing.T) {
			oldFile, oldDir := fileSync, dirSync
			t.Cleanup(func() { fileSync, dirSync = oldFile, oldDir })
			reached := false
			fail := func(f *os.File) error {
				reached = true
				if err := f.Close(); err != nil {
					t.Fatal("failure setup close failed")
				}
				return f.Sync()
			}
			if stage == "file" {
				fileSync = fail
			} else {
				dirSync = fail
			}
			dir := t.TempDir()
			out := filepath.Join(dir, "seed.iso")
			kept := out + ".kept-original"
			retained := []byte("retained-previous-artifact")
			if err := os.WriteFile(kept, retained, 0600); err != nil {
				t.Fatal("kept setup failed")
			}
			err := GenerateExactISO(ExactSeed{UserData: []byte{}, MetaData: []byte("m")}, out)
			if !reached || err == nil || err.Error() != "exact seed generation failed" {
				t.Error("durability failure acknowledged or not redacted")
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Error("failed new seed left in place")
			}
			got, err := os.ReadFile(kept)
			if err != nil || !bytes.Equal(got, retained) {
				t.Error("kept seed changed")
			}
			temps, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
			if err != nil || len(temps) != 0 {
				t.Error("failed build left temporary ISO")
			}
		})
	}
}
