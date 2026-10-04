package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The clone identity reset runs as root against a rootfs whose contents the
// tenant controls. These tests plant guest symlinks aimed at a sentinel file
// OUTSIDE the rootfs and assert the daemon never writes through them.

const sentinelContent = "root:$6$do-not-touch:19000:0:99999:7:::\n"

// cloneFixture lays out <lxcpath>/src/{config,rootfs} plus a sentinel file
// outside lxcpath entirely, runs plant against the source rootfs, clones src to
// dst, and returns the clone's rootfs and the sentinel path.
func cloneFixture(t *testing.T, plant func(rootfs, sentinel string)) (dstRootfs, sentinel string) {
	t.Helper()
	base := t.TempDir()
	sentinel = filepath.Join(base, "host-etc", "shadow")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte(sentinelContent), 0o600); err != nil {
		t.Fatal(err)
	}
	lxcpath := filepath.Join(base, "lxc")
	srcRootfs := filepath.Join(lxcpath, "src", "rootfs")
	for _, d := range []string{"etc", "var/lib/dbus", "bin", "usr"} {
		if err := os.MkdirAll(filepath.Join(srcRootfs, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "lxc.uts.name = src\nlxc.rootfs.path = dir:" + srcRootfs + "\n"
	if err := os.WriteFile(filepath.Join(lxcpath, "src", "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	plant(srcRootfs, sentinel)
	r := &LxcRunner{Lxcpath: lxcpath}
	if err := r.CloneContainer(context.Background(), "src", "dst"); err != nil {
		t.Fatalf("CloneContainer: %v", err)
	}
	return filepath.Join(lxcpath, "dst", "rootfs"), sentinel
}

func assertSentinelIntact(t *testing.T, sentinel string) {
	t.Helper()
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("sentinel %s: %v", sentinel, err)
	}
	if string(got) != sentinelContent {
		t.Fatalf("host file outside the rootfs was modified through a guest symlink: %q", got)
	}
}

// assertRegular checks rel inside rootfs is a regular file (not a symlink)
// holding want.
func assertRegular(t *testing.T, rootfs, rel, want string) {
	t.Helper()
	p := filepath.Join(rootfs, rel)
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("%s is %v, want a regular file", rel, fi.Mode().Type())
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", rel, got, want)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestCloneIdentity_NoSymlinks_WritesIdentity(t *testing.T) {
	rootfs, sentinel := cloneFixture(t, func(rootfs, _ string) {
		if err := os.WriteFile(filepath.Join(rootfs, "etc/hostname"), []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
			if err := os.WriteFile(filepath.Join(rootfs, f), []byte("old\n"), 0o444); err != nil {
				t.Fatal(err)
			}
		}
	})
	assertSentinelIntact(t, sentinel)
	assertRegular(t, rootfs, "etc/hostname", "dst\n")
	assertRegular(t, rootfs, "etc/machine-id", "")
	assertRegular(t, rootfs, "var/lib/dbus/machine-id", "")
	// The source's file mode survives the rewrite.
	if fi, _ := os.Stat(filepath.Join(rootfs, "etc/machine-id")); fi.Mode().Perm() != 0o444 {
		t.Errorf("machine-id mode = %v, want 0444", fi.Mode().Perm())
	}
}

func TestCloneIdentity_MissingMachineIDStaysMissing(t *testing.T) {
	rootfs, _ := cloneFixture(t, func(string, string) {})
	assertRegular(t, rootfs, "etc/hostname", "dst\n")
	for _, f := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		if _, err := os.Lstat(filepath.Join(rootfs, f)); !os.IsNotExist(err) {
			t.Errorf("%s created on a guest that had none (err=%v)", f, err)
		}
	}
}

func TestCloneIdentity_AbsoluteFinalSymlinks(t *testing.T) {
	rootfs, sentinel := cloneFixture(t, func(rootfs, sentinel string) {
		for _, f := range []string{"etc/hostname", "etc/machine-id", "var/lib/dbus/machine-id"} {
			symlink(t, sentinel, filepath.Join(rootfs, f))
		}
	})
	assertSentinelIntact(t, sentinel)
	assertRegular(t, rootfs, "etc/hostname", "dst\n")
	assertRegular(t, rootfs, "etc/machine-id", "")
	assertRegular(t, rootfs, "var/lib/dbus/machine-id", "")
}

func TestCloneIdentity_RelativeFinalSymlinks(t *testing.T) {
	rootfs, sentinel := cloneFixture(t, func(rootfs, sentinel string) {
		for _, f := range []string{"etc/hostname", "etc/machine-id", "var/lib/dbus/machine-id"} {
			link := filepath.Join(rootfs, f)
			rel, err := filepath.Rel(filepath.Dir(link), sentinel)
			if err != nil {
				t.Fatal(err)
			}
			// Re-anchor at the clone: the link is copied verbatim, and the clone
			// sits at the same depth as the source, so the same ../ chain escapes.
			if !strings.HasPrefix(rel, "..") {
				t.Fatalf("relative link %q does not climb out of the rootfs", rel)
			}
			symlink(t, rel, link)
		}
	})
	assertSentinelIntact(t, sentinel)
	assertRegular(t, rootfs, "etc/hostname", "dst\n")
	assertRegular(t, rootfs, "etc/machine-id", "")
	assertRegular(t, rootfs, "var/lib/dbus/machine-id", "")
}

func TestCloneIdentity_SymlinkedParentDirs(t *testing.T) {
	_, sentinel := cloneFixture(t, func(rootfs, sentinel string) {
		hostEtc := filepath.Dir(sentinel)
		// The guest's etc and var/lib/dbus point at the host's directory, so the
		// identity files resolve to <host-etc>/hostname and <host-etc>/machine-id.
		if err := os.WriteFile(filepath.Join(hostEtc, "machine-id"), []byte(sentinelContent), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(rootfs, "etc")); err != nil {
			t.Fatal(err)
		}
		symlink(t, hostEtc, filepath.Join(rootfs, "etc"))
		if err := os.RemoveAll(filepath.Join(rootfs, "var/lib/dbus")); err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(filepath.Join(rootfs, "var/lib"), hostEtc)
		if err != nil {
			t.Fatal(err)
		}
		symlink(t, rel, filepath.Join(rootfs, "var/lib/dbus"))
	})
	assertSentinelIntact(t, sentinel)
	assertSentinelIntact(t, filepath.Join(filepath.Dir(sentinel), "machine-id"))
	if _, err := os.Lstat(filepath.Join(filepath.Dir(sentinel), "hostname")); !os.IsNotExist(err) {
		t.Fatalf("hostname written into the host directory behind a guest etc symlink (err=%v)", err)
	}
}

// configureGuestStaticIP writes etc/network/interfaces into a rootfs that may
// come from a pulled (untrusted) image.
func TestConfigureGuestStaticIP_DoesNotFollowSymlinks(t *testing.T) {
	nics := []NetworkAttach{{IP: "10.0.3.5/24"}}
	for _, tc := range []struct {
		name  string
		plant func(rootfs, sentinel string)
	}{
		{"final", func(rootfs, sentinel string) {
			if err := os.MkdirAll(filepath.Join(rootfs, "etc/network"), 0o755); err != nil {
				t.Fatal(err)
			}
			symlink(t, sentinel, filepath.Join(rootfs, "etc/network/interfaces"))
		}},
		{"parent", func(rootfs, sentinel string) {
			if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			symlink(t, filepath.Dir(sentinel), filepath.Join(rootfs, "etc/network"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			sentinel := filepath.Join(base, "host", "interfaces")
			if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sentinel, []byte(sentinelContent), 0o644); err != nil {
				t.Fatal(err)
			}
			rootfs := filepath.Join(base, "rootfs")
			tc.plant(rootfs, sentinel)
			err := configureGuestStaticIP(rootfs, nics)
			assertSentinelIntact(t, sentinel)
			if tc.name == "final" {
				if err != nil {
					t.Fatalf("configureGuestStaticIP: %v", err)
				}
				fi, lerr := os.Lstat(filepath.Join(rootfs, "etc/network/interfaces"))
				if lerr != nil || !fi.Mode().IsRegular() {
					t.Fatalf("interfaces not replaced by a regular file: %v %v", fi, lerr)
				}
			} else if err == nil {
				t.Fatal("expected an error for an etc/network symlink escaping the rootfs")
			}
		})
	}
}

func TestConfigureGuestStaticIP_WritesInterfaces(t *testing.T) {
	rootfs := t.TempDir()
	if err := configureGuestStaticIP(rootfs, []NetworkAttach{{IP: "10.0.3.5/24"}}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(rootfs, "etc/network/interfaces"))
	if err != nil || !strings.Contains(string(got), "address 10.0.3.5") {
		t.Fatalf("interfaces = %q, %v", got, err)
	}
}
