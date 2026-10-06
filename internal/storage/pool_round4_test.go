package storage

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mountInfoWith makes the mount table hold one mount at dir: an export (source)
// of fstype with per-mount options flags.
func mountInfoWith(t *testing.T, dir, flags, fstype, source string) {
	t.Helper()
	prev := readMountInfo
	readMountInfo = func() ([]byte, error) {
		return []byte(fmt.Sprintf("36 1 0:50 / %s %s shared:7 - %s %s rw,vers=4.2\n",
			strings.ReplaceAll(dir, " ", "\\040"), flags, fstype, source)), nil
	}
	t.Cleanup(func() { readMountInfo = prev })
}

const hardenedFlags = "rw,nosuid,nodev,noexec,nosymfollow,relatime"

// IMP-2: a hardened mount already at the pool's mount point is used only when
// it is this pool's export. Another export there — left by a deleted pool, or
// mounted by hand — is refused at Prepare and by the pool check, and nothing
// is mounted over it.
func TestNFSMountOfAnotherExportIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, fstype, mounted string
		wantErr               bool
	}{
		{"another export", "nfs4", "nas:/bravo", true},
		{"a parent export", "nfs4", "nas:/", true},
		{"another server", "nfs4", "nas2:/acme", true},
		{"not NFS, under the export's name", "fuse.sshfs", "nas:/acme", true},
		{"the same export", "nfs4", "nas:/acme", false},
		{"the same export over NFSv3", "nfs", "nas:/acme", false},
		{"the same export, spelled differently", "nfs4", "NAS:/acme/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mountInfoWith(t, dir, hardenedFlags, tc.fstype, tc.mounted)
			var ran []string
			d := &nfsDriver{source: "nas:/acme", targetOverride: dir, opts: map[string]string{},
				run: func(_ context.Context, cmd string, args ...string) ([]byte, error) {
					if cmd != "mountpoint" {
						ran = append(ran, cmd)
					}
					return nil, nil // a mount point
				}}
			err := d.Prepare(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Prepare with %s mounted = %v, wantErr %v", tc.mounted, err, tc.wantErr)
			}
			if len(ran) != 0 {
				t.Fatalf("ran %q over an existing mount", ran)
			}
			cerr := CheckNFSMountHardened(t.TempDir(), Config{Driver: "nfs", Source: "nas:/acme", Target: dir})
			if (cerr != nil) != tc.wantErr {
				t.Fatalf("pool check with %s mounted = %v, wantErr %v", tc.mounted, cerr, tc.wantErr)
			}
		})
	}
}

// IMP-1: one export is recognised under every spelling of it.
func TestParseNFSExportIsCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"nas:/x":                   "nas:/x",
		"NAS.Corp.LAN:/x/":         "nas.corp.lan:/x",
		"nas:/x//y/./z/..":         "nas:/x/y",
		"nas:/":                    "nas:/",
		"10.0.0.5:/x":              "10.0.0.5:/x",
		"[FE80::A]:/x":             "[fe80::a]:/x",
		"[fe80:0:0::1]:/x":         "[fe80::1]:/x",
		"[2001:DB8:0:0:0:0:0:5]:/": "[2001:db8::5]:/",
		"[::ffff:10.0.0.5]:/x":     "10.0.0.5:/x",
	} {
		e, err := ParseNFSExport(in)
		if err != nil {
			t.Errorf("ParseNFSExport(%q): %v", in, err)
			continue
		}
		if e.String() != want || NFSExportKey(in) != want {
			t.Errorf("ParseNFSExport(%q) = %s (key %s), want %s", in, e, NFSExportKey(in), want)
		}
	}
	for _, in := range []string{"", "nas", "nas:x", ":/x", "[fe80::1/x", "[nas]:/x", "[fe80::1%eth0]:/x"} {
		if e, err := ParseNFSExport(in); err == nil {
			t.Errorf("ParseNFSExport(%q) = %s, want an error", in, e)
		}
	}
}

// IMP-1: export paths overlap when equal or nested either way; "/" (an NFSv4
// pseudo-root) contains every export. Siblings and prefixes do not overlap.
func TestNFSExportPathsOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"nas:/x", "nas:/x", true},
		{"nas:/tenants", "nas:/tenants/acme", true},
		{"nas:/tenants/acme", "nas:/tenants", true},
		{"nas:/", "nas:/srv/nfs/acme", true},
		{"nas:/tenants/acme", "nas:/tenants/acme2", false},
		{"nas:/a", "nas:/b", false},
	} {
		a, _ := ParseNFSExport(tc.a)
		b, _ := ParseNFSExport(tc.b)
		if got := a.PathsOverlap(b); got != tc.want {
			t.Errorf("%s overlaps %s = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// IMP-1: an address is itself (no lookup); a name is looked up, and resolving
// to nothing is an error. Servers sharing any address are one server.
func TestResolveNFSServer(t *testing.T) {
	var looked []string
	defer OverrideNFSResolverForTest(func(_ context.Context, host string) ([]netip.Addr, error) {
		looked = append(looked, host)
		switch host {
		case "nas":
			return []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.5"), netip.MustParseAddr("10.0.0.9")}, nil
		case "empty":
			return nil, nil
		}
		return nil, errors.New("no such host")
	})()
	ip, err := ResolveNFSServer(context.Background(), "10.0.0.5")
	if err != nil || len(looked) != 0 {
		t.Fatalf("an address: %v %v, looked up %q", ip, err, looked)
	}
	nas, err := ResolveNFSServer(context.Background(), "nas")
	if err != nil {
		t.Fatal(err)
	}
	if !SharesAddress(ip, nas) {
		t.Errorf("nas %v and 10.0.0.5 share no address", nas)
	}
	other, _ := ResolveNFSServer(context.Background(), "10.0.0.7")
	if SharesAddress(other, nas) {
		t.Errorf("10.0.0.7 shares an address with nas %v", nas)
	}
	for _, h := range []string{"ghost", "empty"} {
		if a, err := ResolveNFSServer(context.Background(), h); err == nil {
			t.Errorf("%s resolved to %v, want an error", h, a)
		}
	}
}

// IMP-2: a directory pool on an NFS mount — the mount point or below it,
// directly or through a symlink — is refused; one on a local filesystem, or
// on a local mount inside an NFS one, is not.
func TestCheckNotOnNFS(t *testing.T) {
	nfs := t.TempDir()
	local := t.TempDir()
	inner := filepath.Join(nfs, "disk")
	if err := os.MkdirAll(filepath.Join(nfs, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(local, "link")
	if err := os.Symlink(filepath.Join(nfs, "sub"), link); err != nil {
		t.Fatal(err)
	}
	prev := readMountInfo
	readMountInfo = func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+
			"40 1 0:60 / %s %s - nfs4 nas:/bravo rw\n"+
			"41 40 8:2 / %s rw - ext4 /dev/sdb1 rw\n", nfs, hardenedFlags, inner)), nil
	}
	defer func() { readMountInfo = prev }()
	for dir, wantErr := range map[string]bool{
		nfs:                        true,
		filepath.Join(nfs, "sub"):  true,
		filepath.Join(nfs, "new"):  true,
		link:                       true,
		local:                      false,
		inner:                      false,
		filepath.Join(inner, "vm"): false,
	} {
		if err := CheckNotOnNFS(dir); (err != nil) != wantErr {
			t.Errorf("CheckNotOnNFS(%s) = %v, wantErr %v", dir, err, wantErr)
		}
	}
}
