package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// (re-review rr2 N4) The area roots. The data dir and the "other volume" are
// two temp directories (the reviewer ran it with them on two filesystems,
// RR2_SCRATCH; symlink resolution is the same either way). A pools/ linked to
// a non-system but sensitive directory is the accepted residual: logged.
func TestRR2Probe_AreaRoots(t *testing.T) {
	scratch := os.Getenv("RR2_SCRATCH")
	if scratch == "" {
		scratch = t.TempDir()
	}
	base, err := os.MkdirTemp(scratch, "n4-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	vol := t.TempDir() // on /mnt/vmstore (TMPDIR)
	mk := func(d string) {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, at string) {
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
	}
	type tc struct {
		label string
		setup func(data string) // makes data/pools etc
		probe string            // relative to data
		want  bool
	}
	cases := []tc{
		{"pools -> other volume dir", func(d string) {
			mk(filepath.Join(vol, "p1", "a"))
			link(filepath.Join(vol, "p1"), filepath.Join(d, "pools"))
		}, "pools/a", true},
		{"pools -> link -> other volume dir", func(d string) {
			mk(filepath.Join(vol, "p2", "a"))
			link(filepath.Join(vol, "p2"), filepath.Join(vol, "p2link"))
			link(filepath.Join(vol, "p2link"), filepath.Join(d, "pools"))
		}, "pools/a", true},
		{"pools -> relative link to other volume", func(d string) {
			mk(filepath.Join(vol, "p3", "a"))
			rel, _ := filepath.Rel(d, filepath.Join(vol, "p3"))
			link(rel, filepath.Join(d, "pools"))
		}, "pools/a", true},
		{"pools -> another volume's whole directory", func(d string) { link(vol, filepath.Join(d, "pools")) }, "pools/p1", true},
		{"mounts -> other volume dir", func(d string) {
			mk(filepath.Join(vol, "m1", "a"))
			link(filepath.Join(vol, "m1"), filepath.Join(d, "mounts"))
		}, "mounts/a", true},
		{"disks -> other volume dir", func(d string) {
			mk(filepath.Join(vol, "dk"))
			link(filepath.Join(vol, "dk"), filepath.Join(d, "disks"))
		}, "disks", true},
		{"pools -> /etc", func(d string) { link("/etc", filepath.Join(d, "pools")) }, "pools/ssh", false},
		{"pools -> link -> /etc", func(d string) {
			link("/etc", filepath.Join(vol, "etclink-"+filepath.Base(d)))
			link(filepath.Join(vol, "etclink-"+filepath.Base(d)), filepath.Join(d, "pools"))
		}, "pools/ssh", false},
		{"pools -> /", func(d string) { link("/", filepath.Join(d, "pools")) }, "pools/opt", false},
		{"pools -> parent of data dir", func(d string) { link(filepath.Dir(d), filepath.Join(d, "pools")) }, "pools/x", false},
		{"pools -> grandparent of data dir", func(d string) { link(filepath.Dir(filepath.Dir(d)), filepath.Join(d, "pools")) }, "pools/x", false},
		{"pools -> data dir itself", func(d string) { link(d, filepath.Join(d, "pools")) }, "pools/x", false},
		{"pools -> /var/lib (holds the default data dir)", func(d string) { link("/var/lib", filepath.Join(d, "pools")) }, "pools/polkit-1", false},
		{"pools -> /var (ancestor of the default data dir)", func(d string) { link("/var", filepath.Join(d, "pools")) }, "pools/lib/polkit-1", false},
		{"mounts -> /etc", func(d string) { link("/etc", filepath.Join(d, "mounts")) }, "mounts/ssh", false},
		{"disks -> /etc", func(d string) { link("/etc", filepath.Join(d, "disks")) }, "disks", false},
		{"pools -> /var/lib/polkit-1 (residual: not a system root)", func(d string) { link("/var/lib/polkit-1", filepath.Join(d, "pools")) }, "pools/localauthority", false},
		{"pools -> /var/lib/systemd (residual)", func(d string) { link("/var/lib/systemd", filepath.Join(d, "pools")) }, "pools/linger", false},
	}
	for i, c := range cases {
		data := filepath.Join(base, "d"+string(rune('a'+i)), "data")
		mk(data)
		c.setup(data)
		pki := filepath.Join(base, "pki")
		in, err := InDataDirPoolArea(filepath.Join(data, c.probe), data, pki)
		mark := "ok"
		if in != c.want {
			mark = "UNEXPECTED"
		}
		t.Logf("%-58s in=%-5t err=%v want=%t %s", c.label, in, err, c.want, mark)
		if in != c.want && !strings.Contains(c.label, "residual") {
			t.Errorf("%s: in=%t, want %t", c.label, in, c.want)
		}
	}
	// The data dir itself a symlink to the other volume, pools plain.
	real := filepath.Join(vol, "realdata")
	mk(filepath.Join(real, "pools", "a"))
	dl := filepath.Join(base, "datalink")
	link(real, dl)
	in, err := InDataDirPoolArea(filepath.Join(dl, "pools", "a"), dl, filepath.Join(base, "pki"))
	t.Logf("%-58s in=%-5t err=%v want=true", "data dir is a link to the other volume", in, err)
	if !in {
		t.Error("a data dir that is a link to another volume: its pools are not the daemon's area")
	}
}
