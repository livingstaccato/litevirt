package daemon

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestQemuConfUser(t *testing.T) {
	for _, tc := range []struct{ conf, want string }{
		{"", ""},
		{`#user = "root"`, ""},
		{`user = "root"`, "root"},
		{"user=\"libvirt-qemu\"\n", "libvirt-qemu"},
		{"group = \"kvm\"\n  user = \"qemu\"  \n", "qemu"},
		{"dynamic_ownership = 1\n# user = \"root\"\n", ""},
	} {
		if got := qemuConfUser(tc.conf); got != tc.want {
			t.Errorf("qemuConfUser(%q) = %q, want %q", tc.conf, got, tc.want)
		}
	}
}

// The migration key must belong to the account QEMU runs as and nobody else.
// qemu.conf's user wins; without one, the distro defaults are tried in order.
func TestQemuOwner(t *testing.T) {
	users := map[string]*user.User{
		"libvirt-qemu": {Uid: "64055", Gid: "108"},
		"qemu":         {Uid: "107", Gid: "107"},
		"root":         {Uid: "0", Gid: "0"},
	}
	lookup := func(name string) (*user.User, error) {
		if u, ok := users[name]; ok {
			return u, nil
		}
		return nil, fmt.Errorf("no user %q", name)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "qemu.conf")

	// No qemu.conf: the Debian default.
	if uid, gid, err := qemuOwner(conf, lookup); err != nil || uid != 64055 || gid != 108 {
		t.Errorf("no qemu.conf: (%d, %d, %v), want (64055, 108, nil)", uid, gid, err)
	}
	// qemu.conf names a user: that one, even though a default exists.
	if err := os.WriteFile(conf, []byte(`user = "root"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if uid, _, err := qemuOwner(conf, lookup); err != nil || uid != 0 {
		t.Errorf("qemu.conf user=root: uid %d err %v, want 0", uid, err)
	}
	// A configured user that does not exist is an error, not a silent default.
	if err := os.WriteFile(conf, []byte(`user = "nobody-here"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := qemuOwner(conf, lookup); err == nil {
		t.Error("qemu.conf names a user that does not exist, and qemuOwner picked another")
	}
}
