package lxc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerStamp_RoundTrip(t *testing.T) {
	r := &LxcRunner{Lxcpath: t.TempDir()}
	if err := r.StampOwner("web", ContainerOwner{Project: "acme", OwnerID: "o1"}); err == nil {
		t.Fatal("stamped a container with no directory")
	}
	if o, err := r.ReadOwner("web"); err != nil || o != nil {
		t.Fatalf("no container: %v %v", o, err)
	}
	if err := os.MkdirAll(filepath.Join(r.Lxcpath, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if o, err := r.ReadOwner("web"); err != nil || o != nil {
		t.Fatalf("unstamped: %v %v", o, err)
	}
	if err := r.StampOwner("web", ContainerOwner{Project: "acme", OwnerID: "o1"}); err != nil {
		t.Fatal(err)
	}
	o, err := r.ReadOwner("web")
	if err != nil || o == nil || *o != (ContainerOwner{Project: "acme", OwnerID: "o1"}) {
		t.Fatalf("read back %+v %v", o, err)
	}
	fi, _ := os.Stat(filepath.Join(r.Lxcpath, "web", ownerStampFile))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("stamp mode %o", fi.Mode().Perm())
	}
	if err := r.StampOwner("../x", ContainerOwner{}); err == nil {
		t.Error("a path-like name was stamped")
	}
}
