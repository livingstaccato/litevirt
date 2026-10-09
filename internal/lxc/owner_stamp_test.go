package lxc

import (
	"errors"
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

// A write that fails part-way never leaves a torn record at the record's name:
// the previous record, or none, is what ReadOwner sees, and no temp file is
// left in the container's directory.
func TestOwnerStamp_FailedWriteLeavesNoTornRecord(t *testing.T) {
	r := &LxcRunner{Lxcpath: t.TempDir()}
	dir := filepath.Join(r.Lxcpath, "web")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := writeOwnerBytes
	t.Cleanup(func() { writeOwnerBytes = orig })
	failing := func(f *os.File, b []byte) error {
		if _, err := f.Write(b[:len(b)/2]); err != nil {
			return err
		}
		return errors.New("injected: disk went away mid-write")
	}

	// No record before: still none after.
	writeOwnerBytes = failing
	if err := r.StampOwner("web", ContainerOwner{Project: "acme", OwnerID: "o1"}); err == nil {
		t.Fatal("a failed write reported success")
	}
	if o, err := r.ReadOwner("web"); err != nil || o != nil {
		t.Fatalf("after a failed first stamp: record %+v, err %v (want none)", o, err)
	}

	// A record before: the same record after.
	writeOwnerBytes = orig
	if err := r.StampOwner("web", ContainerOwner{Project: "acme", OwnerID: "o1"}); err != nil {
		t.Fatal(err)
	}
	writeOwnerBytes = failing
	if err := r.StampOwner("web", ContainerOwner{Project: "beta", OwnerID: "o2"}); err == nil {
		t.Fatal("a failed write reported success")
	}
	o, err := r.ReadOwner("web")
	if err != nil || o == nil || *o != (ContainerOwner{Project: "acme", OwnerID: "o1"}) {
		t.Fatalf("after a failed restamp: record %+v, err %v (want the previous one)", o, err)
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != ownerStampFile {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("container dir holds %v, want only %s", names, ownerStampFile)
	}
}
