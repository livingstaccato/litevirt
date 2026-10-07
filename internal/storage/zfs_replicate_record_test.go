package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// zfsReplicateWith runs a native zfs replicate against a fake zfs whose `set`
// behaves like OpenZFS 2.1 (no getopt: any argument after "set" starting with
// "-" is refused), or fails outright when setFails. It returns every zfs
// argv run and the error.
func zfsReplicateWith(t *testing.T, setFails bool) ([][]string, error) {
	t.Helper()
	prev := zfsPipe
	zfsPipe = func(context.Context, string, string, []string, string, []string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { zfsPipe = prev })
	var calls [][]string
	d := &zfsDriver{dataset: "tank/dr", run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		switch args[0] {
		case "list":
			return []byte("dataset does not exist"), errors.New("exit status 1")
		case "set":
			if setFails {
				return []byte("cannot set property"), errors.New("exit status 1")
			}
			if strings.HasPrefix(args[1], "-") {
				return []byte("invalid option '-'"), errors.New("exit status 2")
			}
		}
		return nil, nil
	}}
	err := d.Replicate(context.Background(), ReplicateOptions{
		SrcRef: "tank/vms/web-root", DstRef: "tank/dr/web-root-copy",
		Record: map[string]string{"project": "acme", "vm": "web", "disk": "root"},
	})
	return calls, err
}

// C2: `zfs set` takes no "--" (OpenZFS up to 2.1 has no getopt there), so a
// native replicate records its copy on Ubuntu 22.04 / Debian 12 too.
func TestZFSReplicate_SetTakesNoDoubleDash(t *testing.T) {
	calls, err := zfsReplicateWith(t, false)
	if err != nil {
		t.Fatalf("Replicate: %v", err)
	}
	var sets [][]string
	for _, c := range calls {
		if c[0] == "set" {
			sets = append(sets, c)
		}
	}
	if len(sets) != 3 {
		t.Fatalf("zfs set calls = %q, want one per record key", sets)
	}
	for _, c := range sets {
		if len(c) != 3 || !strings.HasPrefix(c[1], "litevirt:") || c[2] != "tank/dr/web-root-copy" {
			t.Errorf("zfs argv = %q, want [set litevirt:<k>=<v> <dataset>]", c)
		}
	}
	for _, c := range calls {
		if c[0] == "destroy" && slicesContains(c, "tank/dr/web-root-copy") {
			t.Errorf("the received copy was destroyed: %q", c)
		}
	}
}

// C2: a property that cannot be written never costs the copy just received:
// the replicate succeeds with a warning, and the deferred cleanup destroys
// nothing but the per-call source snapshot.
func TestZFSReplicate_PropertyWriteFailureKeepsTheCopy(t *testing.T) {
	calls, err := zfsReplicateWith(t, true)
	if err != nil {
		t.Fatalf("Replicate with a failing zfs set = %v, want success (the copy is kept)", err)
	}
	for _, c := range calls {
		if c[0] == "destroy" && slicesContains(c, "tank/dr/web-root-copy") {
			t.Fatalf("the received copy was destroyed on a property-write failure: %q", c)
		}
	}
}

func slicesContains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
