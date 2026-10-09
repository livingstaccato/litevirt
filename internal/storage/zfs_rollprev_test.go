package storage

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
)

const (
	testPrev    = "tank/x@litevirt-replicate-prev"
	testPrevNew = testPrev + "-new"
)

// The two ways zfs reports destroying a snapshot that is not there. 2.2.2
// (Ubuntu 24.04) prints the first for `zfs destroy <snap>` and
// `zfs destroy -- <snap>` alike (lab-recheck-5 11:11:52); older releases the
// second.
var missingSnapshotMessages = map[string]string{
	"zfs-2.2.2": "could not find any snapshots to destroy; check snapshot names.",
	"older":     "cannot open 'tank/x@litevirt-replicate-prev': dataset does not exist",
}

// fakeZFS is a zfs that keeps its datasets and snapshots, answering list,
// snapshot, destroy and rename as zfs does, with destroyMissing as the
// message for destroying something that is not there.
type fakeZFS struct {
	have           map[string]bool
	busy           map[string]bool
	destroyMissing string
	calls          [][]string
}

func newFakeZFS(destroyMissing string, have ...string) *fakeZFS {
	f := &fakeZFS{have: map[string]bool{}, busy: map[string]bool{}, destroyMissing: destroyMissing}
	for _, h := range have {
		f.have[h] = true
	}
	return f
}

func (f *fakeZFS) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	last := args[len(args)-1]
	switch args[0] {
	case "list":
		if f.have[last] {
			return []byte(last + "\n"), nil
		}
		return []byte("cannot open '" + last + "': dataset does not exist"), errors.New("exit status 1")
	case "snapshot":
		if f.have[last] {
			return []byte("cannot create snapshot '" + last + "': dataset already exists"), errors.New("exit status 1")
		}
		f.have[last] = true
	case "destroy":
		if f.busy[last] {
			return []byte("cannot destroy '" + last + "': dataset is busy"), errors.New("exit status 1")
		}
		if !f.have[last] {
			return []byte(f.destroyMissing), errors.New("exit status 1")
		}
		delete(f.have, last)
	case "rename":
		src := args[len(args)-2]
		if !f.have[src] {
			return []byte("cannot open '" + src + "': dataset does not exist"), errors.New("exit status 1")
		}
		if f.have[last] {
			return []byte("cannot rename to '" + last + "': dataset already exists"), errors.New("exit status 1")
		}
		delete(f.have, src)
		f.have[last] = true
	}
	return nil, nil
}

func (f *fakeZFS) snapshots() []string {
	var out []string
	for k := range f.have {
		if strings.Contains(k, "@") {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func requireOnlyPrev(t *testing.T, f *fakeZFS) {
	t.Helper()
	got := f.snapshots()
	if len(got) != 1 || got[0] != testPrev {
		t.Fatalf("snapshots after the roll = %q, want exactly %q", got, testPrev)
	}
}

// The first replication has no prev: on every zfs version that is "absent",
// judged by asking whether it exists, never by the wording of an error.
func TestZFSRollPrev_FirstRunOnEveryZFSVersion(t *testing.T) {
	for ver, msg := range missingSnapshotMessages {
		t.Run(ver, func(t *testing.T) {
			f := newFakeZFS(msg)
			d := &zfsDriver{dataset: "tank", run: f.run}
			if err := d.rollPrevSnapshot(context.Background(), testPrev); err != nil {
				t.Fatalf("first roll (no prev yet) = %v", err)
			}
			requireOnlyPrev(t, f)
		})
	}
}

// A run that failed after its "-new" snapshot left it behind; the next run
// must not fail on it ("dataset already exists"), whether or not prev is
// still there.
func TestZFSRollPrev_LeftoverNewDoesNotBreakTheNextRun(t *testing.T) {
	for _, have := range [][]string{{testPrevNew}, {testPrevNew, testPrev}} {
		t.Run(strings.Join(have, "+"), func(t *testing.T) {
			f := newFakeZFS(missingSnapshotMessages["zfs-2.2.2"], have...)
			d := &zfsDriver{dataset: "tank", run: f.run}
			if err := d.rollPrevSnapshot(context.Background(), testPrev); err != nil {
				t.Fatalf("roll with a leftover %s = %v", testPrevNew, err)
			}
			requireOnlyPrev(t, f)
		})
	}
}

// A prev that exists and cannot be destroyed aborts the roll (the next
// incremental must not diff against a stale base), and the roll leaves no
// "-new" behind to break the run after.
func TestZFSRollPrev_FailedDestroyLeavesNoNew(t *testing.T) {
	f := newFakeZFS(missingSnapshotMessages["zfs-2.2.2"], testPrev)
	f.busy[testPrev] = true
	d := &zfsDriver{dataset: "tank", run: f.run}
	if err := d.rollPrevSnapshot(context.Background(), testPrev); err == nil {
		t.Fatal("a prev that cannot be destroyed must fail the roll")
	}
	if f.have[testPrevNew] {
		t.Fatalf("the failed roll left %s behind", testPrevNew)
	}
	for _, c := range f.calls {
		if c[0] == "rename" {
			t.Fatalf("rename ran after a failed destroy: %q", c)
		}
	}
}

// End to end with zfs 2.2.2: the first native replicate succeeds and keeps
// its copy, and so does the next one.
func TestZFSReplicate_FirstAndSecondRunWithZFS222(t *testing.T) {
	prevPipe := zfsPipe
	t.Cleanup(func() { zfsPipe = prevPipe })
	f := newFakeZFS(missingSnapshotMessages["zfs-2.2.2"], "tank/x")
	zfsPipe = func(_ context.Context, _ string, _ string, _ []string, _ string, recvArgs []string) ([]byte, error) {
		f.have[recvArgs[len(recvArgs)-1]] = true
		return nil, nil
	}
	d := &zfsDriver{dataset: "tank", run: f.run}
	for i, dst := range []string{"tank/dr/x-copy-1", "tank/dr/x-copy-2"} {
		if err := d.Replicate(context.Background(), ReplicateOptions{SrcRef: "tank/x", DstRef: dst}); err != nil {
			t.Fatalf("replicate run %d: %v", i+1, err)
		}
		if !f.have[dst] {
			t.Fatalf("run %d: the received copy %s was destroyed", i+1, dst)
		}
		requireOnlyPrev(t, f)
	}
}

// The roll's order: the new pointer is taken before the old one is
// destroyed, and renamed into place last.
func TestZFSRollPrev_Sequence(t *testing.T) {
	f := newFakeZFS(missingSnapshotMessages["zfs-2.2.2"], testPrev)
	d := &zfsDriver{dataset: "tank", run: f.run}
	if err := d.rollPrevSnapshot(context.Background(), testPrev); err != nil {
		t.Fatal(err)
	}
	var muts []string
	for _, c := range f.calls {
		if c[0] != "list" {
			muts = append(muts, c[0]+" "+c[len(c)-1])
		}
	}
	want := []string{"snapshot " + testPrevNew, "destroy " + testPrev, "rename " + testPrev}
	if strings.Join(muts, "|") != strings.Join(want, "|") {
		t.Fatalf("roll = %q, want %q", muts, want)
	}
	requireOnlyPrev(t, f)
}
