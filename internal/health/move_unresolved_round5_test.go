package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// I4-2: the owner's heal of another host's pivoted move never points the disk
// row at the copy under the owner's domain: not while it runs, and not while
// its persistent config names the source. A config naming the copy, or no
// domain (a start rebuilds it from the row), is healed.
func TestResolveRemoteMove_NeverRepointsUnderTheOwnersDomain(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name         string
		define       string // "": no domain; "src" or "dst": the config names it
		running      bool
		wantErr      string
		wantRowOnDst bool
	}{
		{name: "running", define: "src", running: true, wantErr: "running"},
		{name: "running on the copy", define: "dst", running: true, wantErr: "running"},
		{name: "shut off, the config names the source", define: "src", wantErr: "virsh edit mv"},
		{name: "shut off, the config names the copy", define: "dst", wantRowOnDst: true},
		{name: "no domain", wantRowOnDst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			originDir := t.TempDir()
			_, src, dst := seedMovedVM(t, db, originDir, "dst", true, true)
			ms, _ := UnresolvedMovesOf(originDir, "mv")
			ms[0].DstType = "nfs"
			if err := RecordUnresolvedMove(originDir, ms[0]); err != nil {
				t.Fatal(err)
			}
			if err := PublishUnresolvedMoves(ctx, db, originDir, "node-a", "mv"); err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{"node-a", "node-b"} {
				if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: "warm",
					Driver: "nfs", Source: "nas:/vol", Target: filepath.Dir(dst)}); err != nil {
					t.Fatal(err)
				}
			}
			fakeNFSMount(t, filepath.Dir(dst), "nas:/vol")
			if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-b", src, "local", "hot"); err != nil {
				t.Fatal(err)
			}
			if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-b' WHERE name = 'mv'`); err != nil {
				t.Fatal(err)
			}
			f := libvirtfake.New()
			if tc.define != "" {
				names := src
				if tc.define == "dst" {
					names = dst
				}
				if err := f.DefineDomain(moveDomainXML("mv", names)); err != nil {
					t.Fatal(err)
				}
				if tc.running {
					f.SetState("mv", libvirtfake.StateRunning)
				}
			}
			dom := MoveDomain{
				InactiveXML: func() (string, error) { return f.DumpXMLInactive("mv") },
				State:       func() (string, error) { return f.DomainState("mv") },
			}
			err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", dom)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("heal: %v", err)
			}
			if tc.wantErr != "" && (!IsMoveUnresolved(err) || !strings.Contains(err.Error(), tc.wantErr) ||
				!strings.Contains(err.Error(), src) || !strings.Contains(err.Error(), dst)) {
				t.Fatalf("want a refusal saying %q and naming both files, got %v", tc.wantErr, err)
			}
			want := src
			if tc.wantRowOnDst {
				want = dst
			}
			if got := movedRowPath(t, db); got != want {
				t.Fatalf("row names %s, want %s", got, want)
			}
		})
	}
}

// m3-4 / m4-4: a pool of a shared driver other than nfs holds a file only
// while the pool's own Source is what is mounted on its directory: nothing
// mounted, or another filesystem mounted there, does not.
func TestSharedPoolHolds_OtherDriversNeedTheirSourceMounted(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "hot")
	file := filepath.Join(target, "vm-root.qcow2")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"node-a", "node-b"} {
		if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: h, Name: "hot",
			Driver: "ceph", Source: "mon:/vms", Target: target}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, mount string
		want        bool
	}{
		{name: "nothing mounted"},
		{name: "another filesystem mounted", mount: "- ceph mon:/other rw"},
		{name: "a local disk mounted", mount: "- ext4 /dev/sdb1 rw"},
		{name: "the pool's source mounted", mount: "- ceph mon:/vms rw", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tab := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
			if tc.mount != "" {
				tab += "2 1 0:40 / " + target + " rw,nosuid,nodev " + tc.mount + "\n"
			}
			t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) { return []byte(tab), nil }))
			if got := SharedPoolHolds(ctx, db, dataDir, "node-b", "node-a", "hot", "ceph", file); got != tc.want {
				t.Fatalf("SharedPoolHolds = %v, want %v", got, tc.want)
			}
		})
	}
}

// m4-5: a returning holder whose record knows more than the evidence an
// admin resolved by hand (here: the pivot, recorded in the same second)
// keeps the admin's decision, and records the divergence in the audit log.
func TestPublishUnresolvedMoves_HandResolutionThatKnewLessIsAudited(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	seedMovedVM(t, db, dir, "src", true, false)
	if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	handResolve(t, db, "mv", true)
	if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-b' WHERE name = 'mv'`); err != nil {
		t.Fatal(err)
	}
	ms, _ := UnresolvedMovesOf(dir, "mv")
	ms[0].Pivoted = true
	if err := RecordUnresolvedMove(dir, ms[0]); err != nil {
		t.Fatal(err)
	}
	if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	if MoveConditionCovers(ctx, db, "mv", "root") {
		t.Fatal("raised again over the admin's resolution")
	}
	if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 0 {
		t.Fatalf("record kept: %+v", left)
	}
	rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "pivoted") {
		t.Fatalf("audit = %+v %v", rows, err)
	}
}
