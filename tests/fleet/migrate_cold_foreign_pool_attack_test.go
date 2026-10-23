// Fleet scenario: a replicated storage_pools row for the SOURCE host must not
// make a cold-move target write into a place the target would never let a pool
// use (the security review of the F1 fix, round 1).
//
// The target accepts a foreign pool directory only when it, with symlinks
// resolved on the target, is inside the target's own disks/, pools/ or mounts/
// areas (or the directory of a usable pool row of the target's own) AND passes
// the check the target applies to its own pools (storage.CheckWriteRoot). The
// file's parent is held to the same rules.

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// probeReceive sends the header of a check-only ReceiveMigrationDisk of fp1's
// disk at path from the source to the target, as a peer would, and returns the
// target's answer: nil means every check it runs before writing passed.
func (fp *foreignPoolScenario) probeReceive(t *testing.T) error {
	t.Helper()
	up, err := fp.c.PeerClient(fp.src, fp.dst).ReceiveMigrationDisk(context.Background())
	if err != nil {
		t.Fatalf("open the receive: %v", err)
	}
	_ = up.Send(&pb.ReceiveMigrationDiskRequest{VmName: "fp1", Path: fp.disk, SizeBytes: int64(len(fp.payload)), CheckOnly: true})
	_, err = up.CloseAndRecv()
	return err
}

func (fp *foreignPoolScenario) targetFile(p string) string {
	return filepath.Join(fp.c.tmpRoot, "fs-"+fp.dst.Name, p)
}

// Every row is red on 2bc0443c6 (the target wrote into the system directory, or
// the pool row's directory was taken as it was named) and must be refused.
//
// Mutations: drop the CheckWriteRoot of the pool directory or of the parent in
// foreignPoolDirAcceptable - the system rows (and /proc) go red; drop the
// resolved containment in the target's areas - the symlinked-pool-dir row and
// the outside-the-areas row go red; drop the parent's containment in the
// resolved pool directory - the symlinked-parent row goes red.
func TestFleet_ColdMigrationRefusesASourcePoolRowThatReachesOutsideTheTargetsPoolAreas(t *testing.T) {
	type row struct {
		name  string
		pool  func(def, outside string) string // the pool row's directory
		disk  func(def, outside string) string
		setup func(t *testing.T, fp *foreignPoolScenario, def, outside string)
	}
	link := func(t *testing.T, fp *foreignPoolScenario, at, to string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(fp.targetFile(at)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(fp.targetFile(to), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fp.targetFile(to), fp.targetFile(at)); err != nil {
			t.Fatal(err)
		}
	}
	fixed := func(pool, disk string) (func(string, string) string, func(string, string) string) {
		return func(string, string) string { return pool }, func(string, string) string { return disk }
	}
	var rows []row
	for _, r := range []struct{ name, pool, disk string }{
		{"etc-cron", "/etc", "/etc/cron.d/litevirt-review-pwn"},
		{"root-ssh", "/root", "/root/.ssh/authorized_keys2"},
		{"systemd", "/usr/lib/systemd/system", "/usr/lib/systemd/system/review-pwn.service"},
		{"libvirt", "/var/lib/libvirt", "/var/lib/libvirt/qemu/review-pwn"},
		{"pki", "/etc/litevirt/pki", "/etc/litevirt/pki/review-pwn.crt"},
		{"proc", "/proc", "/proc/review-pwn"},
	} {
		p, d := fixed(r.pool, r.disk)
		rows = append(rows, row{name: r.name, pool: p, disk: d})
	}
	rows = append(rows,
		// A pool row named inside the target's pools/ area that is a link to
		// somewhere else on the target.
		row{name: "symlinked-pool-dir",
			pool: func(def, _ string) string { return filepath.Join(filepath.Dir(def), "evil") },
			disk: func(def, _ string) string { return filepath.Join(filepath.Dir(def), "evil", "x.qcow2") },
			setup: func(t *testing.T, fp *foreignPoolScenario, def, outside string) {
				link(t, fp, filepath.Join(filepath.Dir(def), "evil"), outside)
			}},
		// An honest pool directory with a link below it.
		row{name: "symlinked-parent",
			pool: func(def, _ string) string { return def },
			disk: func(def, _ string) string { return filepath.Join(def, "sub", "x.qcow2") },
			setup: func(t *testing.T, fp *foreignPoolScenario, def, outside string) {
				link(t, fp, filepath.Join(def, "sub"), outside)
			}},
		// Inside the target's pools/ area by position, but the root of the
		// area, which is not a pool: only the pool check refuses it.
		row{name: "the-pools-area-root",
			pool: func(def, _ string) string { return filepath.Dir(def) },
			disk: func(def, _ string) string { return filepath.Join(filepath.Dir(def), "x.qcow2") }},
		// An ordinary directory, not a system one, that the target has no pool
		// of its own on.
		row{name: "outside-the-areas-no-pool-of-its-own",
			pool: func(_, outside string) string { return outside },
			disk: func(_, outside string) string { return filepath.Join(outside, "x.qcow2") }},
	)
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			var def, outside string
			fp := newForeignPoolScenario(t,
				func(pool, _ string) string {
					def = pool
					outside = filepath.Join(filepath.Dir(filepath.Dir(pool)), "outside-"+tc.name)
					return tc.disk(pool, outside)
				},
				func(pool, _ string) string {
					return tc.pool(pool, filepath.Join(filepath.Dir(filepath.Dir(pool)), "outside-"+tc.name))
				})
			if tc.setup != nil {
				tc.setup(t, fp, def, outside)
			}
			err := fp.probeReceive(t)
			if err == nil || !strings.Contains(err.Error(), "not in a disk-artifact root") {
				t.Fatalf("pool row %s for the source, disk %s: the target answered %v, want the disk-artifact root refusal", tc.pool(def, outside), fp.disk, err)
			}
			if _, serr := os.Lstat(fp.targetFile(fp.disk)); serr == nil {
				t.Errorf("%s exists on the target", fp.disk)
			}
			// And a whole move writes nothing there either, whoever refuses it.
			if merr := fp.migrate(); merr == nil {
				t.Errorf("migrate --cold with a disk at %s succeeded", fp.disk)
			}
			if _, serr := os.Lstat(fp.targetFile(fp.disk)); serr == nil {
				t.Errorf("a cold move put %s on the target", fp.disk)
			}
		})
	}
}

// The residual a bare CheckWriteRoot would leave: an ordinary directory outside
// the target's pool areas is accepted only when the target has a usable pool of
// its own on that same directory.
//
// Mutation: drop the own-pool branch in foreignPoolDirAcceptable - red.
func TestFleet_ColdMigrationAcceptsAForeignPoolDirectoryTheTargetHasAPoolOn(t *testing.T) {
	var outside string
	fp := newForeignPoolScenario(t,
		func(pool, _ string) string {
			outside = filepath.Join(filepath.Dir(filepath.Dir(pool)), "srv-pool")
			return filepath.Join(outside, "x.qcow2")
		},
		func(pool, _ string) string { return filepath.Join(filepath.Dir(filepath.Dir(pool)), "srv-pool") })
	if err := fp.probeReceive(t); err == nil || !strings.Contains(err.Error(), "not in a disk-artifact root") {
		t.Fatalf("with no pool of its own on %s the target answered %v, want the refusal", outside, err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), fp.dst.DB, corrosion.StoragePoolRecord{
		HostName: fp.dst.Name, Name: "srv", Driver: "dir", Target: outside, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fp.targetFile(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fp.probeReceive(t); err != nil {
		t.Fatalf("with its own pool on %s the target answered %v, want the receive accepted", outside, err)
	}
}
