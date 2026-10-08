package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedReplica writes a recorded replica of (project, vm, disk) into poolDir the
// way the replication runner does, size bytes of zeros, and returns its file
// name (what PromoteReplica.replica names).
func seedReplica(t *testing.T, poolDir, project, vm, disk, taken, format string, size int) string {
	t.Helper()
	rec := newReplicaRecord(project, vm, disk, vm+"/test", taken, format)
	if _, err := publishRecordedReplica(context.Background(), poolDir, rec, func(tmp string) error {
		return os.WriteFile(tmp, make([]byte, size), 0o600)
	}); err != nil {
		t.Fatalf("seed replica %s: %v", rec.File, err)
	}
	return rec.File
}

// A record is selected only from the owner directory of exactly its project
// and VM, and only when it describes the file beside it.
func TestListReplicaRecords_OnlyTheOwnersOwnRecords(t *testing.T) {
	pool := t.TempDir()
	mine := seedReplica(t, pool, "a", "web", "1", "20261001-000000", "qcow2", 16)
	seedReplica(t, pool, "b", "web", "1", "20261002-000000", "qcow2", 16) // same VM name, other project
	seedReplica(t, pool, "a", "web-1", "root", "20261003-000000", "qcow2", 16)

	recs, err := listReplicaRecords(pool, "a", "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].File != mine || recs[0].Project != "a" {
		t.Fatalf("records of (a, web) = %+v, want only %s", recs, mine)
	}

	// A record copied into the owner directory but naming another VM is not
	// this owner's; nor is a file with no record, nor a record of a missing file.
	dir := replicaOwnerDir(pool, "a", "web")
	foreign := newReplicaRecord("b", "db", "root", "db/dr", "20261004-000000", "raw")
	data, _ := json.Marshal(foreign)
	if err := os.WriteFile(filepath.Join(dir, foreign.File+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, foreign.File), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1-20261005-000000.qcow2"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	gone := newReplicaRecord("a", "web", "1", "web/dr", "20261006-000000", "qcow2")
	data, _ = json.Marshal(gone)
	if err := os.WriteFile(filepath.Join(dir, gone.File+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if recs, _ := listReplicaRecords(pool, "a", "web"); len(recs) != 1 || recs[0].File != mine {
		t.Fatalf("records of (a, web) = %+v, want only %s", recs, mine)
	}
}

func TestReplicaRecord_ValidateRefusesAMismatchedFile(t *testing.T) {
	r := newReplicaRecord("a", "web", "1", "web/dr", "20261001-000000", "qcow2")
	if err := r.validate(); err != nil {
		t.Fatalf("valid record refused: %v", err)
	}
	for name, mut := range map[string]func(*replicaRecord){
		"file":   func(r *replicaRecord) { r.File = "../../db-root.qcow2" },
		"vm":     func(r *replicaRecord) { r.VM = "../x" },
		"format": func(r *replicaRecord) { r.Format = "iso" },
		"taken":  func(r *replicaRecord) { r.Taken = "latest" },
	} {
		bad := r
		mut(&bad)
		if bad.validate() == nil {
			t.Errorf("%s: an invalid record was accepted: %+v", name, bad)
		}
	}
}

// The schedule key names the row a run came from: a fan-out run is not the
// vm-scoped schedule of the same VM and pool.
func TestReplicaScheduleKey(t *testing.T) {
	vm := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr"}
	fan := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", Origin: "__project__acme"}
	if replicaScheduleKey(vm) != "web/dr" || replicaScheduleKey(fan) != "__project__acme/dr" {
		t.Errorf("keys = %q, %q", replicaScheduleKey(vm), replicaScheduleKey(fan))
	}
}
