package grpcapi

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

const promoteVMUUID = "aaaaaaaa-0000-0000-0000-000000000001" // promoteFixture's vm1

// moveVM1Away makes vm1's row name a dead host, so a same-name promotion is a
// takeover onto this one.
func moveVM1Away(t *testing.T, s *Server) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE vms SET host_name = 'dead-host' WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
}

func promoteVM1(s *Server, force bool) error {
	return s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", TargetPool: "replica-pool", NoLocalize: true, Force: force,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
}

// A promotion's domain carries the VM's uuid, so the VM it brings up stays
// rebuildable: the rebuild's identity check knows the domain for the VM's own
// (dupcreate re-review 2, I-B). It used to be defined with a uuid libvirt
// chose, and every rebuild of a VM failover had promoted was refused.
//
// Mutation: drop the UUID from promote's domain config AND the owner-epoch
// identity — the rebuild is refused, red.
func TestRebuildVM_RebuildsAVMAPromotionDefined(t *testing.T) {
	s, fake := promoteFixture(t)
	moveVM1Away(t, s)
	if err := promoteVM1(s, true); err != nil {
		t.Fatalf("promote: %v", err)
	}
	x, _ := fake.DumpXMLInactive("vm1")
	if u := domainUUIDFromXML(x); u != promoteVMUUID {
		t.Errorf("the promoted domain's uuid = %q, want the VM's %s", u, promoteVMUUID)
	}
	s.images = image.NewStore(s.dataDir) // the rebuild's create sweeps the name's disks
	s.images.Init()
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("rebuild of a VM a promotion brought up: %v", err)
	}
}

// A --force retry of a promotion that crashed between its define and its
// start replaces the stopped domain it left: its own (the VM's uuid), and one
// an older build defined under a uuid libvirt chose (a stopped domain of the
// name is replaced under --force). A running domain that is not the VM's is
// still refused.
//
// Mutation: refuse every domain whose uuid is not the VM's — the older-build
// leftover is refused, red.
func TestPromoteReplica_ForceRetryReplacesItsOwnStaleDomain(t *testing.T) {
	for _, tc := range []struct {
		name, uuid string
		running    bool
		wantErr    codes.Code
	}{
		{"its own, stopped", promoteVMUUID, false, codes.OK},
		{"an older build's, stopped", "eeeeeeee-0000-0000-0000-000000000005", false, codes.OK},
		{"another guest, running", "eeeeeeee-0000-0000-0000-000000000006", true, codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := promoteFixture(t)
			moveVM1Away(t, s)
			if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>vm1</name><uuid>%s</uuid></domain>", tc.uuid)); err != nil {
				t.Fatal(err)
			}
			if tc.running {
				if err := fake.StartDomain("vm1"); err != nil {
					t.Fatal(err)
				}
			}
			err := promoteVM1(s, true)
			if status.Code(err) != tc.wantErr {
				t.Fatalf("--force promote over %s: %v, want %v", tc.name, err, tc.wantErr)
			}
			if tc.wantErr != codes.OK {
				if u, d := undefinesOf(fake, "vm1"); u != 0 || d != 0 {
					t.Errorf("the refused promote undefined/destroyed %d/%d times", u, d)
				}
				return
			}
			x, _ := fake.DumpXMLInactive("vm1")
			if u := domainUUIDFromXML(x); u != promoteVMUUID {
				t.Errorf("after the retry the domain's uuid = %q, want the VM's", u)
			}
			if active, _ := fake.DomainIsActive("vm1"); !active {
				t.Error("the retried promotion did not start the VM")
			}
		})
	}
}

// The same recovery through automated failover, which always sends --force.
func TestAutoPromote_RecoversFromAStoppedDomainACrashedPromotionLeft(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	const u = "ffffffff-0000-0000-0000-000000000009"
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "db-9", HostName: "dead-host", State: "running",
		Spec: `{"name":"db-9","cpu":1,"memory_mib":512,"uuid":"` + u + `"}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "db-9", HostName: "dead-host", DiskName: "root", Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "dir",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: "db-9", Repo: "dr", Type: "replication", TargetPool: "dr",
		TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3,
	}); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, replicaPoolDir(t, s, "dr"), "", "db-9", "root",
		time.Now().Add(-10*time.Minute).UTC().Format("20060102-150405"), "raw", 1<<20)
	// What an older build's crashed promotion left: a stopped domain under a
	// uuid libvirt chose.
	if err := fake.DefineDomain("<domain type='kvm'><name>db-9</name></domain>"); err != nil {
		t.Fatal(err)
	}
	if err := s.AutoPromoteReplica(context.Background(), "db-9", "", 0); err != nil {
		t.Fatalf("automated promotion over the stale domain: %v", err)
	}
	x, _ := fake.DumpXMLInactive("db-9")
	if got := domainUUIDFromXML(x); got != u {
		t.Errorf("the promoted domain's uuid = %q, want the VM's %s", got, u)
	}
	if active, _ := fake.DomainIsActive("db-9"); !active {
		t.Error("automated promotion did not start the VM")
	}
}

// --force over a stopped leftover of the name with no row: replaced, as a
// create replaces one.
func TestPromoteReplica_ForceReplacesAStoppedLeftoverWithNoRow(t *testing.T) {
	s, fake := promoteFixture(t)
	if err := fake.DefineDomain("<domain type='kvm'><name>vm1-new</name><uuid>eeeeeeee-0000-0000-0000-000000000007</uuid></domain>"); err != nil {
		t.Fatal(err)
	}
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-new", TargetPool: "replica-pool", NoLocalize: true, Force: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if err != nil {
		t.Fatalf("--force promote over a stopped leftover: %v", err)
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1-new"); row == nil {
		t.Fatal("no row for the promoted VM")
	}
}

// A promotion to a new name is a second VM: it gets its own uuid, in its row
// and its domain, never the original's (rereview 2 observation).
//
// Mutation: keep the original's uuid on a renamed promotion — red.
func TestPromoteReplica_ARenamedPromotionGetsItsOwnUUID(t *testing.T) {
	s, fake := promoteFixture(t)
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-copy", TargetPool: "replica-pool", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if err != nil {
		t.Fatalf("renamed promote: %v", err)
	}
	row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1-copy")
	if row == nil {
		t.Fatal("no row for the renamed promotion")
	}
	x, _ := fake.DumpXMLInactive("vm1-copy")
	du := domainUUIDFromXML(x)
	if du == "" || du == promoteVMUUID || strings.Contains(row.Spec, promoteVMUUID) || !strings.Contains(row.Spec, du) {
		t.Errorf("the renamed promotion's identity: domain %q, row spec %s; want a fresh uuid in both, not %s", du, row.Spec, promoteVMUUID)
	}
}

// A rebuild whose domain cannot be identified (libvirt cannot dump it) stops
// nothing (dupcreate re-review 2, m-D).
//
// Mutation: skip the check when the uuid cannot be read — the domain is
// destroyed, red.
func TestRebuildVM_ADomainThatCannotBeIdentifiedRefusesTheRebuild(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "rb5"
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	fake.FailDumpXMLInactive = func(string) error { return fmt.Errorf("injected: libvirt not answering") }
	fake.FailDumpXML = func(string) error { return fmt.Errorf("injected: libvirt not answering") }
	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "cannot be identified") {
		t.Fatalf("rebuild of a domain that cannot be identified: %v, want Unavailable", err)
	}
	if u, d := undefinesOf(fake, name); u != 0 || d != 0 {
		t.Errorf("the refused rebuild undefined/destroyed %d/%d times", u, d)
	}
}

// A live restore's domain carries the VM's uuid, firmware or not: the VM's
// own when it is restored to its name, a fresh one, in row and domain, when
// it is restored beside the original under a new name (re-review 2, I-B).
//
// Mutations: define the non-firmware domain without the uuid — the own-name
// case red; keep the original's uuid on a new name — the new-name case red.
func TestRestoreLive_TheDomainCarriesTheVMsIdentity(t *testing.T) {
	const orig = "0b7c6a8e-3333-4c2d-9e0f-000000000003"
	for _, tc := range []struct {
		name, newName string
	}{
		{"own name", ""},
		{"new name", "vm1-r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.hostName = "host-a"
			s.dataDir = t.TempDir()
			fake := libvirtfake.New()
			s.virt = fake
			spec := `{"name":"vm1","cpu":1,"memory_mib":512,"uuid":"` + orig + `"}`
			repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), spec)
			_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
				RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts, NewName: tc.newName,
				TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
			}, pb.RestoreLiveProgress_STARTED)
			target := "vm1"
			if tc.newName != "" {
				target = tc.newName
			}
			x, _ := fake.DumpXMLInactive(target)
			row, _ := corrosion.GetVM(context.Background(), s.db, target)
			cancel()
			<-done
			if row == nil {
				t.Fatal("no row for the restored VM")
			}
			du := domainUUIDFromXML(x)
			switch {
			case tc.newName == "" && du != orig:
				t.Errorf("restored to its own name, the domain's uuid = %q, want the VM's %s", du, orig)
			case tc.newName != "" && (du == "" || du == orig || !strings.Contains(row.Spec, du)):
				t.Errorf("restored beside it, the domain's uuid = %q (row %s); want a fresh one in both", du, row.Spec)
			}
		})
	}
}
