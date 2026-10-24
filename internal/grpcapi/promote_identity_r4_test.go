package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// --force never stops a running domain of the name that is not the VM's,
// even one carrying the row's owner-epoch stamp: healers write the stamp by
// name onto whatever runs under it on the owner, and epochs repeat across
// VMs and incarnations (dupcreate re-review 3, I-1).
//
// Mutation: accept the owner-epoch stamp as identity — the foreign guest is
// destroyed and undefined, red.
func TestPromoteReplica_ForceNeverStopsARunningDomainCarryingTheRowsStamp(t *testing.T) {
	s, fake := promoteFixture(t)
	moveVM1Away(t, s)
	if err := s.db.Execute(adminCtx(), `UPDATE vms SET vm_owner_epoch = 1 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	const foreign = "eeeeeeee-0000-0000-0000-000000000011"
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>vm1</name><uuid>%s</uuid></domain>", foreign)); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("vm1"); err != nil {
		t.Fatal(err)
	}
	if err := fake.SetDomainOwnerEpoch("vm1", 1, true); err != nil {
		t.Fatal(err)
	}
	err := promoteVM1(s, true)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), foreign) {
		t.Fatalf("--force promote over a running stamped domain of another uuid: %v, want FailedPrecondition naming it", err)
	}
	if u, d := undefinesOf(fake, "vm1"); u != 0 || d != 0 {
		t.Errorf("the foreign guest was undefined %d and destroyed %d times", u, d)
	}
	if active, _ := fake.DomainIsActive("vm1"); !active {
		t.Error("the foreign guest no longer runs")
	}
}

// A rebuild knows a domain an older build defined under a uuid libvirt chose
// (a promotion or restore before the domain carried the VM's uuid, its row
// still at owner epoch 0) for the VM's own by its disks: it runs on the disks
// the VM's row records on this host (re-review 3, I-1 and its Observation).
//
// Mutation: drop the disk rule — the rebuild is refused, red.
func TestRebuildVM_KnowsALegacyDomainByTheVMsDisks(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "rb6"
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, name)
	if err := fake.DestroyDomain(name); err != nil {
		t.Fatal(err)
	}
	x, err := fake.DumpXMLInactive(name)
	if err != nil {
		t.Fatal(err)
	}
	own := domainUUIDFromXML(x)
	disks, _ := corrosion.GetVMDisks(adminCtx(), s.db, name)
	if own == "" || len(disks) == 0 || !strings.Contains(x, disks[0].Path) {
		t.Fatalf("fixture: domain uuid %q, disks %+v, xml %s", own, disks, x)
	}
	if err := fake.UndefineDomain(name, false); err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(x, "<uuid>"+own+"</uuid>", "<uuid>eeeeeeee-0000-0000-0000-000000000012</uuid>", 1)
	if err := fake.DefineDomain(legacy); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain(name); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(adminCtx(), `UPDATE vms SET vm_owner_epoch = 0 WHERE name = ?`, name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name}); err != nil {
		t.Fatalf("rebuild of a VM whose domain an older build defined on its disks: %v", err)
	}
}

// Replacing a stopped domain of the name that is not the VM's keeps its NVRAM
// and vTPM state: only the definition goes (re-review 3, m-1).
//
// Mutation: undefine it with UndefineDomain — red.
func TestPromoteReplica_ForceKeepsAReplacedForeignDomainsFirmwareState(t *testing.T) {
	s, fake := promoteFixture(t)
	moveVM1Away(t, s)
	if err := fake.DefineDomain("<domain type='kvm'><name>vm1</name><uuid>eeeeeeee-0000-0000-0000-000000000013</uuid></domain>"); err != nil {
		t.Fatal(err)
	}
	if err := promoteVM1(s, true); err != nil {
		t.Fatalf("--force promote over a stopped foreign domain: %v", err)
	}
	var notes []string
	for _, e := range fake.EventLog() {
		if e.Domain == "vm1" && e.Op == "undefine" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "keep_state=true") {
		t.Errorf("the foreign domain's undefine: %q, want its firmware state kept", notes)
	}
}

// startsAfterCheck is the fake with a domain started by someone else right
// after the first time its activity is read as stopped: an operator or an
// autostart between promote's --force check and its replace.
type startsAfterCheck struct {
	*libvirtfake.Fake
	name string
	once sync.Once
}

func (f *startsAfterCheck) DomainIsActive(name string) (bool, error) {
	active, err := f.Fake.DomainIsActive(name)
	if name == f.name && err == nil && !active {
		f.once.Do(func() { _ = f.Fake.StartDomain(name) })
	}
	return active, err
}

// A foreign domain that was stopped at the --force check but runs by the
// replace is not stopped: the verdict is taken again just before it
// (re-review 3, m-2).
//
// Mutation: drop the re-check — the foreign guest is destroyed, red.
func TestPromoteReplica_ForceNeverStopsAForeignDomainStartedDuringTheBuild(t *testing.T) {
	s, fake := promoteFixture(t)
	moveVM1Away(t, s)
	if err := fake.DefineDomain("<domain type='kvm'><name>vm1</name><uuid>eeeeeeee-0000-0000-0000-000000000014</uuid></domain>"); err != nil {
		t.Fatal(err)
	}
	s.virt = &startsAfterCheck{Fake: fake, name: "vm1"}
	err := promoteVM1(s, true)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("--force promote over a foreign domain started during the build: %v, want FailedPrecondition", err)
	}
	if u, d := undefinesOf(fake, "vm1"); u != 0 || d != 0 {
		t.Errorf("the foreign guest was undefined %d and destroyed %d times", u, d)
	}
	if active, _ := fake.DomainIsActive("vm1"); !active {
		t.Error("the foreign guest no longer runs")
	}
}

// A renamed promotion's retry that adopts the domain its first attempt
// started keeps that domain's uuid for the row and the NIC guards: the row
// and the domain never name two identities (re-review 3, m-3).
//
// Mutation: keep the uuid the retry minted — red.
func TestPromoteReplica_ARenamedRetryAdoptsTheRunningDomainsUUID(t *testing.T) {
	s, fake := promoteFixture(t)
	const first = "eeeeeeee-0000-0000-0000-000000000015"
	// It runs from the live disk it built: one that runs from none is not
	// adopted (NB-R3).
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>vm1-p</name><uuid>%s</uuid><devices>%s"+
		"<interface type='bridge'><mac address='52:54:00:aa:bb:15'/><source bridge='lo'/></interface></devices></domain>",
		first, adoptablePromotedDisk(t, s, "replica-pool", "vm1-p"))); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("vm1-p"); err != nil {
		t.Fatal(err)
	}
	// The first attempt crashed after its start, before its "started"
	// checkpoint: its marker is there.
	if err := s.writePromoteMarkerFor("vm1-p", "", first); err != nil {
		t.Fatal(err)
	}
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-p", TargetPool: "replica-pool", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if err != nil {
		t.Fatalf("renamed promotion retry: %v", err)
	}
	row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1-p")
	if row == nil {
		t.Fatal("no row for the promoted VM")
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(row.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Uuid != first {
		t.Errorf("the adopted VM's row uuid = %q, want its domain's %s", spec.Uuid, first)
	}
	guards, _ := corrosion.ListNICGuards(adminCtx(), s.db)
	for _, g := range guards {
		if g.VMName == "vm1-p" && g.VMUUID != first {
			t.Errorf("NIC guard %s names uuid %q, want the domain's %s", g.MAC, g.VMUUID, first)
		}
	}
	if u, d := undefinesOf(fake, "vm1-p"); u != 0 || d != 0 {
		t.Errorf("the adopted domain was undefined %d and destroyed %d times", u, d)
	}
}

// A restore keeps the spec's uuid only when the spec is the backup's own or
// this cluster's row, and no live VM holds the uuid; a caller's --spec, or a
// uuid a live VM holds, gets a fresh one, as a create does (re-review 3,
// m-4). Two live VMs never share one.
//
// Mutation: keep the spec's uuid on a restore to its own name — the
// caller-spec and held-uuid cases red.
func TestRestoreLive_KeepsTheSpecsUUIDOnlyWhenTrustedAndFree(t *testing.T) {
	const held = "0b7c6a8e-3333-4c2d-9e0f-000000000021"
	const free = "0b7c6a8e-3333-4c2d-9e0f-000000000022"
	for _, tc := range []struct {
		name       string
		manifestU  string
		callerSpec bool
		wantKept   bool
	}{
		{"backup's own, free", free, false, true},
		{"backup's own, held by a live VM", held, false, false},
		{"caller's spec, held by a live VM", held, true, false},
		{"caller's spec, free", free, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.hostName = "host-a"
			s.dataDir = t.TempDir()
			fake := libvirtfake.New()
			s.virt = fake
			if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
				Name: "other", HostName: "host-b", State: "running",
				Spec: `{"name":"other","cpu":1,"memory_mib":512,"uuid":"` + held + `"}`,
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
			specJSON := `{"name":"x","cpu":1,"memory_mib":512,"uuid":"` + tc.manifestU + `"}`
			repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), specJSON)
			req := &pb.RestoreLiveRequest{
				RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
				TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
			}
			if tc.callerSpec {
				req.Spec = &pb.VMSpec{Name: "x", Cpu: 1, MemoryMib: 512, Uuid: tc.manifestU}
			}
			_, cancel, done := runRestoreLiveUntil(t, s, req, pb.RestoreLiveProgress_STARTED)
			x, _ := fake.DumpXMLInactive("x")
			row, _ := corrosion.GetVM(context.Background(), s.db, "x")
			cancel()
			rerr := <-done
			if row == nil {
				t.Fatalf("no row for the restored VM: %v", rerr)
			}
			du := domainUUIDFromXML(x)
			if du == "" || !strings.Contains(row.Spec, du) {
				t.Fatalf("the restored domain's uuid %q is not its row's (%s)", du, row.Spec)
			}
			if kept := du == tc.manifestU; kept != tc.wantKept {
				t.Errorf("the restored VM's uuid = %q (spec's %s); kept = %v, want %v", du, tc.manifestU, kept, tc.wantKept)
			}
		})
	}
}
