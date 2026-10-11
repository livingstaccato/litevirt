package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Review R4-I2, the in-band remedy: after a partial promotion left the shared
// data1 unattached (its owner fenced by SSH only), `lv restart` re-judges the
// owner. Unproven, the restarted VM still lacks data1, and InspectVM says
// which disk, why, and what to do. Once the owner is confirmed off
// (`lv host fence-confirm`), the next restart attaches it and the report
// clears. A re-run of the promotion is refused (TestPromote_AForced…); this
// is the remedy the partial report names.
//
// Mutation "no re-judge at start" (rejudgeSharedDisksForStart does nothing) —
// red: the restart after the confirmation does not attach data1.
// Mutation "attach every row" (JudgeSharedDiskRows withholds nothing) — red:
// the restart before the confirmation attaches it.
func TestRestart_AttachesAPartialPromotionsSharedDiskOnceItsOwnerIsProvenOff(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	recordOwnerFence(t, s, "f1", "ssh", "fenced", time.Minute)
	promoteVia(t, s, false, true)
	assertSharedUnattached(t, s, nfsDisk, "dead-host is fenced, but not proven powered off")
	p := eventDetail(t, s, "db", vmEventPromotedPartial)
	if !strings.Contains(p, "`lv host fence-confirm dead-host`, then `lv restart db`") {
		t.Errorf("partial = %q, want the restart remedy named", p)
	}
	fake := s.virt.(*libvirtfake.Fake)

	if _, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "db"}); err != nil {
		t.Fatalf("RestartVM before the confirmation: %v", err)
	}
	if xml := fake.DefinedXML("db"); strings.Contains(xml, nfsDisk) {
		t.Fatalf("a restart attached data1 while dead-host is not proven off:\n%s", xml)
	}
	if st, _ := fake.DomainState("db"); st != "running" {
		t.Errorf("db state after the restart = %q, want running", st)
	}
	vm, err := s.vmToProto(context.Background(), "db")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"data1", "dead-host is fenced, but not proven powered off",
		"`lv host fence-confirm dead-host`", "then `lv restart db`"} {
		if !strings.Contains(vm.GetSharedDiskWithheld(), want) {
			t.Errorf("shared_disk_withheld = %q, want %q", vm.GetSharedDiskWithheld(), want)
		}
	}

	recordOwnerFence(t, s, "f2", "manual", "manual-confirmed", 0)
	if _, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "db"}); err != nil {
		t.Fatalf("RestartVM after the confirmation: %v", err)
	}
	if xml := fake.DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
		t.Fatalf("the restart after the confirmation did not attach data1:\n%s", xml)
	}
	if st, _ := fake.DomainState("db"); st != "running" {
		t.Errorf("db state after the second restart = %q, want running", st)
	}
	if vm, _ := s.vmToProto(context.Background(), "db"); vm.GetSharedDiskWithheld() != "" {
		t.Errorf("shared_disk_withheld = %q after a restart that attached it, want cleared", vm.GetSharedDiskWithheld())
	}
}

// Review R4-I2: a definition that already holds a shared disk whose row names
// a host not proven off — a row a move left behind, here naming an active
// host — is redefined without it before an operator's start, and the start
// goes ahead. Every other VM starts on its definition untouched.
//
// Mutation "no re-judge at start" — red.
func TestStart_ADefinitionWithAnUnprovenSharedDiskIsRedefinedWithoutIt(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "active")
	alreadyPromotedHere(t, s)
	fake := s.virt.(*libvirtfake.Fake)
	if err := fake.UndefineDomain("db", false); err != nil {
		t.Fatal(err)
	}
	xml, err := lv.GenerateDomainXML(lv.VMConfig{Name: "db", CPU: 1, MemoryMiB: 256, Disks: []lv.DiskConfig{
		{Name: "root", Path: "/dead/db-root.qcow2", Bus: "virtio", TargetDev: "vda"},
		{Name: "data1", Path: nfsDisk, Bus: "virtio", TargetDev: "vdb"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(xml); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'db'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "db"}); err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	if xml := fake.DefinedXML("db"); strings.Contains(xml, nfsDisk) {
		t.Fatalf("the start kept data1, whose row names active dead-host:\n%s", xml)
	}
	if st, _ := fake.DomainState("db"); st != "running" {
		t.Errorf("db state = %q, want running", st)
	}
	if got := eventDetail(t, s, "db", vmEventSharedWithheld); !strings.Contains(got, "its owner dead-host is active, not fenced") ||
		!strings.Contains(got, "`lv doctor repair-owner db test-host`") {
		t.Errorf("withheld event = %q, want the reason and the repair-owner remedy", got)
	}
}

// JudgeSharedDiskRows' split, row by row: this host's, no host's and a
// non-shared row are attached; a shared row naming another host only when that
// host is proven off.
func TestJudgeSharedDiskRows(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "ipmi-off", Address: "10.0.0.2", State: "fenced"},
		{Name: "ssh-off", Address: "10.0.0.3", State: "fenced"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range [][3]string{{"ipmi-off", "ipmi", "fenced"}, {"ssh-off", "ssh", "fenced"}} {
		ts := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		if err := s.db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
			VALUES (?, ?, ?, ?, ?, '')`, f[0], f[0], f[1], f[2], ts); err != nil {
			t.Fatal(err)
		}
	}
	rows := []corrosion.DiskRecord{
		{DiskName: "here", HostName: s.hostName, StorageType: "nfs"},
		{DiskName: "nohost", HostName: "", StorageType: "nfs"},
		{DiskName: "local-elsewhere", HostName: "ssh-off", StorageType: "local"},
		{DiskName: "proven", HostName: "ipmi-off", StorageType: "nfs"},
		{DiskName: "unproven", HostName: "ssh-off", StorageType: "ceph"},
		{DiskName: "gone", HostName: "never-seen", StorageType: "iscsi"},
	}
	attach, withheld := s.judgeSharedDiskRows(ctx, rows)
	var got []string
	for _, d := range attach {
		got = append(got, d.DiskName)
	}
	if strings.Join(got, ",") != "here,nohost,local-elsewhere,proven" {
		t.Errorf("attached %v", got)
	}
	got = nil
	for _, w := range withheld {
		got = append(got, w.Disk.DiskName+"@"+w.Owner)
	}
	if strings.Join(got, ",") != "unproven@ssh-off,gone@never-seen" {
		t.Errorf("withheld %v", got)
	}
}

// Review PB-m2, end to end: a removed owner whose fence on record would prove
// it off, but whose fence rows cannot be read, is not proven off. (A
// host_membership read that fails is pinned in corrosion,
// TestRemovedHostProvedOff_AReadErrorIsNoProof: here it would refuse the
// whole promotion earlier, at the host admission, as on main.) The promotion leaves its shared disk unattached and says the owner's
// state cannot be read; a restart withholds it the same way. Nothing is
// refused: main never attached the disk.
//
// Mutation "a read error is no error" (SharedDiskOwnerProvedOff drops it) —
// red: the reason no longer says the state cannot be read.
func TestPromote_AnOwnerWhoseRowsCannotBeReadIsNotProvenOff(t *testing.T) {
	for _, broken := range []string{"fencing_log"} {
		t.Run(broken, func(t *testing.T) {
			s := testServer(t)
			nfsDisk := nfsPromoteVM(t, s, "") // dead-host has no hosts row
			recordOwnerFence(t, s, "f1", "ipmi", "fenced", time.Minute)
			if _, err := s.db.DB().Exec(`ALTER TABLE ` + broken + ` RENAME TO ` + broken + `_gone`); err != nil {
				t.Fatal(err)
			}
			promoteVia(t, s, false, true)
			assertSharedUnattached(t, s, nfsDisk, "the state of its owner dead-host cannot be read")
			if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "db"}); err != nil {
				t.Fatalf("RestartVM: %v", err)
			}
			if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); strings.Contains(xml, nfsDisk) {
				t.Errorf("a restart attached data1 while its owner's rows cannot be read:\n%s", xml)
			}
		})
	}
}
