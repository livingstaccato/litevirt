package grpcapi

import (
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// seedDomain is a domain definition whose only CD-ROM is the cloud-init seed at
// seed.
func seedDomain(name, uuid, seed string) string {
	return `<domain><name>` + name + `</name><uuid>` + uuid + `</uuid><devices>` +
		`<disk type="file" device="cdrom"><source file="` + seed + `"/></disk>` +
		`</devices></domain>`
}

// seedCutoverFixture is restartFixture with a running replacement whose domain
// carries its own cloud-init seed, at the seed path of its temporary name.
func seedCutoverFixture(t *testing.T) (s *Server, nextSeed string) {
	t.Helper()
	s, _, _, _ = restartFixture(t)
	ctx := adminCtx()
	nextSeed = lv.CloudInitISOPath(s.dataDir, "app-next")
	if err := os.WriteFile(nextSeed, []byte("the replacement's seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET state = 'running', updated_at = ? WHERE name = ?`,
		s.db.NowTS(), "app-next"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.UndefineDomainPreservingState("app-next"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(seedDomain("app-next", "uuid-app-next", nextSeed)); err != nil {
		t.Fatal(err)
	}
	return s, nextSeed
}

// The cloud-init seed is name-keyed like the vars file. A cutover that renamed
// the domain but left its seed at the temporary name's path handed every later
// start a CD-ROM the ISO check reads as an installer ISO inside the data
// directory, so the VM could never start again.
func TestCutover_TheSeedFollowsTheVMToItsName(t *testing.T) {
	s, nextSeed := seedCutoverFixture(t)
	ctx := adminCtx()

	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	seed := lv.CloudInitISOPath(s.dataDir, "app")
	xml, err := s.virt.DumpXML("app")
	if err != nil {
		t.Fatalf("no domain at the contested name: %v", err)
	}
	if strings.Contains(xml, nextSeed) {
		t.Fatalf("the definition still points at the temporary name's seed:\n%s", xml)
	}
	if !strings.Contains(xml, seed) {
		t.Fatalf("the definition does not point at the VM's own seed:\n%s", xml)
	}
	body, err := os.ReadFile(seed)
	if err != nil || string(body) != "the replacement's seed" {
		t.Fatalf("the replacement's seed is not at the VM's seed path: %q, %v", body, err)
	}
	rec, err := corrosion.GetVM(ctx, s.db, "app")
	if err != nil || rec == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if err := s.verifyVMISOForStart(rec); err != nil {
		t.Fatalf("a start after the cutover is refused: %v", err)
	}
}

// A VM that took the freed temporary name owns the seed at that path; recovery
// must not move it onto the contested name.
func TestCutoverRestart_RecoveryWillNotStealAReusedNamesSeed(t *testing.T) {
	s, nextSeed := seedCutoverFixture(t)
	ctx := adminCtx()

	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the redefine failure must not report success")
	}
	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "app-next", HostName: s.hostName, State: "stopped",
			Spec: `{"name":"app-next","uuid":"a-different-vm"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nextSeed, []byte("the other VM's seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(seedDomain("app-next", "a-different-vm", nextSeed)); err != nil {
		t.Fatal(err)
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Logf("resume reported: %v", err)
	}
	body, err := os.ReadFile(nextSeed)
	if err != nil {
		t.Fatalf("recovery took the other VM's seed: %v", err)
	}
	if string(body) != "the other VM's seed" {
		t.Fatalf("the other VM's seed was replaced: %q", body)
	}
}
