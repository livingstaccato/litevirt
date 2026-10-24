package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// vlanDomainOps is the ops the fake recorded for domain, in order, with the
// VLAN ones carrying their note.
func vlanDomainOps(f *libvirtfake.Fake, domain string) []string {
	var out []string
	for _, e := range f.EventLog() {
		if e.Domain != domain {
			continue
		}
		switch e.Op {
		case "vlan-tap", "trunk-tap":
			out = append(out, e.Op+" "+e.Note)
		default:
			out = append(out, e.Op)
		}
	}
	return out
}

// opIndex is the index of the first op starting with prefix, or -1.
func opIndex(ops []string, prefix string) int {
	for i, op := range ops {
		if strings.HasPrefix(op, prefix) {
			return i
		}
	}
	return -1
}

// vlanStartServer is a server whose fake libvirt goes through the start guard
// the daemon wires (NICStartGuard), with a stopped VM vm1 that has a plain, an
// access (VLAN 30) and a trunk (100, 101) NIC.
func vlanStartServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := hotplugDiskServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "vm1", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{
			{Name: "plainnet", Mac: "52:54:00:aa:01:00"},
			{Name: "accnet", Mac: "52:54:00:aa:01:01", Trunk: []int32{30}},
			{Name: "trknet", Mac: "52:54:00:aa:01:02", Trunk: []int32{100, 101}},
		},
	}))
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateDefined)
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	return s, fake
}

// Every start goes through the start guard, and a guest whose NICs have VLANs
// on their taps is started PAUSED, its VLANs put on the taps libvirt made,
// and only then resumed: an access NIC never runs on VLAN 1, the bridge's
// untagged segment, not even for the moment between a start and a later
// re-apply. This is the one place the reconciler's failover, reschedule and
// onboot starts, a health restart, promote, clone, replace, restore and
// `lv start` get their VLANs (tap_vlans.go).
//
// Mutations: Before not pausing for tap VLANs — red (no VLAN is put on);
// AfterPaused not applying them — red.
func TestNICStartGuard_PutsTheTapVLANsOnBeforeTheGuestRuns(t *testing.T) {
	s, fake := vlanStartServer(t)
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	ops := vlanDomainOps(fake, "vm1")
	acc := opIndex(ops, "vlan-tap bridge="+network.FlatBridgeName("accnet")+" mac=52:54:00:aa:01:01 vlan=30")
	trk := opIndex(ops, "trunk-tap bridge="+network.FlatBridgeName("trknet")+" mac=52:54:00:aa:01:02 vlans=[100 101]")
	start, resume := opIndex(ops, "start"), opIndex(ops, "resume")
	if start < 0 || acc < 0 || trk < 0 || resume < 0 || !(start < acc && acc < resume && start < trk && trk < resume) {
		t.Fatalf("ops = %q: want start (paused), then each NIC's VLANs, then resume", ops)
	}
	if strings.Count(strings.Join(ops, "|"), "vlan-tap") != 1 {
		t.Fatalf("ops = %q: the plain NIC was given a VLAN, or the access NIC twice", ops)
	}
	if st, _ := fake.DomainState("vm1"); st != "running" {
		t.Fatalf("domain %q, want running", st)
	}
}

// An access NIC whose VLAN cannot be put on its tap would run on VLAN 1: the
// start is refused and the domain left down. (A trunk that cannot be
// configured only lacks its VLANs, and is logged.)
//
// Mutation: applyTapVLANNICs ignoring an access NIC's error — red.
func TestNICStartGuard_AnAccessVLANThatCannotBePutOnRefusesTheStart(t *testing.T) {
	s, fake := vlanStartServer(t)
	fake.FailConfigureVLANTap = func(string, string, int) error { return errors.New("RTNETLINK answers: Operation not supported") }
	_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"})
	if err == nil || !strings.Contains(err.Error(), "VLAN 30") {
		t.Fatalf("StartVM with an access VLAN that cannot be put on: %v, want a refusal naming VLAN 30", err)
	}
	if st, _ := fake.DomainState("vm1"); st == "running" {
		t.Fatal("the guest runs although its access NIC is not on its VLAN")
	}
	if opIndex(vlanDomainOps(fake, "vm1"), "resume") >= 0 {
		t.Fatalf("ops = %q: the guest was resumed", vlanDomainOps(fake, "vm1"))
	}
}

// A VM with no VLAN NIC (and no NIC guard) starts as before: not paused.
func TestNICStartGuard_APlainVMIsNotPaused(t *testing.T) {
	s := hotplugDiskServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "plain", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{
		Name: "plain", Cpu: 1, MemoryMib: 512, Network: []*pb.NetworkAttachment{{Name: "plainnet", Mac: "52:54:00:aa:02:00"}},
	}))
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("plain", libvirtfake.StateDefined)
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "plain"}); err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	if ops := vlanDomainOps(fake, "plain"); opIndex(ops, "resume") >= 0 || opIndex(ops, "vlan-tap") >= 0 {
		t.Fatalf("ops = %q: a plain VM was started paused or given a VLAN", ops)
	}
}

// A create's rows are written once its domain runs, so the guard reads its
// NICs' VLANs from the create itself (notePendingTapVLANs): the access VLAN is
// on the tap before the new guest's first instruction.
//
// Mutation: drop notePendingTapVLANs from createVM — red.
func TestCreateVM_PutsTheAccessVLANOnBeforeTheGuestRuns(t *testing.T) {
	s, fake := provableCreateServer(t)
	s.SetBridgeEnsure(func(string) error { return nil })
	s.SetNetPreflight(func([]network.PreFlightCheck) error { return nil })
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	req := disklessCreateRequest("acc")
	req.Spec.Network[0].Trunk = []int32{30}
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	ops := vlanDomainOps(fake, "acc")
	acc, start, resume := opIndex(ops, "vlan-tap bridge=lo "), opIndex(ops, "start"), opIndex(ops, "resume")
	if acc < 0 || !(start < acc && acc < resume) {
		t.Fatalf("ops = %q: want start (paused), the access VLAN on lo, then resume", ops)
	}
	if _, pending := s.pendingTapVLANs.Load("acc"); pending {
		t.Fatal("the create's pending tap VLANs outlived it")
	}
}

// A guest that arrived here paused — a live move handed over paused for its
// NIC guards or its tap VLANs — is resumed by ArmNICFirewall(resume) only once
// its VLANs are on the taps it got here.
//
// Mutation: ArmNICFirewall's resume calling ArmNICsFor instead of
// readyGuestHere — red.
func TestArmNICFirewallResume_PutsTheTapVLANsOnBeforeTheResume(t *testing.T) {
	s, fake := vlanStartServer(t)
	fake.SetState("vm1", libvirtfake.StatePaused)
	fake.SetStateReason("vm1", "paused")
	if _, err := s.ArmNICFirewall(peerCtxFor(t, s, "node-src"), &pb.ArmNICFirewallRequest{VmName: "vm1", Resume: true}); err != nil {
		t.Fatalf("ArmNICFirewall(resume): %v", err)
	}
	ops := vlanDomainOps(fake, "vm1")
	acc, resume := opIndex(ops, "vlan-tap"), opIndex(ops, "resume")
	if acc < 0 || resume < 0 || acc > resume {
		t.Fatalf("ops = %q: want the access VLAN on before the resume", ops)
	}

	fake.SetState("vm1", libvirtfake.StatePaused)
	fake.FailConfigureVLANTap = func(string, string, int) error { return errors.New("no") }
	if _, err := s.ArmNICFirewall(peerCtxFor(t, s, "node-src2"), &pb.ArmNICFirewallRequest{VmName: "vm1", Resume: true}); err == nil {
		t.Fatal("a guest whose access VLAN cannot be put on was resumed")
	}
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("state %v, want it held paused", st)
	}
}

// ConvergeTapVLANs puts every running guest's NIC VLANs back on its taps on a
// timer: a guest a path missed, or whose tap was changed behind litevirt's
// back, is put right; a stopped one, and a VM with no VLAN NIC, are left.
//
// Mutations: ConvergeTapVLANs a no-op — red; walking every VM row instead of
// the domains running here — red.
func TestConvergeTapVLANs_ReappliesEveryRunningGuest(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "off", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{
		Name: "off", Cpu: 1, MemoryMib: 512, Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:aa:03:01", Trunk: []int32{30}}},
	}))
	fake.SetState("off", libvirtfake.StateDefined)
	fake.SetState("vm1", libvirtfake.StateRunning) // started behind the guard's back
	s.ConvergeTapVLANs(ctx)
	ops := vlanDomainOps(fake, "vm1")
	if opIndex(ops, "vlan-tap bridge="+network.FlatBridgeName("accnet")+" mac=52:54:00:aa:01:01 vlan=30") < 0 || opIndex(ops, "trunk-tap") < 0 {
		t.Fatalf("vm1 ops = %q: the running guest's VLANs were not converged", ops)
	}
	if ops := vlanDomainOps(fake, "off"); opIndex(ops, "vlan-tap") >= 0 {
		t.Fatalf("off ops = %q: a stopped guest was touched", ops)
	}

	// It works from the domains libvirt runs here (NB-R4): with that list
	// unreadable, it converges nothing this pass.
	before := len(vlanDomainOps(fake, "vm1"))
	fake.FailRunningDomainTaps = func() error { return errors.New("libvirt is restarting") }
	s.ConvergeTapVLANs(ctx)
	if after := len(vlanDomainOps(fake, "vm1")); after != before {
		t.Fatalf("converged without the list of domains running here (%d ops, then %d)", before, after)
	}
}

// The start paths and the resumes of a guest that came here from elsewhere
// cannot miss the tap VLANs, by construction:
//
//   - in this package, every function that resumes a domain (ResumeDomain,
//     ResumeFirmwareMoveTarget) calls readyGuestHere before it;
//   - nothing outside internal/libvirt, its fake and this package resumes a
//     domain at all, so a resume elsewhere has to come through here.
//
// Starts need no list: libvirt.Client starts a domain only through its start
// guard (TestEveryDomainStartGoesThroughTheStartGuard in internal/libvirt),
// which is NICStartGuard. A new resume path that skips readyGuestHere fails
// here; one that is a resume of a guest that never left this host (its taps
// unchanged) goes in sameTapResumes with the reason.
//
// Mutation: delete the readyGuestHere call from resumeHeld — red.
func TestResumesOfAMovedGuestGoThroughReadyGuestHere(t *testing.T) {
	resumes := map[string]bool{"ResumeDomain": true, "ResumeFirmwareMoveTarget": true}
	// A resume of a guest whose taps did not change: none in this package.
	sameTapResumes := map[string]string{}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, pkg := range pkgs {
		for fname, f := range pkg.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				readyAt := token.NoPos
				var resumeAt []token.Pos
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch {
					case sel.Sel.Name == "readyGuestHere" && readyAt == token.NoPos:
						readyAt = call.Pos()
					case resumes[sel.Sel.Name]:
						resumeAt = append(resumeAt, call.Pos())
					}
					return true
				})
				if len(resumeAt) == 0 {
					continue
				}
				found++
				if _, ok := sameTapResumes[fd.Name.Name]; ok {
					continue
				}
				for _, at := range resumeAt {
					if readyAt == token.NoPos || readyAt > at {
						t.Errorf("%s: %s resumes a domain at %s without readyGuestHere before it: its NICs' VLANs "+
							"may not be on the taps it has here", filepath.Base(fname), fd.Name.Name, fset.Position(at))
					}
				}
			}
		}
	}
	if found < 4 {
		t.Fatalf("found %d resuming functions, want at least resumeHeld, ArmNICFirewall, resumeReleased and releaseAdoptedHold: the scan is broken", found)
	}

	// No resume outside the packages that own it.
	root := filepath.Join("..", "..")
	allowed := []string{
		filepath.Join("internal", "libvirt") + string(filepath.Separator),
		filepath.Join("internal", "libvirtfake") + string(filepath.Separator),
		filepath.Join("internal", "grpcapi") + string(filepath.Separator),
	}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			for _, a := range allowed {
				if strings.HasPrefix(rel, a) {
					return nil
				}
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range []string{".ResumeDomain(", ".ResumeFirmwareMoveTarget(", ".DomainResume("} {
				if strings.Contains(string(src), m) {
					t.Errorf("%s calls %s: a resume outside internal/grpcapi skips readyGuestHere (the guest's tap VLANs)", rel, strings.Trim(m, ".("))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A hot attach records the NIC in its rows only, and a NIC's VLANs are put on
// its tap from the VM's spec: a trunk given to an attach would never reach the
// tap, and an access NIC would join the bridge's untagged segment. Refused,
// with nothing attached; the same NIC without a trunk attaches.
//
// Mutation: drop the trunk refusal from attachNICEntry — red.
func TestNICHotplug_ATrunkIsRefused(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "plain", "running")
	fake := s.virt.(*libvirtfake.Fake)
	for _, trunk := range [][]int32{{30}, {100, 101}} {
		_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "plain",
			Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:5e:01:01", Trunk: trunk}})
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "trunk") {
			t.Fatalf("attach with trunk %v: %v, want InvalidArgument", trunk, err)
		}
	}
	for _, e := range fake.EventLog() {
		if e.Domain == "plain" && strings.Contains(e.Op, "attach") {
			t.Fatalf("a refused attach reached libvirt: %+v", e)
		}
	}
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "plain",
		Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:5e:01:01"}}); err != nil {
		t.Fatalf("attach without a trunk: %v", err)
	}
}

// A clone started at creation has no row until it runs, as a create: the
// guard reads its NICs' VLANs from the clone itself, with the clone's own
// MAC, and puts them on before the guest runs.
//
// Mutation: drop pendingTapVLANsFor from CloneVM — red.
func TestCloneVM_AStartedClonesAccessVLANIsOnBeforeItRuns(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	srcDisk := s.images.DiskPath("src", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "src", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:aa:04:01", Trunk: []int32{30}}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "src", HostName: "test-host", State: "stopped", Spec: string(specJSON)},
		[]corrosion.InterfaceRecord{{VMName: "src", NetworkName: "accnet", Ordinal: 0, MAC: "52:54:00:aa:04:01"}},
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "test-host",
			Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM src: %v", err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src", Target: "clone1", Mode: "full", Start: true}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	ops := vlanDomainOps(fake, "clone1")
	tap, start, resume := opIndex(ops, "vlan-tap"), opIndex(ops, "start"), opIndex(ops, "resume")
	if tap < 0 || !(start < tap && tap < resume) {
		t.Fatalf("ops = %q: want start (paused), the access VLAN, then resume", ops)
	}
	if strings.Contains(ops[tap], "52:54:00:aa:04:01") || !strings.Contains(ops[tap], "vlan=30") {
		t.Fatalf("the clone's tap op %q: want VLAN 30 on the clone's own MAC, not its source's", ops[tap])
	}
}

// A restore that starts the VM writes its row after the start, as a create
// does: the guard reads the NICs' VLANs from the restore and puts them on
// before the guest runs.
//
// Mutation: drop pendingTapVLANsFor from the restore's autostart — red.
func TestRestoreLive_AutoStart_PutsTheAccessVLANOnBeforeItRuns(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, "")
	target := filepath.Join(t.TempDir(), "live.qcow2")
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true, NewName: "vm1-restored",
		Spec: &pb.VMSpec{Name: "x", Cpu: 1, MemoryMib: 512, Machine: "q35",
			Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:aa:05:01", Trunk: []int32{30}}}},
	}, pb.RestoreLiveProgress_STARTED)
	defer func() { cancel(); <-done }()
	ops := vlanDomainOps(fake, "vm1-restored")
	tap, start, resume := opIndex(ops, "vlan-tap"), opIndex(ops, "start"), opIndex(ops, "resume")
	if tap < 0 || !(start < tap && tap < resume) || !strings.Contains(ops[tap], "vlan=30") {
		t.Fatalf("ops = %q: want start (paused), VLAN 30 on the tap, then resume", ops)
	}
}

// NB-4: convergeMovedGuest — the doctor's finish of a move whose guest now
// runs here — puts the guest's NIC VLANs on its taps here; a guest that does
// not run here has no taps, and nothing is configured.
//
// Mutation: drop applyTapVLANs from convergeMovedGuest — red.
func TestConvergeMovedGuest_PutsTheVLANsOnARunningGuestsTaps(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	rec, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || rec == nil {
		t.Fatalf("GetVM: %v", err)
	}
	s.convergeMovedGuest(ctx, rec, "other-host", s.hostName, false)
	if ops := vlanDomainOps(fake, "vm1"); opIndex(ops, "vlan-tap") >= 0 {
		t.Fatalf("ops = %q: VLANs configured for a guest that does not run here", ops)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)
	s.convergeMovedGuest(ctx, rec, "other-host", s.hostName, true)
	ops := vlanDomainOps(fake, "vm1")
	if opIndex(ops, "vlan-tap bridge="+network.FlatBridgeName("accnet")+" mac=52:54:00:aa:01:01 vlan=30") < 0 || opIndex(ops, "trunk-tap") < 0 {
		t.Fatalf("ops = %q: want the access VLAN and the trunk on the running guest's taps", ops)
	}
}

// R-B2: clone --start, which (like promote, replace and import) does not run
// the start preflight, is refused at the guard when the clone's access NIC is
// on a bridge here that does not filter VLANs.
//
// Mutation: drop the bridge check from applyTapVLANNICs — red.
func TestCloneVM_AStartedCloneOnANonFilteringBridgeIsRefused(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	s.SetBridgeVLANFiltering(func(string) (bool, bool, error) { return true, false, nil })
	srcDisk := s.images.DiskPath("src", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "src", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:aa:06:01", Trunk: []int32{30}}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "src", HostName: "test-host", State: "stopped", Spec: string(specJSON)},
		[]corrosion.InterfaceRecord{{VMName: "src", NetworkName: "accnet", Ordinal: 0, MAC: "52:54:00:aa:06:01"}},
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "test-host",
			Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	_, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src", Target: "clone1", Mode: "full", Start: true})
	if err == nil || !strings.Contains(err.Error(), "does not filter VLANs") {
		t.Fatalf("clone --start onto a non-filtering bridge: %v, want a refusal naming it", err)
	}
	if st, _ := fake.DomainState("clone1"); st == "running" {
		t.Fatal("the clone runs on a bridge that does not filter VLANs")
	}
}

// A guest that arrived here (a hand-over resumed by ArmNICFirewall) on a
// bridge that does not filter VLANs is held unless its network allows
// unfiltered moves; with the opt-in it runs. A start there is refused either
// way.
//
// Mutation: honour the opt-in for starts too (ignore how) — red.
func TestReadyGuestHere_TheOptInCoversArrivalsNotStarts(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	s.SetBridgeVLANFiltering(func(string) (bool, bool, error) { return true, false, nil })
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "accnet", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"accnet","AllowUnfilteredAccessVLANMoves":true}`}); err != nil {
		t.Fatal(err)
	}
	// Straight at the guard, as promote, clone, replace and import start a
	// domain (they do not run the start preflight).
	if err := fake.StartDomain("vm1"); err == nil {
		t.Fatal("a start on a non-filtering bridge ran, the network's opt-in notwithstanding")
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	fake.SetStateReason("vm1", "paused")
	if _, err := s.ArmNICFirewall(peerCtxFor(t, s, "node-src"), &pb.ArmNICFirewallRequest{VmName: "vm1", Resume: true}); err != nil {
		t.Fatalf("an arrival on a network that allows unfiltered moves: %v", err)
	}
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "accnet", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"accnet"}`}); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	if _, err := s.ArmNICFirewall(peerCtxFor(t, s, "node-src2"), &pb.ArmNICFirewallRequest{VmName: "vm1", Resume: true}); err == nil {
		t.Fatal("an arrival on a non-filtering bridge without the opt-in was resumed")
	}
}

// NB-R2: an access NIC whose MAC cannot be resolved refuses the start instead
// of running unpaused on VLAN 1.
//
// Mutation: skip such a NIC in tapVLANNICs — red.
func TestNICStartGuard_AnAccessNICWithNoMACRefusesTheStart(t *testing.T) {
	s := hotplugDiskServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "nomac", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{
		Name: "nomac", Cpu: 1, MemoryMib: 512, Network: []*pb.NetworkAttachment{{Name: "accnet", Trunk: []int32{30}}},
	}))
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("nomac", libvirtfake.StateDefined)
	fake.SetStartGuard(s.NICStartGuard(context.Background()))
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "nomac"}); err == nil || !strings.Contains(err.Error(), "MAC or bridge") {
		t.Fatalf("StartVM with an unresolvable access NIC: %v, want a refusal", err)
	}
	if st, _ := fake.DomainState("nomac"); st == "running" {
		t.Fatal("it runs")
	}
}
