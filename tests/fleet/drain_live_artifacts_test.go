// Fleet scenarios for what a drain's LIVE move puts on the target before
// libvirt is handed the guest. libvirt validates every file and bridge the
// domain names on the destination before it moves anything, so the target
// must already hold the VM's cloud-init ISO and its networks. `lv migrate`
// has always asked the target for both (migrateOwnedVM); the drain did not,
// so on lab 2 every cloud-init VM's live drain failed with "Cannot access
// storage file '/var/lib/litevirt/cloudinit/<vm>.iso'" and fell back to a cold
// move that waits for the guest to shut down (lab2c-report.md, bug 2).
//
// Multi-node by construction: the ISO and the network are made on the target
// by its own RPCs, which the source sends over real gRPC.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// liveDrainScenario is two nodes with "ci" running on src, every disk on
// shared storage (none recorded), with a cloud-init ISO on src only and one
// NIC on the cluster network "lan". The source's libvirt behaves as libvirt
// does on the destination: a live move fails unless the target holds the
// VM's ISO and has provisioned "lan".
type liveDrainScenario struct {
	c        *Cluster
	src, dst *Node
	srcISO   string
	dstISO   string

	mu          sync.Mutex
	provisioned map[string]bool // networks dst was asked to provision
}

func newLiveDrainScenario(t *testing.T) *liveDrainScenario {
	t.Helper()
	ctx := context.Background()
	// EnsureCloudInit shells out to genisoimage; the libvirt fake never reads
	// the ISO, so the stand-in's empty file is all it needs.
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	sc := &liveDrainScenario{c: c, src: c.Nodes[0], dst: c.Nodes[1], provisioned: map[string]bool{}}
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	sc.srcISO = filepath.Join(c.tmpRoot, sc.src.Name, "data", "cloudinit", "ci.iso")
	sc.dstISO = filepath.Join(c.tmpRoot, sc.dst.Name, "data", "cloudinit", "ci.iso")
	if err := os.MkdirAll(filepath.Dir(sc.srcISO), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sc.srcISO, []byte("source iso"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := corrosion.UpsertNetwork(ctx, sc.src.DB, corrosion.NetworkRecord{
		Name: "lan", Type: "bridge", Config: `{"name":"lan","type":"bridge"}`,
	}); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(&pb.VMSpec{
		Name: "ci", Cpu: 1, MemoryMib: 256,
		CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: ci\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, sc.src.DB, corrosion.VMRecord{
		Name: "ci", HostName: sc.src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, []corrosion.InterfaceRecord{{VMName: "ci", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	sc.src.Virt.SetState("ci", "running")

	// The target's network setup is the real handler's job on a real host; the
	// scenario records that it was asked and answers as a host that did it.
	sc.armProvisionHook()
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "ci" {
			return nil
		}
		if _, err := os.Stat(sc.dstISO); err != nil {
			return fmt.Errorf("operation failed: Cannot access storage file '%s': No such file or directory", sc.dstISO)
		}
		sc.mu.Lock()
		defer sc.mu.Unlock()
		if !sc.provisioned["lan"] {
			return errors.New("Cannot get interface MTU on 'lv-lan': No such device")
		}
		return nil
	}
	return sc
}

// armProvisionHook answers the next few ProvisionNetwork calls on dst.
func (sc *liveDrainScenario) armProvisionHook() {
	for i := 0; i < 4; i++ {
		sc.dst.HookUnary("ProvisionNetwork", func(_ context.Context, req any, _ grpc.UnaryHandler) (any, error) {
			sc.mu.Lock()
			sc.provisioned[req.(*pb.ProvisionNetworkRequest).GetName()] = true
			sc.mu.Unlock()
			return &emptypb.Empty{}, nil
		})
	}
}

func (sc *liveDrainScenario) drain(t *testing.T) (*pb.DrainProgress, error) {
	t.Helper()
	st, err := sc.c.SelfClient(sc.src).DrainHost(context.Background(), &pb.DrainHostRequest{Name: sc.src.Name})
	if err != nil {
		return nil, err
	}
	var last *pb.DrainProgress
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return last, nil
		}
		if rerr != nil {
			return last, rerr
		}
		if p.GetVmName() == "ci" {
			last = p
		}
	}
}

func (sc *liveDrainScenario) srcOps(op string) int {
	n := 0
	for _, e := range sc.src.Virt.EventLog() {
		if e.Op == op && e.Domain == "ci" {
			n++
		}
	}
	return n
}

// A running cloud-init VM on shared storage drains LIVE to a target that held
// neither its ISO nor its network: the drain puts both there first, as `lv
// migrate` does, and the guest is never shut down. After the cut-over the
// source's ISO is cleaned up, as a migration's is.
//
// Mutations: drop the cloud-init ensure from the shared target preparation
// (or skip that preparation in the drain) — libvirt refuses, the drain falls
// back to a cold move, and the strategy and shutdown count go red. Drop the
// network provisioning — the same. Skip the post-migration finish in the
// drain — the source ISO is left behind and goes red.
func TestFleet_DrainMovesACloudInitVMLiveToATargetWithoutItsISO(t *testing.T) {
	sc := newLiveDrainScenario(t)

	p, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain of a host holding one running cloud-init VM on shared storage: %v", err)
	}
	if p == nil || p.Status != "done" || p.Error != "" || p.Strategy != pb.MigrateStrategy_MIGRATE_LIVE {
		t.Fatalf("drain progress for ci = %+v, want a LIVE move, done, no error", p)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Errorf("ci was shut down %d time(s); a live drain never shuts the guest down", n)
	}
	if n := sc.srcOps("migrate"); n != 1 {
		t.Errorf("libvirt was asked to migrate ci %d time(s), want 1", n)
	}
	if _, err := os.Stat(sc.dstISO); err != nil {
		t.Errorf("the target holds no cloud-init ISO for ci after the move: %v", err)
	}
	sc.mu.Lock()
	lan := sc.provisioned["lan"]
	sc.mu.Unlock()
	if !lan {
		t.Errorf("the target was never asked to provision network lan")
	}
	vm, err := corrosion.GetVM(context.Background(), sc.src.DB, "ci")
	if err != nil || vm == nil || vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Fatalf("ci row = %+v (err %v), want running on %s", vm, err, sc.dst.Name)
	}
	// cleanupPostMigration runs in the background after the cut-over.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sc.srcISO); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the drained host still holds ci's cloud-init ISO after the live move")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A live attempt that libvirt fails for another reason takes back the ISO it
// put on the target before the drain falls back to a cold move. Here that
// cold move then fails too — the guest ignores its shutdown — so nothing else
// would ever remove it, and the target would keep an ISO for a VM it does not
// run.
//
// Mutation: drop the target cleanup on the live failure — the ISO stays on
// the target and goes red.
func TestFleet_AFailedLiveDrainTakesBackTheISOItPutOnTheTarget(t *testing.T) {
	sc := newLiveDrainScenario(t)
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if _, err := os.Stat(sc.dstISO); err != nil {
			t.Errorf("the live attempt reached libvirt without the ISO on the target: %v", err)
		}
		return errors.New("injected live migration failure")
	}
	sc.src.Virt.IgnoreShutdown = func(string) bool { return true }

	p, err := sc.drain(t)
	if err == nil {
		t.Fatal("drain of a VM that could neither move live nor shut down reported success")
	}
	if p == nil || p.Status != "error" {
		t.Fatalf("drain progress for ci = %+v, want error (the guest never shut down)", p)
	}
	if _, err := os.Stat(sc.dstISO); !os.IsNotExist(err) {
		t.Errorf("the target still holds the cloud-init ISO the failed live attempt put there (stat: %v)", err)
	}
	if _, err := os.Stat(sc.srcISO); err != nil {
		t.Errorf("the source's own ISO is gone, though ci still runs there: %v", err)
	}
}

// While a drain's cold move waits for the guest to shut down, the row already
// says stopped (an operator stop to every health decision), but the domain
// still runs. What the owner shows for it is VM_STOPPING, not VM_STOPPED: on
// lab 2 a guest that ignored ACPI showed STOPPED for five minutes while it ran
// (lab2c-report.md, bug 4). The cold move itself is unchanged.
//
// Mutation: drop the drain-stop case from the shown state — both reads say
// VM_STOPPED and go red.
func TestFleet_ADrainColdMoveShowsTheVMStoppingWhileItsGuestRuns(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	var inspected, listed pb.VMState
	var read bool
	var readErr error
	sc.src.Virt.FailShutdownDomain = func(name string) error {
		if name != "os1" || read {
			return nil
		}
		read = true
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cl := sc.c.SelfClient(sc.src)
		v, err := cl.InspectVM(ctx, &pb.InspectVMRequest{Name: "os1"})
		if err != nil {
			readErr = err
			return nil
		}
		inspected = v.GetState()
		l, err := cl.ListVMs(ctx, &pb.ListVMsRequest{})
		if err != nil {
			readErr = err
			return nil
		}
		for _, vm := range l.GetVms() {
			if vm.GetName() == "os1" {
				listed = vm.GetState()
			}
		}
		return nil
	}

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" {
		t.Fatalf("drain progress for os1 = %+v, want done", p)
	}
	if !read {
		t.Fatal("os1 was never shut down")
	}
	if readErr != nil {
		t.Fatalf("reading os1 while its guest shut down: %v", readErr)
	}
	if inspected != pb.VMState_VM_STOPPING || listed != pb.VMState_VM_STOPPING {
		t.Fatalf("os1 while its guest was still running for the cold move: inspect %v, list %v; want VM_STOPPING for both",
			inspected, listed)
	}
	// Once the move is done the VM is what it is: running on the target.
	if v, err := sc.c.SelfClient(sc.dst).InspectVM(context.Background(), &pb.InspectVMRequest{Name: "os1"}); err != nil ||
		v.GetState() != pb.VMState_VM_RUNNING {
		t.Fatalf("os1 after the move: %v (err %v), want VM_RUNNING", v.GetState(), err)
	}
}
