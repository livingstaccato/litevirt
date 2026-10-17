package fleet

// The scene every live firmware move scenario stands on (tests/fleet/fwlive*):
// two nodes, src running fwlive1 (Secure Boot + vTPM) with its firmware state
// in src's store, dst labelled for a live firmware move, one firmware layout,
// src's migrations landing on dst, and the one-copy invariant watched on both
// hosts for the whole test. The accessors read fwlive1's records, row, domain
// and files on a node.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// fwliveScene is the scene of one scenario.
type fwliveScene struct {
	c        *Cluster
	src, dst *Node
	// one watches the one-copy invariant.
	one *fwliveOneCopy
	// disk is the host-local disk's path when the VM has one (a storage
	// copy), else "".
	disk string
}

// fwliveSetup builds the scene; withDisk gives fwlive1 one host-local disk,
// copied with the memory (a storage copy), and both hosts migration TLS (a
// storage copy carries the TPM state and has no plaintext fallback). Each
// node's daemon configuration is reapplied on every restart (serverSetup).
func fwliveSetup(t *testing.T, withDisk bool) *fwliveScene {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	sc := &fwliveScene{c: c, src: src, dst: dst}
	ctx := context.Background()
	setHostCapacity(t, c, src.Name, 64, 65536)
	setHostCapacity(t, c, dst.Name, 64, 65536)
	layout := filepath.Join(c.tmpRoot, "layout")
	setup := func(s *grpcapi.Server) {
		s.SetFirmwareLayoutDirForTest(layout)
		if withDisk {
			s.SetMigrationTLS(func() (bool, error) { return true, nil })
		}
	}
	for _, n := range c.Nodes {
		n.serverSetup = setup
		setup(n.Server)
	}
	for _, l := range []string{corrosion.LabelTPMCapable, corrosion.LabelSecureBootCapable, corrosion.LabelFwLiveMigrate} {
		if err := corrosion.SetHostLabel(ctx, src.DB, dst.Name, l, "true"); err != nil {
			t.Fatal(err)
		}
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: fwwVM, Cpu: 1, MemoryMib: 256, SecureBoot: true, Tpm: true, Firmware: "uefi", Uuid: fwwUUID})
	if err != nil {
		t.Fatal(err)
	}
	var disks []corrosion.DiskRecord
	if withDisk {
		sc.disk = filepath.Join(c.tmpRoot, dst.Name, "data", "disks", fwwVM+"-root.qcow2")
		disks = []corrosion.DiskRecord{{VMName: fwwVM, DiskName: "root", HostName: src.Name, Path: sc.disk,
			SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda"}}
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: fwwVM, HostName: src.Name, State: "running",
		Spec: string(spec), CPUActual: 1, MemActual: 256}, nil, disks); err != nil {
		t.Fatal(err)
	}
	x := "<domain type='kvm'><name>" + fwwVM + "</name><uuid>" + fwwUUID + "</uuid><os><type>hvm</type>" +
		"<loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.secboot.fd</loader>" +
		"<nvram>" + src.FW.NvramPath(fwwVM) + "</nvram></os><devices>" +
		"<tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='yes'/></tpm></devices></domain>"
	src.Virt.SetInactiveXML(fwwVM, x)
	src.Virt.SetActiveXML(fwwVM, x)
	src.Virt.SetState(fwwVM, libvirtfake.StateRunning)
	hlWrite(t, fwlivePermall(src), fwwPermall)
	hlWrite(t, src.FW.NvramPath(fwwVM), fwwNvram)
	src.LandMigrationsOn(dst)
	sc.one = fwliveWatchOneCopy(t, src, dst)
	// A failed test may leave a daemon's goroutine frozen in a handler of a
	// server that was never replaced (fwlive_restart_test.go kills daemons
	// that way, and never lets them go): stop every server outright first,
	// so the cluster's graceful stop does not wait on it.
	t.Cleanup(func() {
		if t.Failed() {
			for _, n := range c.Nodes {
				n.Stop()
			}
		}
	})
	return sc
}

// migrate runs `lv migrate fwlive1 <dst>` on src (live, a storage copy when
// the VM has a disk) and returns its terminal error.
func (sc *fwliveScene) migrate(t *testing.T) error {
	t.Helper()
	return fwliveWait(t, fwliveMigrateReq(t, sc.c, sc.src, &pb.MigrateVMRequest{
		VmName: fwwVM, TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: sc.disk != "",
	}))
}

// fwliveCluster is fwliveSetup without a disk, unpacked.
func fwliveCluster(t *testing.T) (*Cluster, *Node, *Node, *fwliveOneCopy) {
	t.Helper()
	sc := fwliveSetup(t, false)
	return sc.c, sc.src, sc.dst, sc.one
}

// fwliveOneCopy records each moment fwlive1 started running on one host while
// the other host ran it: one copy of the VM at every moment. It is event
// driven (the fakes' OnRunning, called each time a domain starts running: a
// start or a resume), so no overlap is missed between two looks, and it
// reports at the end of the test. A scenario adds its own reaction to a guest
// starting with onRunning, before the move starts.
type fwliveOneCopy struct {
	mu   sync.Mutex
	bad  []string
	also map[*libvirtfake.Fake]func(name string)
}

func fwliveWatchOneCopy(t *testing.T, a, b *Node) *fwliveOneCopy {
	w := &fwliveOneCopy{also: map[*libvirtfake.Fake]func(string){}}
	watch := func(self, other *libvirtfake.Fake, host string) {
		self.OnRunning = func(name string) {
			if name == fwwVM {
				if st, _ := other.RawState(name); st == libvirtfake.StateRunning {
					w.mu.Lock()
					w.bad = append(w.bad, fmt.Sprintf("%s started running on %s while the other host ran it", name, host))
					w.mu.Unlock()
				}
			}
			w.mu.Lock()
			fn := w.also[self]
			w.mu.Unlock()
			if fn != nil {
				fn(name)
			}
		}
	}
	watch(a.Virt, b.Virt, a.Name)
	watch(b.Virt, a.Virt, b.Name)
	t.Cleanup(func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, s := range w.bad {
			t.Errorf("one copy of the VM at every moment: %s", s)
		}
	})
	return w
}

// onRunning sets n's extra reaction to a guest starting to run there.
func (w *fwliveOneCopy) onRunning(n *Node, fn func(name string)) {
	w.mu.Lock()
	w.also[n.Virt] = fn
	w.mu.Unlock()
}

// fwliveMigrateReq starts the move req asks of src and returns its outcome
// when it ends.
func fwliveMigrateReq(t *testing.T, c *Cluster, src *Node, req *pb.MigrateVMRequest) <-chan error {
	t.Helper()
	cl := c.SelfClient(src)
	done := make(chan error, 1)
	go func() {
		st, err := cl.MigrateVM(context.Background(), req)
		if err != nil {
			done <- err
			return
		}
		for {
			if _, err := st.Recv(); err != nil {
				if err == io.EOF {
					err = nil
				}
				done <- err
				return
			}
		}
	}()
	return done
}

// fwliveMigrate starts the live move of fwlive1 from src to dst.
func fwliveMigrate(t *testing.T, c *Cluster, src, dst *Node) <-chan error {
	t.Helper()
	return fwliveMigrateReq(t, c, src, &pb.MigrateVMRequest{
		VmName: fwwVM, TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	})
}

// fwliveWait waits for a move's outcome.
func fwliveWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Minute):
		t.Fatal("the move did not end within 3 minutes")
		return nil
	}
}

func fwliveMarker(t *testing.T, n *Node) (fwmig.Marker, bool) {
	t.Helper()
	m, ok, err := fwmig.New(n.FW.DataDir).GetMarker(fwwVM)
	if err != nil {
		t.Fatalf("read the marker on %s: %v", n.Name, err)
	}
	return m, ok
}

func fwliveHold(t *testing.T, n *Node) (fwmig.Hold, bool) {
	t.Helper()
	h, ok, err := fwmig.New(n.FW.DataDir).GetHold(fwwVM)
	if err != nil {
		t.Fatalf("read the hold on %s: %v", n.Name, err)
	}
	return h, ok
}

func fwliveRow(t *testing.T, n *Node) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, fwwVM)
	if err != nil || vm == nil {
		t.Fatalf("read %s's row: %v (row %v)", fwwVM, err, vm)
	}
	return vm
}

// fwliveState is fwlive1's domain state on n, "undefined" when it has none.
func fwliveState(n *Node) string {
	st, ok := n.Virt.RawState(fwwVM)
	if !ok {
		return "undefined"
	}
	return string(st)
}

// fwlivePermall is fwlive1's permall path in n's store.
func fwlivePermall(n *Node) string {
	return filepath.Join(n.FW.SwtpmDir(fwwUUID), "tpm2", "tpm2-00.permall")
}

func fwliveFile(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	return b, err == nil
}

func fwliveExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fwliveQuarantines(n *Node) []string {
	q, _ := filepath.Glob(filepath.Join(n.FW.DataDir, fwmig.QuarantineDir, fwwVM+"-*"))
	return q
}

// fwliveQuarantine is the one quarantine directory n keeps for fwlive1, or "".
func fwliveQuarantine(t *testing.T, n *Node) string {
	t.Helper()
	q := fwliveQuarantines(n)
	if len(q) > 1 {
		t.Fatalf("quarantines %v, want at most one", q)
	}
	if len(q) == 0 {
		return ""
	}
	return q[0]
}

// fwliveOps lists the libvirt operations n's fake performed on fwlive1, in
// order.
func fwliveOps(n *Node) []string {
	var ops []string
	for _, e := range n.Virt.EventLog() {
		if e.Domain == fwwVM {
			ops = append(ops, e.Op)
		}
	}
	return ops
}

func fwliveDid(n *Node, op string) bool {
	for _, o := range fwliveOps(n) {
		if o == op {
			return true
		}
	}
	return false
}

// fwliveCondition reports whether n's database holds the open
// firmware_migration condition code for fwlive1.
func fwliveCondition(t *testing.T, n *Node, code string) bool {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), n.DB, "firmware_migration", code, "vm", fwwVM)
	if err != nil {
		t.Fatalf("read condition %s: %v", code, err)
	}
	return found && row.Lifecycle != corrosion.ConditionResolved
}

// fwliveOpenConditions lists the firmware_migration conditions open for
// fwlive1 in n's database.
func fwliveOpenConditions(t *testing.T, n *Node) []string {
	t.Helper()
	conds, err := corrosion.ListHealthConditions(context.Background(), n.DB, false)
	if err != nil {
		t.Fatalf("list conditions: %v", err)
	}
	var open []string
	for _, c := range conds {
		if c.Evaluator == "firmware_migration" && c.SubjectKind == "vm" && c.SubjectID == fwwVM {
			open = append(open, c.Code)
		}
	}
	return open
}

// fwliveMoved asserts the move completed (§6.1 steps 9 to 12): the guest
// runs on dst with the source's final NVRAM and TPM state, the row names
// dst, no hold, marker, quarantine or open condition remains, the source
// leftover is undefined and its state wiped, and the retained bundle keeps
// it.
func fwliveMoved(t *testing.T, src, dst *Node) {
	t.Helper()
	if st := fwliveState(dst); st != string(libvirtfake.StateRunning) {
		t.Errorf("%s's domain is %s, want running", dst.Name, st)
	}
	if st := fwliveState(src); st != "undefined" {
		t.Errorf("%s's leftover domain is %s, want undefined", src.Name, st)
	}
	if row := fwliveRow(t, src); row.HostName != dst.Name || row.State != "running" {
		t.Errorf("row on %s %s, want running on %s", row.HostName, row.State, dst.Name)
	}
	if b, _ := fwliveFile(dst.FW.NvramPath(fwwVM)); !bytes.Equal(b, fwwNvram) {
		t.Errorf("%s's NVRAM %q, want the source's final", dst.Name, b)
	}
	if b, _ := fwliveFile(fwlivePermall(dst)); !bytes.HasPrefix(b, fwwPermall) {
		t.Errorf("%s's permall %q, want the source's (then the running swtpm's)", dst.Name, b)
	}
	if h, ok := fwliveHold(t, dst); ok {
		t.Errorf("%s still holds the move (%s)", dst.Name, h.State)
	}
	if m, ok := fwliveMarker(t, src); ok {
		t.Errorf("%s's marker is left in %s (%s)", src.Name, m.Phase, m.Detail)
	}
	for _, p := range []string{fwlivePermall(src), src.FW.NvramPath(fwwVM)} {
		if fwliveExists(p) {
			t.Errorf("source state %s is not wiped", p)
		}
	}
	if tars, _ := filepath.Glob(filepath.Join(src.FW.DataDir, fwmig.RetainedDir, fwwVM+"-*.tar")); len(tars) != 1 {
		t.Errorf("retained bundles %v, want one", tars)
	}
	if q := fwliveQuarantines(dst); len(q) != 0 {
		t.Errorf("%s quarantined %v in a move that verified", dst.Name, q)
	}
	if open := fwliveOpenConditions(t, src); len(open) != 0 {
		t.Errorf("firmware_migration conditions %v still open after the move", open)
	}
}

// fwliveSourceKept asserts the source still holds its firmware state byte for
// byte.
func fwliveSourceKept(t *testing.T, src *Node) {
	t.Helper()
	if b, _ := fwliveFile(fwlivePermall(src)); !bytes.Equal(b, fwwPermall) {
		t.Errorf("%s's permall %q, want its own, kept", src.Name, b)
	}
	if b, _ := fwliveFile(src.FW.NvramPath(fwwVM)); !bytes.Equal(b, fwwNvram) {
		t.Errorf("%s's NVRAM %q, want its own, kept", src.Name, b)
	}
}
