package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// midStream runs fn once, after the handler has received `after` messages.
type midStream struct {
	grpc.ServerStream
	after int
	n     int
	once  sync.Once
	fn    func()
}

func (m *midStream) RecvMsg(msg any) error {
	err := m.ServerStream.RecvMsg(msg)
	if err == nil {
		m.n++
		if m.n == m.after {
			m.once.Do(m.fn)
		}
	}
	return err
}

// TestFleet_RenewalMidColdMigrationLetsItFinish is re-review 3's I1 through
// the product path. A stopped VM with two host-local disks is migrated
// --cold from node-0 to node-1. While node-1 is receiving the FIRST disk,
// `lv host renew-cert node-0` runs to the end — node-0 generates its key,
// adopts the successor, the cluster records it, and the replaced
// certificate is REVOKED at once (--revoke-old; the default path revokes at
// once too unless a hold applies) — the CRL lands on both nodes, and both
// nodes' connection trackers sweep.
//
// Two connections were made with the replaced certificate: node-0's dial to
// node-1 carrying the disk stream (node-0's client certificate), and the
// operator's MigrateVM stream into node-0 (node-0 served it). Both are
// renewals' revocations, not emergencies, so both drain rather than being
// cut: the disk stream finishes, the MigrateVM stream keeps reporting, the
// second disk goes over a fresh connection with the renewed certificate, and
// the VM arrives with both disks' bytes.
//
// Mutations: make Server.revokedByRenewal report false — node-1's sweep cuts
// the disk stream at once and the migration fails; make
// servedRevokedByRenewal report false — node-0's sweep cuts the operator's
// MigrateVM stream; reuse one connection for every disk
// (copyColdDisksToTarget) — the second disk's stream is refused on the
// draining connection.
func TestFleet_RenewalMidColdMigrationLetsItFinish(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true, ConnTracking: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range []*Node{src, dst} {
		n.Server.SetHostDiskRootForTest(filepath.Join(c.tmpRoot, "fs-"+n.Name))
	}
	file := func(n *Node, path string) string { return filepath.Join(c.tmpRoot, "fs-"+n.Name, path) }
	disks := map[string]string{
		"root": filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "os1-root.raw"),
		"data": filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "os1-data.raw"),
	}
	payload := map[string][]byte{}
	for name, path := range disks {
		b := make([]byte, 6<<20+777)
		for i := range b {
			b[i] = byte(i*13 + len(name))
		}
		payload[name] = b
		if err := os.MkdirAll(filepath.Dir(file(src, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file(src, path), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "os1", HostName: src.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "os1", DiskName: "root", HostName: src.Name, Path: disks["root"], SizeBytes: int64(len(payload["root"])), StorageType: "local", TargetDev: "vda"},
		{VMName: "os1", DiskName: "data", HostName: src.Name, Path: disks["data"], SizeBytes: int64(len(payload["data"])), StorageType: "local", TargetDev: "vdb"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>os1</name><uuid>11111111-2222-4333-8444-555555555556</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + disks["root"] + `'/><target dev='vda'/></disk>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + disks["data"] + `'/><target dev='vdb'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain: %v", err)
	}

	withOperatorPKI(t, dst)
	stopWatches := runCertWatches(c)
	defer stopWatches()
	var renewErr error
	renewed := false
	renewMid := func() {
		renewErr = renewRevokeAndSweep(ctx, t, c, src, dst)
		renewed = renewErr == nil
	}
	dst.HookStream("ReceiveMigrationDisk", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		// The header, then the first data frame: the copy is under way.
		return h(srv, &midStream{ServerStream: ss, after: 2, fn: renewMid})
	})

	st, err := c.SelfClient(src).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		t.Fatal(err)
	}
	var migErr error
	for {
		if _, rerr := st.Recv(); rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				migErr = rerr
			}
			break
		}
	}
	if renewErr != nil {
		t.Fatalf("the renewal in the middle of the copy failed: %v", renewErr)
	}
	if !renewed {
		t.Fatal("fixture: the renewal never ran during the copy")
	}
	if migErr != nil {
		t.Fatalf("a cold migration in flight when node-0's replaced certificate was revoked failed: %v", migErr)
	}
	for name, path := range disks {
		got, err := os.ReadFile(file(dst, path))
		if err != nil {
			t.Fatalf("disk %s did not arrive on %s: %v", name, dst.Name, err)
		}
		if string(got) != string(payload[name]) {
			t.Fatalf("disk %s on %s differs from the source's", name, dst.Name)
		}
	}
	vm, err := corrosion.GetVM(ctx, dst.DB, "os1")
	if err != nil || vm == nil || vm.HostName != dst.Name {
		t.Fatalf("VM row after the migration: %+v %v, want it on %s", vm, err, dst.Name)
	}
}

// renewRevokeAndSweep runs `lv host renew-cert <target> --revoke-old` against
// via, lets via learn the successor the way target's replicator would (a push
// with the renewed certificate), waits for the replaced certificate to be
// revoked on every node, and sweeps every node's connection tracker. It is
// called from inside a server handler, so it returns errors rather than
// failing the test.
func renewRevokeAndSweep(ctx context.Context, t *testing.T, c *Cluster, target, via *Node) error {
	prevCert, err := pki.ServedHostCertificate(target.PKIDir)
	if err != nil {
		return err
	}
	prev := strings.ToLower(prevCert.SerialNumber.Text(16))
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := cli.RenewHostCertOn(rctx, c.SelfClient(via), &cli.LocalRemotePKI{Dir: target.PKIDir},
		cli.GRPCProbe(target.Address, target.Port), target.Name,
		cli.RenewCertOptions{Wait: 20 * time.Second, RevokeOld: true}); err != nil {
		return err
	}
	// target's replicator pushes with its renewed certificate (its serial was
	// just re-recorded): that handshake is how via learns the CA-signed
	// successor of the certificate it is streaming from.
	if err := pushAs(t, target.PKIDir, target.Name, via); err != nil {
		return err
	}
	deadline := time.Now().Add(convergeTimeout)
	for {
		done := true
		for _, n := range c.Nodes {
			// Each node installs the published CRL, as its 30 s loop does.
			_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
			done = done && revokedOn(n, prev)
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, n := range c.Nodes {
		n.SweepConnections(ctx)
	}
	return nil
}

// TestFleet_RenewalMidContainerMigrateLetsItLand is re-review 4's L1. A
// container cold migrate pushes the rootfs to the target (PushBackup) and
// then drives the target's RestoreContainer. While the target is receiving
// the push, node-0 (the source) renews with its replaced certificate revoked
// at once, and both trackers sweep. The push drains and finishes; the restore
// goes over a FRESH connection with the renewed certificate, and the
// container lands on the target with its bytes.
//
// Mutation: drive RestoreContainer on the push's connection (the pre-fix
// drivePeerRestore) — the restore is refused on the draining connection, and
// the container does not land.
func TestFleet_RenewalMidContainerMigrateLetsItLand(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true, ConnTracking: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-renew"
	createContainer(t, c, src, name)
	const payload = "rootfs-bytes-pushed-while-node-0-renewed"
	src.CT.Seed(name, payload)

	withOperatorPKI(t, dst)
	stopWatches := runCertWatches(c)
	defer stopWatches()
	var renewErr error
	renewed := false
	dst.HookStream("PushBackup", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		return h(srv, &midStream{ServerStream: ss, after: 1, fn: func() {
			renewErr = renewRevokeAndSweep(ctx, t, c, src, dst)
			renewed = renewErr == nil
		}})
	})
	migErr := runMigrate(t, c, src, dst, name, stagingRepo(t))
	if renewErr != nil {
		t.Fatalf("the renewal in the middle of the push failed: %v", renewErr)
	}
	if !renewed {
		t.Fatal("fixture: the renewal never ran during the push")
	}
	if migErr != nil {
		t.Fatalf("a container migrate whose push was in flight when node-0's replaced certificate was revoked failed: %v", migErr)
	}
	if got := dst.CT.Payload(name); got != payload {
		t.Fatalf("target rootfs payload = %q, want %q", got, payload)
	}
	if rec, err := corrosion.GetContainer(ctx, dst.DB, dst.Name, name); err != nil || rec == nil {
		t.Fatalf("target row after migrate: rec=%v err=%v", rec, err)
	}
}
