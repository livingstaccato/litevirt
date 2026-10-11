// Fleet scenario for a live migration of a VM with a ceph (rbd) disk: the
// target must hold the libvirt ceph secret the incoming domain names before
// libvirt is asked, whatever libvirtd on the target lost, and whatever path
// the target keeps its keyring at — and must refuse, with the reason, when its
// keyring holds a different key than the source's.

package fleet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// cephKeyring writes client.litevirt's keyring under dir and returns its path.
func cephKeyring(t *testing.T, dir string, key []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "litevirt.keyring")
	if err := os.WriteFile(p, []byte("[client.litevirt]\n\tkey = "+base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// cephMigrationCluster: two nodes, each with ceph pool "ceph" whose keyring is
// at a DIFFERENT path, and a running VM on the source with one rbd disk.
func cephMigrationCluster(t *testing.T, dstKey []byte) (c *Cluster, src, dst *Node, key []byte) {
	t.Helper()
	t.Cleanup(storage.OverrideCephRunnerForTest(func(context.Context, string, ...string) ([]byte, error) { return nil, nil }))
	c = New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst = c.Nodes[0], c.Nodes[1]
	key = []byte("the-restricted-client-key-28b")
	if dstKey == nil {
		dstKey = key
	}
	ctx := context.Background()
	for _, n := range []struct {
		node *Node
		key  []byte
	}{{src, key}, {dst, dstKey}} {
		keyring := cephKeyring(t, filepath.Join(c.tmpRoot, n.node.Name, "ceph"), n.key)
		opts := map[string]string{"id": "litevirt", "keyring": keyring}
		n.node.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"ceph": {Driver: "ceph", Source: "lv", Options: opts}})
		if err := corrosion.UpsertStoragePool(ctx, src.DB, corrosion.StoragePoolRecord{
			HostName: n.node.Name, Name: "ceph", Driver: "ceph", Source: "lv", Options: opts, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Each host records its key's fingerprint on its row.
	src.Server.ReconcileCephSecrets(ctx)
	dst.Server.ReconcileCephSecrets(ctx)

	srcKeyring := filepath.Join(c.tmpRoot, src.Name, "ceph", "litevirt.keyring")
	spec, err := json.Marshal(&pb.VMSpec{Name: "cv", Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "cv", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "cv", DiskName: "data", HostName: src.Name, SizeBytes: 1 << 30,
		Path:        "rbd:lv/cv-data:id=litevirt:keyring=" + srcKeyring + ":lvpool=ceph",
		StorageType: "ceph", StorageVolume: "ceph", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	src.Virt.SetState("cv", "running")
	return c, src, dst, key
}

// I1 + I2. The target lost its secrets (a libvirtd restart) and keeps its
// keyring elsewhere than the source: the migration still lands, because the
// source always prepares the target (EnsureDisks) for a VM with an rbd disk,
// and the target defines the pool's secret — the UUID the domain names, which
// is the pool's, not the keyring path's — from its own keyring.
//
// Mutation: skip EnsureDisks when there are no stubs, TLS or ISO (the old
// early return) — the target never defines the secret and the test goes red.
func TestFleet_LiveMigrationDefinesTheCephSecretOnTheTarget(t *testing.T) {
	c, src, dst, key := cephMigrationCluster(t, nil)
	dst.Virt.DropSecrets()
	if err := migrateAt(t, c, src, "cv", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	client, val, ok := dst.Virt.CephSecret(lv.CephSecretUUID("ceph", "litevirt"))
	if !ok || client != "litevirt" || !bytes.Equal(val, key) {
		t.Fatalf("target secret: ok=%v client=%q value=%q; want client.litevirt's key", ok, client, val)
	}
	// N5: the source hands libvirt the rbd disk's locator, so the destination
	// definition carries the pool's current monitors.
	if note := migrateNote(t, src); !strings.Contains(note, " rbd=lv/cv-data") {
		t.Fatalf("libvirt migration %q names no rbd disk to re-resolve", note)
	}
}

// I2. A target whose keyring holds another key refuses before libvirt is
// asked, naming the keyring, and the VM stays on the source.
//
// Mutation: drop refuseCephKeyUnlikeSource — the migration reaches libvirt
// and the test goes red.
func TestFleet_LiveMigrationRefusesATargetWithAnotherKey(t *testing.T) {
	c, src, dst, _ := cephMigrationCluster(t, []byte("a-different-key-for-the-cli"))
	err := migrateAt(t, c, src, "cv", dst.Name)
	if err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("migrate onto a host with another key: %v, want a refusal naming the keyring", err)
	}
	for _, e := range src.Virt.EventLog() {
		if e.Op == "migrate" {
			t.Fatalf("libvirt was asked to migrate: %+v", e)
		}
	}
}
