// Fleet scenario: an `lv host add` that the cluster refuses leaves the machine
// it was pointed at untouched.
//
// On the kvm003-f3 lab (lab-eqts-test26, F8/A8), `lv host add` of a name that
// was still active pushed host.crt and host.key to the machine and only then
// asked AdmitHost, which refused. The machine was the live host under that
// name: its daemon serves its identity from disk, so it was held as
// superseded and cut off from its peers until it was re-added.
package fleet

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/pki"
)

// operatorPKICopy points this process's `lv` at a pki directory holding the
// cluster CA, copied from n: an operator machine.
func operatorPKICopy(t *testing.T, n *Node) string {
	t.Helper()
	dir := t.TempDir()
	op := filepath.Join(dir, "pki")
	if err := os.MkdirAll(op, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "ca.key"} {
		if err := copyFile(filepath.Join(n.PKIDir, f), filepath.Join(op, f)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LV_CONFIG_DIR", dir)
	return op
}

func readFiles(t *testing.T, dir string, names ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		out[n] = b
	}
	return out
}

func TestFleet_HostAdd_ARefusedAddLeavesTheMachineAlone(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 4108})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)
	op := operatorPKICopy(t, a)
	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := os.WriteFile(bin, []byte("build"), 0o755); err != nil {
		t.Fatal(err)
	}
	identity := []string{"host.crt", "host.key", "ca.crt"}
	serialOf := func() map[string]string {
		got := map[string]string{}
		for _, n := range c.Nodes {
			got[n.Name] = hostsRowOf(t, n, b.Name)["cert_serial"]
		}
		return got
	}
	rowsBefore := serialOf()

	// The live member b, added by mistake under a new name: refused before
	// anything is asked or uploaded, by the certificate it serves (another
	// address) or by its address (I3: a member whose served serial is not
	// the recorded one is still caught).
	for _, tc := range []struct{ name, addr, want string }{
		{"by its certificate", "127.0.0.2", "serves " + b.Name + "'s current certificate"},
		{"by its address", b.Address, "live member at that address"},
	} {
		t.Run("the live member "+tc.name, func(t *testing.T) {
			before := readFiles(t, b.PKIDir, identity...)
			target := &cli.LocalAddTarget{Root: t.TempDir(), PKIDir: b.PKIDir, Binary: bin}
			err := cli.HostAddOn(ctx, c.SelfClient(a), target, "node-new", tc.addr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("add of the live %s as node-new = %v, want %q", b.Name, err, tc.want)
			}
			if len(target.Events) != 0 {
				t.Errorf("a refused add reached %s: %v", b.Name, target.Events)
			}
			for n, want := range before {
				if got := readFiles(t, b.PKIDir, n)[n]; !bytes.Equal(got, want) {
					t.Errorf("%s's %s was replaced", b.Name, n)
				}
			}
		})
	}

	// Another machine, holding an identity of its own, added under b's live
	// name: the daemon refuses the admission, and the machine keeps its key.
	t.Run("an active name", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "pki")
		if err := os.MkdirAll(other, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateHostCert(filepath.Join(op, "ca.crt"), filepath.Join(op, "ca.key"),
			filepath.Join(other, "host.crt"), filepath.Join(other, "host.key"), "spare", net.IPv4(127, 0, 0, 1)); err != nil {
			t.Fatal(err)
		}
		before := readFiles(t, other, "host.crt", "host.key")
		target := &cli.LocalAddTarget{Root: t.TempDir(), PKIDir: other, Binary: bin}
		err := cli.HostAddOn(ctx, c.SelfClient(a), target, b.Name, "127.0.0.3")
		if err == nil || !strings.Contains(err.Error(), "already active") || !strings.Contains(err.Error(), "nothing was installed") {
			t.Fatalf("add under the active name %s = %v, want the daemon's refusal", b.Name, err)
		}
		// It uploaded to staged paths, and removed them on the refusal.
		for _, e := range target.Events {
			staged := strings.HasPrefix(e, "write ") && strings.Contains(filepath.Base(e), ".add-")
			if !staged && e != "sh unstage" && e != "sh config" && e != "sh records" && e != "sh mkdir" &&
				e != "sh existing-state" && e != "sh existing-daemon" {
				t.Errorf("a refused add changed the machine: %q", e)
			}
		}
		if m, _ := filepath.Glob(filepath.Join(other, ".*.add*")); len(m) != 0 {
			t.Errorf("staged files left on the machine: %v", m)
		}
		for n, want := range before {
			if got := readFiles(t, other, n)[n]; !bytes.Equal(got, want) {
				t.Errorf("the machine's %s was replaced", n)
			}
		}
		if _, err := os.Stat(filepath.Join(op, b.Name+".crt")); !os.IsNotExist(err) {
			t.Errorf("a refused add left a minted %s.crt with the operator (stat: %v)", b.Name, err)
		}
	})

	// b stays the cluster's admission for its name everywhere, and a member.
	c.WaitConverged(t, convergeTimeout)
	if got := serialOf(); !mapsEqual(got, rowsBefore) {
		t.Errorf("%s's recorded serial changed: %v, was %v", b.Name, got, rowsBefore)
	}
	served, err := pki.CertSerial(filepath.Join(b.PKIDir, "host.crt"))
	if err != nil || !strings.EqualFold(served, rowsBefore[a.Name]) {
		t.Errorf("%s serves %s (%v), the cluster records %s", b.Name, served, err, rowsBefore[a.Name])
	}
}

func mapsEqual(x, y map[string]string) bool {
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}

// fleetAdmittedPort gives n's admitted row its real gRPC port, as n's boot
// records it, through a replicated write on on[0] stamped by its HLC, once
// the admission (serial) has reached every node in on; then it waits until
// each of them holds the port. The write carries a newer stamp than the
// admission, so no late copy of the admission can put 7443 back.
// AdmitHost records 7443, the port every real host serves on; fleet nodes
// share 127.0.0.1 and differ by port, so a second admission before the first
// node boots would hold the same address and port, which AdmitHost refuses
// (one machine, one name).
func fleetAdmittedPort(t *testing.T, n *Node, serial string, on ...*Node) {
	t.Helper()
	ctx := context.Background()
	for _, o := range on {
		eventually(t, convergeTimeout, o.Name+" to hold "+n.Name+"'s admission", func() bool {
			r, err := o.DB.Query(ctx, `SELECT cert_serial FROM hosts WHERE name = ?`, n.Name)
			return err == nil && len(r) == 1 && strings.EqualFold(r[0].String("cert_serial"), serial)
		})
	}
	via := on[0]
	// The statement the daemon's own-endpoint write uses (a registered shape).
	if err := via.DB.Execute(ctx, `UPDATE hosts SET address = ?, grpc_port = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		n.Address, n.Port, via.DB.NowTS(), n.Name); err != nil {
		t.Fatalf("record %s's fleet port on %s: %v", n.Name, via.Name, err)
	}
	for _, o := range on {
		eventually(t, convergeTimeout, o.Name+" to hold "+n.Name+"'s port", func() bool {
			r, err := o.DB.Query(ctx, `SELECT grpc_port FROM hosts WHERE name = ?`, n.Name)
			return err == nil && len(r) == 1 && r[0].Int64("grpc_port") == int64(n.Port)
		})
	}
}
