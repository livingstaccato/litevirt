package daemon

import (
	"context"
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

// recProv is a NetworkProvisioner that records the VTEP each Provision gets
// and touches no host device.
type recProv struct{ local []string }

func (p *recProv) Provision(_ context.Context, _ *corrosion.Client, _ string, _ compose.NetworkDef, localIP, _ string) (string, error) {
	p.local = append(p.local, localIP)
	return "br-vni5177", nil
}
func (p *recProv) Deprovision(context.Context, *corrosion.Client, string, compose.NetworkDef, string) error {
	return nil
}
func (p *recProv) Provisioned(string, compose.NetworkDef) bool { return true }
func (p *recProv) RemoveUnusedBridge(string) (bool, error)     { return false, nil }
func (p *recProv) RetireDevice(context.Context, *corrosion.Client, string, compose.NetworkDef, string) error {
	return nil
}
func (p *recProv) ReleaseDeviceServices(string, compose.NetworkDef) {}
func (p *recProv) ServingGateway(string, compose.NetworkDef) bool   { return false }
func (p *recProv) WouldServeGateway(context.Context, *corrosion.Client, string, compose.NetworkDef, string) bool {
	return false
}
func (p *recProv) GuestPorts(string) ([]string, error) { return nil, nil }
func (p *recProv) SyncFDB(context.Context, *corrosion.Client, string, compose.NetworkDef, string) error {
	return nil
}

// TestNewServer_FirstNetworkPassHasTheHostAddress: the daemon's startup
// network pass (ReconcileNetworksOnce, run right after the server is built)
// resolves a vxlan network's tunnel endpoint from this host's address —
// advertise_address — and from the release token's durable latch. Wired
// after that pass, the pass would see neither: on the lab it provisioned with
// the default-route address every node shares, and that stuck until the next
// VM create.
func TestNewServer_FirstNetworkPassHasTheHostAddress(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	// The release token latched on an earlier run: its durable marker is on disk.
	if err := os.WriteFile(health.ActivationMarkerPath(dataDir, capabilities.ReleaseToken),
		capabilities.MarkerContent(capabilities.ReleaseToken), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := health.NewChecker("node-1", t.TempDir(), db)
	checker.SetActivationMarker(health.ActivationMarkerBase(dataDir))
	d := &Daemon{
		cfg:     &Config{HostName: "node-1", DataDir: dataDir, PKIDir: t.TempDir(), AdvertiseAddress: "10.77.0.11"},
		db:      db,
		checker: checker,
	}
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{
		Name: "vxd_vxdnet", Type: "vxlan", Config: `{"interface":"vxdnet","vni":5177}`,
	}); err != nil {
		t.Fatal(err)
	}

	// A test has no libvirt for grpcapi.NewServer; newServer builds the test
	// server instead and wires it exactly as Run's does.
	d.buildServer = func() *grpcapi.Server {
		return grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "node-1", DataDir: dataDir, DB: db})
	}
	svc := d.newServer()
	prov := &recProv{}
	svc.SetNetworkProvisioner(prov)
	type call struct {
		addr     string
		switched bool
	}
	var calls []call
	svc.SetVTEPResolver(func(_ string, _ compose.NetworkDef, hostAddress string, switched bool) (string, string, error) {
		calls = append(calls, call{hostAddress, switched})
		if !switched {
			return "10.0.2.15", "ens3", nil
		}
		return hostAddress, "net1", nil
	})
	if err := svc.ReconcileNetworksOnce(ctx); err != nil {
		t.Fatalf("ReconcileNetworksOnce: %v", err)
	}
	if len(calls) != 1 || calls[0] != (call{"10.77.0.11", true}) {
		t.Fatalf("the first network pass resolved the VTEP from %+v, want [{10.77.0.11 true}]", calls)
	}
	if len(prov.local) != 1 || prov.local[0] != "10.77.0.11" {
		t.Fatalf("the first network pass provisioned with VTEP %q, want [10.77.0.11]", prov.local)
	}
}
