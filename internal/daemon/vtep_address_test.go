package daemon

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireHostAddress_VTEPIsTheAdvertiseAddress: the gRPC server and the
// reconciler take this host's VXLAN tunnel endpoint from the daemon's host
// address — advertise_address when set — not from the default route. On the
// lab every node's default-route source was the same NAT address, so every
// node registered the same VTEP and each one's flood entry pointed at itself.
func TestWireHostAddress_VTEPIsTheAdvertiseAddress(t *testing.T) {
	d := &Daemon{cfg: &Config{AdvertiseAddress: "10.77.0.11"}}
	db := corrosion.NewTestClientT(t)
	svc := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "node-1", DataDir: t.TempDir(), DB: db})
	rec := health.NewReconciler("node-1", t.TempDir(), db, nil)

	d.wireHostAddress(svc, rec)
	if got := svc.VTEPAddress(); got != "10.77.0.11" {
		t.Errorf("server VTEP = %q, want the advertise address 10.77.0.11", got)
	}
	if got := rec.VTEPAddress(); got != "10.77.0.11" {
		t.Errorf("reconciler VTEP = %q, want the advertise address 10.77.0.11", got)
	}
}
