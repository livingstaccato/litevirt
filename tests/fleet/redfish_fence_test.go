// Fleet scenarios for the redfish fence strategy: its settings are the release
// feature redfish_fence and travel on the sensitive lane, and a coordinator on
// any node fences a 'redfish' host through its BMC — over real HTTPS, against
// a fake Redfish service — with a verified fence its successor can resume from
// or renew.
package fleet

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// fleetBMC is a minimal Redfish service over real TLS with basic auth: one
// ComputerSystem whose PowerState goes Off on a ForceOff.
type fleetBMC struct {
	srv  *httptest.Server
	mu   sync.Mutex
	on   bool
	offs int
}

func newFleetBMC(t *testing.T) *fleetBMC {
	t.Helper()
	b := &fleetBMC{on: true}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); r.URL.Path != "/redfish/v1/" && (!ok || u != "admin" || p != "bmc-pass") {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		switch {
		case r.URL.Path == "/redfish/v1/":
			_ = enc.Encode(map[string]any{"Systems": map[string]string{"@odata.id": "/redfish/v1/Systems"}})
		case r.URL.Path == "/redfish/v1/Systems":
			_ = enc.Encode(map[string]any{"Members": []map[string]string{{"@odata.id": "/redfish/v1/Systems/1"}}})
		case r.URL.Path == "/redfish/v1/Systems/1":
			b.mu.Lock()
			st := "Off"
			if b.on {
				st = "On"
			}
			b.mu.Unlock()
			_ = enc.Encode(map[string]any{"Id": "1", "PowerState": st})
		case r.URL.Path == "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" && r.Method == http.MethodPost:
			var body struct{ ResetType string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			b.mu.Lock()
			if body.ResetType == "ForceOff" {
				b.on = false
				b.offs++
			}
			b.mu.Unlock()
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *fleetBMC) forceOffs() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.offs
}

func (b *fleetBMC) request(host string) *pb.ConfigureHostRequest {
	return &pb.ConfigureHostRequest{
		Name: host, FenceStrategy: "redfish", RedfishEndpoint: b.srv.URL,
		RedfishUser: "admin", RedfishPass: "bmc-pass", RedfishAuth: "basic",
		RedfishCaPem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.srv.Certificate().Raw})),
	}
}

// grantingGate is a release-feature gate that grants every feature at once,
// for a scenario whose subject is not the gate.
type grantingGate struct{ t testing.TB }

func (g grantingGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (grantingGate) FeatureAvailable(capabilities.Feature) bool { return true }

// TestFleet_RedfishFence_ReleaseFeatureGate: while a host is still on the
// previous build (modelled as one advertising nothing), a 'redfish' fence
// strategy is refused and nothing is written anywhere — a previous-release
// node would fence the host as best-effort SSH. Once every host runs this
// build, the configuration through one node records the use and reaches every
// replica, password included, on the sensitive lane only.
func TestFleet_RedfishFence_ReleaseFeatureGate(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1011)
	a, target, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	b := newFleetBMC(t)
	feature := string(capabilities.FeatureRedfishFence)

	old.Server.SetWALQuarantined(func() bool { return true })
	_, err := c.SelfClient(a).ConfigureHost(ctx, b.request(target.Name))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "redfish_fence needs") {
		t.Fatalf("redfish config with a host on the previous build: %v, want the release refusal", err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Fatalf("%s: %s recorded as used by a refused request", n.Name, feature)
		}
		if h, _ := corrosion.GetHost(ctx, n.DB, target.Name); h == nil || h.FenceStrategy == "redfish" || h.Redfish.Configured() {
			t.Fatalf("%s holds a refused redfish config: %+v", n.Name, h)
		}
	}

	old.Server.SetWALQuarantined(func() bool { return false })
	eventually(t, 30*time.Second, "redfish config once every host runs this build", func() bool {
		_, err := c.SelfClient(a).ConfigureHost(ctx, b.request(target.Name))
		return err == nil
	})
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, "redfish config on "+n.Name, func() bool {
			h, err := corrosion.GetHost(ctx, n.DB, target.Name)
			return err == nil && h != nil && h.FenceStrategy == "redfish" &&
				h.Redfish.Endpoint == b.srv.URL && h.Redfish.Pass == "bmc-pass"
		})
		if !featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Errorf("%s holds the redfish config without the use record", n.Name)
		}
		rows, err := n.DB.Query(ctx, `SELECT * FROM hosts WHERE name = ?`, target.Name)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: read hosts: %v", n.Name, err)
		}
		for _, col := range rows[0].Columns {
			if strings.Contains(rows[0].String(col), "bmc-pass") {
				t.Errorf("%s: hosts.%s carries the Redfish password", n.Name, col)
			}
		}
	}
}

// TestFleet_RedfishFence_SuccessorRenewsThroughTheBMC: a leader x fences the
// dead owner d through its BMC — a real Redfish fence, from the settings that
// replicated to x — and dies before it recovers anything. The fence is
// verified, so it records d 'fenced', the same proof as an IPMI power-off. Seven
// minutes later its successor a renews it with the recorded method, through the
// same BMC (a second ForceOff, as ipmi always sends its power-off, then a read
// of Off), and recovers the VM exactly once on that fresh fence.
//
// Mutation: classify redfish as unverified in fence.Assurance (x's fence
// records 'offline' and is never renewed: the fixture and wantRefence go red),
// or drop the Redfish settings from the coordinator's fence config (x's fence
// fails: the fixture goes red).
func TestFleet_RedfishFence_SuccessorRenewsThroughTheBMC(t *testing.T) {
	ctx := context.Background()
	vm := "vm-redfish-renew"
	c, a, b, cc, x, d := crashFleet(t, 1012, vm)
	voters := []*Node{a, b, cc}
	bmc := newFleetBMC(t)

	// d's fence settings, through ConfigureHost on a. The release gate here
	// grants outright; the gate itself is
	// TestFleet_RedfishFence_ReleaseFeatureGate's subject.
	a.Server.SetReleaseFeatureGate(grantingGate{t})
	if _, err := c.SelfClient(a).ConfigureHost(ctx, bmc.request(d.Name)); err != nil {
		t.Fatalf("configure %s's BMC: %v", d.Name, err)
	}
	for _, n := range []*Node{a, b, cc, x} {
		n := n
		eventually(t, 20*time.Second, d.Name+"'s redfish settings on "+n.Name, func() bool {
			h, err := corrosion.GetHost(ctx, n.DB, d.Name)
			return err == nil && h != nil && h.FenceStrategy == "redfish" && h.Redfish.Pass == "bmc-pass"
		})
	}

	ledger := watchClaims(t, c)
	settled := &fenceSettled{voters: voters, host: d.Name, state: "fenced"}
	c.SetClaimScript(dieAtFirstClaim(c, x, settled))
	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	var refenced atomic.Int32
	cs.ByNode[x.Name].Gate = quorateGate{}
	cs.ByNode[x.Name].SetFencer(fence.Execute)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.ByNode[a.Name].SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		refenced.Add(1)
		if h.FenceStrategy != "redfish" {
			t.Errorf("a re-fenced %s with strategy %q, not the recorded redfish", h.Name, h.FenceStrategy)
		}
		return fence.Execute(ctx, h)
	})

	cs.Tick(ctx, x)
	c.Crash(x)
	if !settled.ok {
		t.Fatalf("x's redfish fence of %s never settled 'fenced' on every voter: %v", d.Name, fencesOf(t, a, d.Name))
	}
	if n := bmc.forceOffs(); n != 1 {
		t.Fatalf("the BMC took %d ForceOff(s) from x's fence, want 1", n)
	}
	xFences := fencesOf(t, a, d.Name)
	if len(xFences) != 1 || xFences[0].Method != "redfish" || xFences[0].Result != "fenced" {
		t.Fatalf("x's fence = %+v, want one redfish/fenced row", xFences)
	}

	age := 7 * time.Minute
	clock.Advance(age)
	publish := func() {
		for _, n := range voters {
			PublishHealth(t, n, d.Name, streakSince(age+time.Minute), clock.Now())
		}
		c.WaitConverged(t, convergeTimeout, voters...)
	}
	publish()
	var decided *corrosion.VMRecord
	for i := 0; i < 6 && decided == nil; i++ {
		cs.Tick(ctx, a)
		if vmr := vmOn(t, a, vm); vmr.PendingActionID != "" && vmr.HostName != d.Name {
			decided = vmr
		}
		clock.Advance(contentionPoll)
		publish()
	}
	if n := refenced.Load(); n != 1 {
		t.Errorf("a fenced %s %d time(s), want 1 renewal", d.Name, n)
	}
	if n := bmc.forceOffs(); n != 2 {
		t.Errorf("the BMC took %d ForceOff(s) in all, want 2: the renewal sends its own", n)
	}
	if decided == nil {
		t.Fatalf("the successor never recovered %s from x's redfish fence: %+v", vm, vmOn(t, a, vm))
	}
	var fresh []string
	for _, f := range fencesOf(t, a, d.Name) {
		if f.Method == "redfish" && f.Result == "fenced" && f.ID != xFences[0].ID {
			fresh = append(fresh, f.ID)
		}
	}
	if len(fresh) != 1 {
		t.Errorf("fresh verified redfish fences of %s = %v, want exactly one", d.Name, fresh)
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
	out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
	if len(out.Running) == 1 && out.Running[0] != decided.HostName {
		t.Errorf("%s runs on %s, not on the decided destination %s", vm, out.Running[0], decided.HostName)
	}
}
