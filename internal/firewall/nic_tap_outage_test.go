package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// outageDB is one running VM on host-a with a NIC bound to "web" (tcp/80).
func outageDB(t *testing.T) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg", Name: "web"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r", SGID: "sg",
		Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm-a", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "vm-a", NetworkName: "prod", MAC: "52:54:00:00:00:0a",
			SecurityGroups: []string{"web"}}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return db
}

const outageChain = "oifname vnet3 tcp dport 80 accept"

func upTaps() (map[string]map[string]string, error) {
	return map[string]map[string]string{"vm-a": {"52:54:00:00:00:0a": "vnet3"}}, nil
}

// libvirt's connection drops while the VM keeps running (a libvirtd restart).
// The VM still has its tap, so the pass must fail and the applied ruleset —
// with the VM's chain — must stay. Dropping the NIC from the plan instead
// removed every per-NIC chain on the host, and under the default accept
// policy every VM ran unfiltered until libvirt came back.
func TestReconcile_LibvirtOutageKeepsTheAppliedChains(t *testing.T) {
	ctx := context.Background()
	down := false
	opts := LoaderOptions{RunningTaps: func() (map[string]map[string]string, error) {
		if down {
			return nil, errors.New("list running domains: connection is shut down")
		}
		return upTaps()
	}}
	nft := &fakeNft{}
	r := NewReconciler(CorrosionPlanLoader(outageDB(t), "host-a", Plan{}, opts), NewApplier(nft), 0)
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if !strings.Contains(nft.applies[0], outageChain) {
		t.Fatalf("control: the first apply must carry vm-a's chain:\n%s", nft.applies[0])
	}
	down = true
	if err := r.Reconcile(ctx); err == nil {
		t.Error("a pass that could not ask libvirt must fail, not succeed with the VM NICs dropped")
	}
	if len(nft.applies) != 1 {
		t.Errorf("libvirt outage applied a new ruleset (%d applies); the last one must stay:\n%s",
			len(nft.applies), nft.applies[len(nft.applies)-1])
	}
	if r.LastError() == nil {
		t.Error("the failed pass must be visible in LastError (lv firewall show)")
	}
}

// A hung libvirtd: the call never returns. The pass must fail at the
// deadline, the next pass must fail at once instead of stacking another call
// behind the hung one, and the pass after libvirt answers must succeed.
func TestReconcile_HungLibvirtTimesOut(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	hung := true
	opts := LoaderOptions{TapTimeout: 50 * time.Millisecond, RunningTaps: func() (map[string]map[string]string, error) {
		if hung {
			<-release
			return nil, errors.New("late answer from a hung libvirtd")
		}
		return upTaps()
	}}
	nft := &fakeNft{}
	r := NewReconciler(CorrosionPlanLoader(outageDB(t), "host-a", Plan{}, opts), NewApplier(nft), 0)

	start := time.Now()
	err := r.Reconcile(ctx)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("hung libvirt: got %v, want a deadline error", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the pass took %s; the deadline did not hold", d)
	}
	if err := r.Reconcile(ctx); !errors.Is(err, errTapFetchOutstanding) {
		t.Errorf("a pass while the hung call is outstanding: got %v, want errTapFetchOutstanding", err)
	}
	if len(nft.applies) != 0 {
		t.Errorf("nothing may be applied while libvirt is hung, got %d applies", len(nft.applies))
	}

	hung = false
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := r.Reconcile(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, errTapFetchOutstanding) || time.Now().After(deadline) {
			t.Fatalf("after libvirt answered: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(nft.applies) != 1 || !strings.Contains(nft.applies[0], outageChain) {
		t.Errorf("once libvirt answers, vm-a's chain must be applied: %v", nft.applies)
	}
}
