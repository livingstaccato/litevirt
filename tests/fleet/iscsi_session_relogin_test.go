// Fleet scenario for an iscsi pool's session after a host reboot (lab 2
// observation O-1): the host that lost its session logs back in, and while it
// cannot, every node sees the pool as degraded, with the reason, instead of
// active.

package fleet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// rebootedISCSIAdm is iscsiadm on a host after a reboot: the node record is
// there, no session is, and a login fails while failLogin is set.
type rebootedISCSIAdm struct {
	mu        sync.Mutex
	session   bool
	failLogin bool
	logins    int
}

func (f *rebootedISCSIAdm) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := strings.Join(args, " ")
	switch {
	case a == "-m session":
		if !f.session {
			return []byte("iscsiadm: No active sessions."), errors.New("exit status 21")
		}
		return []byte("tcp: [1] 10.9.9.9:3260,1 " + fleetLUNTarget + " (non-flash)\n"), nil
	case strings.HasSuffix(a, "--login"):
		f.logins++
		if f.failLogin {
			return []byte("iscsiadm: initiator reported error (8 - connection timed out)"), errors.New("exit status 8")
		}
		f.session = true
		return []byte("Login successful."), nil
	}
	return nil, nil
}

func (f *rebootedISCSIAdm) set(fail bool) {
	f.mu.Lock()
	f.failLogin = fail
	f.mu.Unlock()
}

func TestFleet_ISCSIPoolSessionMissingIsDegradedEverywhereUntilLoggedBackIn(t *testing.T) {
	adm := &rebootedISCSIAdm{failLogin: true}
	t.Cleanup(storage.OverrideISCSICommandForTest(adm.run))
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1012})
	owner, peer := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, owner.DB, corrosion.StoragePoolRecord{
		HostName: owner.Name, Name: "san", Driver: "iscsi", Source: fleetLUNTarget, State: "active",
		Options: map[string]string{"portal": "10.9.9.9:3260", "lun": "1"},
	}); err != nil {
		t.Fatal(err)
	}

	stateOnPeer := func() string {
		resp, err := c.SelfClient(peer).ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
		if err != nil {
			return ""
		}
		for _, p := range resp.Pools {
			if p.Host == owner.Name && p.Name == "san" {
				return p.State
			}
		}
		return ""
	}
	conditionOnPeer := func() (corrosion.HealthCondition, bool) {
		cond, ok, err := corrosion.GetHealthCondition(ctx, peer.DB, "iscsi_pool", "iscsi_session_missing", "host", "san@"+owner.Name)
		return cond, ok && err == nil
	}

	owner.Server.ReconcileISCSISessions(ctx)
	eventually(t, 20*time.Second, "the peer to see the pool degraded with the reason", func() bool {
		cond, ok := conditionOnPeer()
		return stateOnPeer() == "degraded" && ok && cond.Lifecycle != corrosion.ConditionResolved &&
			strings.Contains(cond.Evidence, "connection timed out")
	})

	adm.set(false)
	owner.Server.ReconcileISCSISessions(ctx)
	eventually(t, 20*time.Second, "the peer to see the pool active and the condition resolved", func() bool {
		cond, ok := conditionOnPeer()
		return stateOnPeer() == "active" && ok && cond.Lifecycle == corrosion.ConditionResolved
	})
	if adm.logins != 2 {
		t.Fatalf("%d logins, want 2 (one failed, one made)", adm.logins)
	}
}
