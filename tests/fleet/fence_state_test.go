// Fleet scenarios: one meaning of "fenced" (colonelpanik/litevirt#253). Once
// fence_state_v1 has latched, only a proof-grade fence records a host
// 'fenced'; an unverified (SSH) fence records it 'offline', and keeps every
// bit of the authority it had: a successor resumes the recovery from it, and
// the host is not put back in service behind the workloads that moved off it.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// fenceStateUnlatchedGate is quorateGate on a node where every token but
// fence_state_v1 has latched: the fleet is mid-roll, and some node that could
// take the lease next still resumes only from 'fenced'.
type fenceStateUnlatchedGate struct{ quorateGate }

func (fenceStateUnlatchedGate) Enforced(_ context.Context, tok string) bool {
	return tok != capabilities.FenceStateV1
}

// hostStateOn reads host's state in n's replica.
func hostStateOn(t *testing.T, n *Node, host string) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), n.DB, host)
	if err != nil || h == nil {
		t.Fatalf("%s: GetHost %s: %+v, %v", n.Name, host, h, err)
	}
	return h.State
}

// TestFleet_SSHFence_SuccessorResumesFromOffline: a leader SSH-fences d, which
// records it 'offline' (fence_state_v1 latched), and loses the lease before it
// moves anything. Its successor finishes the recovery from that record —
// without fencing d again, since an SSH power-off of a host that is already
// off fails — and d stays 'offline': nothing proved it off, so nothing records
// it 'fenced'.
//
// Mutation: recordedFence accepts only 'fenced' again — the successor never
// resumes and vm stays stranded on d.
func TestFleet_SSHFence_SuccessorResumesFromOffline(t *testing.T) {
	ctx := context.Background()
	vm := "vm-ssh-offline"
	c, a, b, cc, x, d := crashFleet(t, 2741, vm)
	voters := []*Node{a, b, cc}
	cs, clock, refenced := deadLeaderFence(t, c, voters, x, d, sshOff, sshOff)

	for _, n := range voters {
		if got := hostStateOn(t, n, d.Name); got != "offline" {
			t.Fatalf("%s records %s %q after an SSH fence, want 'offline'", n.Name, d.Name, got)
		}
	}
	if fs := fencesOf(t, a, d.Name); len(fs) != 1 || fs[0].Method != "ssh" || fs[0].Result != "fenced" {
		t.Fatalf("fencing_log for %s = %+v, want one ssh/fenced row", d.Name, fs)
	}

	clock.Advance(time.Minute)
	for _, n := range voters {
		PublishHealth(t, n, d.Name, streakSince(2*time.Minute), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)

	decided := tickUntilDecided(ctx, t, cs, a, d, vm, 6)
	if decided == nil {
		t.Fatalf("the successor never recovered %s from x's SSH fence recorded 'offline': %+v", vm, vmOn(t, a, vm))
	}
	if n := refenced.Load(); n != 0 {
		t.Errorf("the successor fenced %s %d time(s); an unverified fence is resumed, never re-fenced", d.Name, n)
	}
	if got := hostStateOn(t, a, d.Name); got != "offline" {
		t.Errorf("%s is %q after the resumed recovery, want 'offline': an SSH fence proves nothing", d.Name, got)
	}
}

// TestFleet_SSHFencedHostWhoseVMsMoved_StaysOffline: the successor above
// moved vm off d. Well past recentFenceWindow, d answers every voter again —
// the poweroff never landed, or the host came back without its daemon
// recording it. A healthy quorum does NOT put it back in service: its newest
// fence succeeded and its workloads moved, so only `lv host undrain` may, as
// for a host recorded 'fenced'.
//
// Mutation: drop the successful-fence rule for 'offline' from recoverHosts —
// the leader marks d 'active' once the window has passed.
func TestFleet_SSHFencedHostWhoseVMsMoved_StaysOffline(t *testing.T) {
	ctx := context.Background()
	vm := "vm-ssh-moved"
	c, a, b, cc, x, d := crashFleet(t, 2742, vm)
	voters := []*Node{a, b, cc}
	cs, clock, _ := deadLeaderFence(t, c, voters, x, d, sshOff, sshOff)

	clock.Advance(time.Minute)
	for _, n := range voters {
		PublishHealth(t, n, d.Name, streakSince(2*time.Minute), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	if decided := tickUntilDecided(ctx, t, cs, a, d, vm, 6); decided == nil {
		t.Fatalf("fixture: the successor never recovered %s: %+v", vm, vmOn(t, a, vm))
	}

	// d answers again, long after its fence.
	clock.Advance(10 * time.Minute)
	for i := 0; i < 3; i++ {
		for _, n := range voters {
			publishAnswered(t, n, d.Name, clock.Now())
		}
		c.WaitConverged(t, convergeTimeout, voters...)
		cs.Tick(ctx, a)
		clock.Advance(health.ProbeInterval)
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	if got := hostStateOn(t, a, d.Name); got != "offline" {
		t.Errorf("%s is %q after answering again; a host whose SSH fence moved its workloads "+
			"must stay 'offline' until `lv host undrain`", d.Name, got)
	}
}

// TestFleet_FenceStateUnlatched_SSHFenceStillRecordsFenced: mid-roll, with
// fence_state_v1 not latched, a node that may take the lease next resumes only
// from 'fenced'. So an SSH fence still records 'fenced', exactly as every
// earlier build does, and the successor resumes from it. Readers do not take
// that state as proof (corrosion.HostProvedOff): the row says ssh.
//
// Mutation: record 'offline' for an unverified fence whether or not the token
// has latched — x's fence never settles as 'fenced' and the fixture fails.
func TestFleet_FenceStateUnlatched_SSHFenceStillRecordsFenced(t *testing.T) {
	ctx := context.Background()
	vm := "vm-ssh-unlatched"
	c, a, b, cc, x, d := crashFleet(t, 2743, vm)
	voters := []*Node{a, b, cc}
	cs, clock, refenced := deadLeaderFenceUnder(t, c, voters, x, d, sshOff, sshOff, fenceStateUnlatchedGate{}, "fenced")

	if proved, err := corrosion.HostProvedOff(ctx, a.DB, d.Name); err != nil || proved {
		t.Errorf("HostProvedOff(%s) = %v, %v on an SSH fence recorded 'fenced'; the state is not proof", d.Name, proved, err)
	}

	clock.Advance(time.Minute)
	for _, n := range voters {
		PublishHealth(t, n, d.Name, streakSince(2*time.Minute), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	if decided := tickUntilDecided(ctx, t, cs, a, d, vm, 6); decided == nil {
		t.Fatalf("the successor never recovered %s from x's SSH fence: %+v", vm, vmOn(t, a, vm))
	}
	if n := refenced.Load(); n != 0 {
		t.Errorf("the successor fenced %s %d time(s); an unverified fence is never re-fenced", d.Name, n)
	}
}
