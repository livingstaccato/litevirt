package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// scriptedFenceSSHHost reports result as the install script's outcome
// without running it.
type scriptedFenceSSHHost struct {
	name, addr, result string
	ran                bool
}

func (h *scriptedFenceSSHHost) Name() string    { return h.name }
func (h *scriptedFenceSSHHost) Address() string { return h.addr }
func (h *scriptedFenceSSHHost) RunScript(context.Context, []string, string) ([]byte, error) {
	h.ran = true
	return []byte("fence ssh: something happened\n" + fenceSSHResultMarker + h.result + "\n"), nil
}

// fakeClock is the time InstallFenceSSH reads, moved on by its waits.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) pause(_ context.Context, d time.Duration) error {
	c.t = c.t.Add(d)
	return nil
}

// ownViewClient answers a fanned-out GetFenceSSHStatus with each host's own
// view of itself, as row(host, now) says.
type ownViewClient struct {
	pb.LiteVirtClient
	clock   *fakeClock
	hosts   []string
	row     func(host string, now time.Time) (accepting bool, lastErr string)
	fanOuts int
}

func (c *ownViewClient) GetFenceSSHStatus(_ context.Context, req *pb.FenceSSHStatusRequest, _ ...grpc.CallOption) (*pb.FenceSSHStatus, error) {
	if req.GetFanOut() {
		c.fanOuts++
	}
	st := &pb.FenceSSHStatus{}
	for _, h := range c.hosts {
		acc, lastErr := c.row(h, c.clock.now())
		st.Nodes = append(st.Nodes, &pb.FenceSSHNode{Host: h, Reachable: true, LastError: lastErr, Peers: []*pb.FenceSSHPeer{
			{Host: h, Row: fencessh.RowVerified, Accepting: acc, Address: "10.78.0.9", Path: fencessh.PathSelf}}})
		if !req.GetFanOut() {
			break
		}
	}
	return st, nil
}

func confirmOpts(out *bytes.Buffer, clk *fakeClock) FenceSSHOptions {
	return FenceSSHOptions{Out: out, Wait: 10 * time.Minute, FreshAfter: 2 * time.Minute, now: clk.now, pause: clk.pause}
}

// TestInstallFenceSSH_RefusedInstallFails: a host whose script refused (it
// returns 0 either way) fails the command, even while every row, stale from
// before the run, says the host accepts.
func TestInstallFenceSSH_RefusedInstallFails(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c := &ownViewClient{clock: clk, hosts: []string{"node-1", "node-2"},
		row: func(string, time.Time) (bool, string) { return true, "" }}
	h1 := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: fencessh.ResultInstalled}
	h2 := &scriptedFenceSSHHost{name: "node-2", addr: "10.78.0.2", result: fencessh.ResultRefused}
	var out bytes.Buffer
	err := InstallFenceSSH(context.Background(), c, []FenceSSHHost{h1, h2}, map[string]string{"node-1": h1.addr, "node-2": h2.addr}, confirmOpts(&out, clk))
	if err == nil || !strings.Contains(err.Error(), "node-2") || strings.Contains(out.String(), "Every host accepts") {
		t.Fatalf("a refused install: err %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), fenceSSHResultMarker) {
		t.Fatalf("the outcome marker is shown to the operator:\n%s", out.String())
	}
	for _, r := range []string{fencessh.ResultUnreloaded, "", "garbage"} {
		h := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: r}
		err := InstallFenceSSH(context.Background(), c, []FenceSSHHost{h}, map[string]string{"node-1": h.addr}, confirmOpts(&bytes.Buffer{}, clk))
		if err == nil {
			t.Fatalf("install outcome %q: no error", r)
		}
		if r == fencessh.ResultUnreloaded && !strings.Contains(err.Error(), "not reloaded") {
			t.Fatalf("an unreloaded sshd is not named: %v", err)
		}
	}
}

// TestInstallFenceSSH_RemoveFailsUnlessRemoved: --remove fails for a host
// whose sshd was not reloaded (it still reads the drop-in) or that refused.
func TestInstallFenceSSH_RemoveFailsUnlessRemoved(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c := &ownViewClient{clock: clk, hosts: []string{"node-1"}, row: func(string, time.Time) (bool, string) { return false, "" }}
	for r, wantErr := range map[string]bool{fencessh.ResultRemoved: false, fencessh.ResultUnreloaded: true, fencessh.ResultRefused: true, "": true} {
		h := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: r}
		opt := confirmOpts(&bytes.Buffer{}, clk)
		opt.Remove = true
		if err := InstallFenceSSH(context.Background(), c, []FenceSSHHost{h}, map[string]string{"node-1": h.addr}, opt); (err != nil) != wantErr {
			t.Fatalf("remove outcome %q: err %v, want error %v", r, err, wantErr)
		}
	}
}

// TestInstallFenceSSH_StaleRowIsNotSuccess: a row that still says accepting
// from before the run (right after a --remove, for about 80 s on the lab) is
// not success: only a row read once the host's agent has re-evaluated its
// sshd counts, and here that fresh row says no.
func TestInstallFenceSSH_StaleRowIsNotSuccess(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	start := clk.t
	c := &ownViewClient{clock: clk, hosts: []string{"node-1"}, row: func(_ string, now time.Time) (bool, string) {
		return now.Sub(start) < 2*time.Minute, "" // stale yes, then the fresh evaluation: no
	}}
	h := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: fencessh.ResultInstalled}
	var out bytes.Buffer
	opt := confirmOpts(&out, clk)
	opt.Wait = 4 * time.Minute
	err := InstallFenceSSH(context.Background(), c, []FenceSSHHost{h}, map[string]string{"node-1": h.addr}, opt)
	if err == nil || strings.Contains(out.String(), "Every host accepts") {
		t.Fatalf("a stale accepting row counted as success: err %v\n%s", err, out.String())
	}
}

// TestInstallFenceSSH_FreshAcceptingRowSucceeds: once the host's own row is
// fresh and says accepting, the command succeeds, and not before.
func TestInstallFenceSSH_FreshAcceptingRowSucceeds(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	start := clk.t
	var sawAt []time.Duration
	c := &ownViewClient{clock: clk, hosts: []string{"node-1", "node-2"}, row: func(_ string, now time.Time) (bool, string) {
		sawAt = append(sawAt, now.Sub(start))
		return true, ""
	}}
	h1 := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: fencessh.ResultInstalled}
	h2 := &scriptedFenceSSHHost{name: "node-2", addr: "10.78.0.2", result: fencessh.ResultInstalled}
	var out bytes.Buffer
	if err := InstallFenceSSH(context.Background(), c, []FenceSSHHost{h1, h2}, map[string]string{"node-1": h1.addr, "node-2": h2.addr}, confirmOpts(&out, clk)); err != nil {
		t.Fatalf("InstallFenceSSH: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Every host accepts") || c.fanOuts == 0 {
		t.Fatalf("fan-outs %d, output:\n%s", c.fanOuts, out.String())
	}
	if d := clk.t.Sub(start); d < 2*time.Minute {
		t.Fatalf("confirmed %s after the install, before a row could be fresh", d)
	}
}

// TestInstallFenceSSH_AgentSyncErrorIsNotConfirmed: a host whose fence ssh
// agent's last sync failed may hold a row it never refreshed; it does not
// confirm, however fresh the read.
func TestInstallFenceSSH_AgentSyncErrorIsNotConfirmed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c := &ownViewClient{clock: clk, hosts: []string{"node-1"}, row: func(string, time.Time) (bool, string) {
		return true, "read the cluster CA: no such file"
	}}
	h := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: fencessh.ResultInstalled}
	var out bytes.Buffer
	if err := InstallFenceSSH(context.Background(), c, []FenceSSHHost{h}, map[string]string{"node-1": h.addr}, confirmOpts(&out, clk)); err == nil {
		t.Fatalf("a host whose agent cannot sync confirmed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "read the cluster CA") {
		t.Fatalf("the sync error is not shown:\n%s", out.String())
	}
}

// TestInstallFenceSSH_WaitShorterThanFreshnessRefusesUpFront: a --wait no row
// could be fresh within refuses before any host is touched.
func TestInstallFenceSSH_WaitShorterThanFreshnessRefusesUpFront(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	h := &scriptedFenceSSHHost{name: "node-1", addr: "10.78.0.1", result: fencessh.ResultInstalled}
	opt := confirmOpts(&bytes.Buffer{}, clk)
	opt.Wait = time.Minute
	err := InstallFenceSSH(context.Background(), &ownViewClient{clock: clk}, []FenceSSHHost{h}, map[string]string{"node-1": h.addr}, opt)
	if err == nil || h.ran {
		t.Fatalf("--wait 1m against a 2m freshness: err %v, host touched %v", err, h.ran)
	}
}
