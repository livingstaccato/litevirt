package fencessh_test

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/metrics"
)

// TestProbeAll_ChecksEachPeerWithoutArmingIt: the probe proves the managed
// path to a peer that accepts it — against real sshd — and records why a
// peer without one has none, without ever powering anything off.
func TestProbeAll_ChecksEachPeerWithoutArmingIt(t *testing.T) {
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	z := w.node("node-z", "127.0.0.5")
	a.publish(true, false, "127.0.0.2", 22)
	x.publish(true, false, "127.0.0.3", 22)
	y.publish(false, false, "127.0.0.4", 22)
	z.hostRow("127.0.0.5", 22) // published nothing
	x.start(false)
	x.hostRow(x.ip, x.port)

	ag := a.agent(fencessh.ModeAuto)
	ag.ProbeAll(context.Background())
	got := ag.Probes()
	if p := got["node-x"]; !p.OK {
		t.Fatalf("probe of node-x = %+v, want ok", p)
	}
	if p := got["node-y"]; p.OK || !strings.Contains(p.Detail, "legacy path, pinned") {
		t.Fatalf("probe of node-y = %+v, want no managed path (pinned)", p)
	}
	if p := got["node-z"]; p.OK || !strings.Contains(p.Detail, "published no fence ssh row") {
		t.Fatalf("probe of node-z = %+v, want no managed path (no row)", p)
	}
	if x.poweredOff() {
		t.Fatal("a probe powered node-x off")
	}
	if v := testutil.ToFloat64(metrics.FenceSSHProbeGauge().WithLabelValues("node-x")); v != 1 {
		t.Fatalf("litevirt_fence_ssh_probe_ok{peer=node-x} = %v", v)
	}
	if v := testutil.ToFloat64(metrics.FenceSSHProbeGauge().WithLabelValues("node-y")); v != 0 {
		t.Fatalf("litevirt_fence_ssh_probe_ok{peer=node-y} = %v", v)
	}

	st, err := ag.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, p := range st {
		paths[p.Host] = p.Path + "/" + p.Row
	}
	want := map[string]string{"node-a": "self/verified", "node-x": "managed/verified", "node-y": "legacy-pinned/verified",
		"node-z": "legacy-unpinned/missing"}
	for h, wp := range want {
		if paths[h] != wp {
			t.Fatalf("status of %s = %q, want %q (all: %v)", h, paths[h], wp, paths)
		}
	}
}
