package fencessh_test

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// TestFence_WrongAddressIsRefused is the one-copy invariant. node-x's
// recorded address reaches node-y (a typo, a reused IP, a NAT'd lab), and
// node-y authorises the coordinator's key, as every lab node does with the
// hand-made shared key. A fence of node-x must NOT power node-y off and
// report node-x fenced: node-x is still running, and its VMs would get a
// second copy.
//
// On the base build every SSH fence is StrictHostKeyChecking=no, so node-y
// answers, powers ITSELF off, prints the marker, and the fence of node-x
// reports success. Here node-x has published its row, so the fence pins
// node-x's sshd key and node-y fails the pin before it authenticates anything
// — on the managed path and on the legacy path alike — and the fence reports
// failure.
func TestFence_WrongAddressIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		accepting bool
		path      string
	}{
		{"managed path", fencessh.ModeAuto, true, "path=managed"},
		{"legacy path, pinned", fencessh.ModeAuto, false, "path=legacy-pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			a := w.node("node-a", "127.0.0.2")
			x := w.node("node-x", "127.0.0.3")
			y := w.node("node-y", "127.0.0.4")
			a.publish(true, false, "127.0.0.2", 22)
			x.publish(tc.accepting, false, "127.0.0.3", 22)
			y.publish(tc.accepting, false, "127.0.0.4", 22)
			x.start(true)
			y.start(true)
			// node-x's recorded address now reaches node-y.
			x.hostRow(y.ip, y.port)

			res := a.fence(a.agent(tc.mode), "node-x")
			if res.Success {
				t.Fatalf("the fence of node-x reported success through node-y: %+v", res)
			}
			if y.poweredOff() {
				t.Fatal("node-y powered itself off for a fence of node-x")
			}
			if x.poweredOff() {
				t.Fatal("node-x is reported off, but nothing reached it")
			}
			if !strings.Contains(res.Detail, tc.path) || !strings.Contains(res.Detail, "Host key verification failed") {
				t.Fatalf("detail = %q, want %s and a host-key failure", res.Detail, tc.path)
			}
			if !res.WrongHost || res.Answered {
				t.Fatalf("result = %+v, want WrongHost (a real OpenSSH mismatch, at LogLevel=ERROR) and not Answered", res)
			}
		})
	}
}

// TestFence_ClonedHostKeyStillRefusedByTheForcedCommand: even a machine that
// presents node-x's own sshd key (a cloned image) and trusts the coordinator's
// managed key cannot be fenced in node-x's place: its forced command refuses
// a request naming another host, with exit 3 and no marker.
func TestFence_ClonedHostKeyStillRefusedByTheForcedCommand(t *testing.T) {
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	y.hkPath, y.hostKey = x.hkPath, x.hostKey // node-y is a clone of node-x's image
	a.publish(true, false, "127.0.0.2", 22)
	x.publish(true, false, "127.0.0.3", 22)
	y.publish(true, false, "127.0.0.4", 22)
	y.start(false)
	x.hostRow(y.ip, y.port)

	res := a.fence(a.agent(fencessh.ModeAuto), "node-x")
	if res.Success || y.poweredOff() {
		t.Fatalf("a clone of node-x was fenced in its place: %+v (node-y off: %v)", res, y.poweredOff())
	}
	if !strings.Contains(res.Detail, "exit status 3") || !strings.Contains(res.Detail, "path=managed") {
		t.Fatalf("detail = %q, want the forced command's refusal (exit 3) on the managed path", res.Detail)
	}
}

// TestFence_ManagedPowersOffTheNamedTarget: the managed path works end to end
// against real sshd — the pin, the key, the from= address (the client binds
// to the coordinator's certificate address), the forced command — and the
// marker classifies it as a fence.
func TestFence_ManagedPowersOffTheNamedTarget(t *testing.T) {
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	a.publish(true, false, "127.0.0.2", 22)
	x.publish(true, false, "127.0.0.3", 22)
	x.start(false) // no hand-made root key: only the managed path can work
	x.hostRow(x.ip, x.port)

	res := a.fence(a.agent(fencessh.ModeManaged), "node-x")
	if !res.Success || res.Method != "ssh" || !x.poweredOff() {
		t.Fatalf("managed fence = %+v, node-x off %v", res, x.poweredOff())
	}
	if !strings.Contains(res.Detail, "path=managed") {
		t.Fatalf("detail = %q, want path=managed", res.Detail)
	}
	// One ssh, with no configuration of root's in play.
	inv := w.sshInvocations()
	if len(inv) != 1 || !strings.Contains(inv[0], "-F /dev/null") || !strings.Contains(inv[0], "BindAddress=127.0.0.2") {
		t.Fatalf("ssh invocations = %q", inv)
	}
}

// TestFence_ManagedFailureIsNeverRetriedOnTheLegacyPath: node-x accepts the
// managed key, and its address reaches a machine where the hand-made legacy
// key (unpinned, as the base build ran it) would work. The managed fence
// fails, and only one ssh ran: nothing retried it down the legacy path.
func TestFence_ManagedFailureIsNeverRetriedOnTheLegacyPath(t *testing.T) {
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	a.publish(true, false, "127.0.0.2", 22)
	x.publish(true, false, "127.0.0.3", 22)
	y.publish(true, false, "127.0.0.4", 22)
	y.start(true)
	x.hostRow(y.ip, y.port) // reaches a machine that would accept the legacy key

	res := a.fence(a.agent(fencessh.ModeAuto), "node-x")
	if res.Success || y.poweredOff() {
		t.Fatalf("fence = %+v, node-y off %v", res, y.poweredOff())
	}
	if inv := w.sshInvocations(); len(inv) != 1 || !strings.Contains(inv[0], "-F /dev/null") {
		t.Fatalf("ssh ran %d times (%q); a managed failure must not be retried down the legacy path", len(inv), inv)
	}
}

// TestManagedKey_Containment: what node-a's fence key can do on node-x is
// power it off, from node-a's address, and nothing else.
func TestManagedKey_Containment(t *testing.T) {
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	a.publish(true, false, "127.0.0.2", 22)
	x.publish(true, false, "127.0.0.3", 22)
	x.start(false)
	x.hostRow(x.ip, x.port)
	ag := a.agent(fencessh.ModeManaged)
	sf := ag.FenceConfig(context.Background(), "node-x")
	if sf.Path != fence.SSHPathManaged {
		t.Fatalf("path = %+v", sf)
	}

	run := func(bind string, extra ...string) (string, error) {
		args := []string{"-F", "/dev/null", "-i", sf.IdentityFile, "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR",
			"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
			"-o", "BindAddress=" + bind, "-o", "ConnectTimeout=5", "-p", itoa(x.port)}
		args = append(args, extra...)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
		return string(out), err
	}
	target := w.user + "@" + x.ip

	t.Run("no shell", func(t *testing.T) {
		out, err := run(a.ip, target, "id")
		if err == nil || strings.Contains(out, "uid=") || !strings.Contains(out, "litevirt-fence: refused") {
			t.Fatalf("`id` with the fence key: %v %q", err, out)
		}
	})
	t.Run("no forwarding", func(t *testing.T) {
		// A remote forward is the server's to grant, so this asks sshd.
		out, err := run(a.ip, "-N", "-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:22", target)
		if err == nil || !strings.Contains(out, "remote port forwarding failed") {
			t.Fatalf("a remote forward with the fence key: %v %q", err, out)
		}
	})
	t.Run("not from another address", func(t *testing.T) {
		out, err := run("127.0.0.9", target, fencessh.PoweroffRequest("node-x"))
		if err == nil || x.poweredOff() || !strings.Contains(out, "Permission denied") {
			t.Fatalf("the fence key from 127.0.0.9: %v %q (off %v)", err, out, x.poweredOff())
		}
	})
	t.Run("another key", func(t *testing.T) {
		args := []string{"-F", "/dev/null", "-i", w.legacyKey, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "BindAddress=" + a.ip, "-p", itoa(x.port),
			target, fencessh.PoweroffRequest("node-x")}
		out, err := exec.Command("ssh", args...).CombinedOutput()
		if err == nil || x.poweredOff() {
			t.Fatalf("a key not in the file: %v %q", err, out)
		}
	})
	t.Run("check never arms", func(t *testing.T) {
		out, err := run(a.ip, target, fencessh.CheckRequest("node-x"))
		if err != nil || strings.TrimSpace(out) != fencessh.CheckOK || x.poweredOff() {
			t.Fatalf("check: %v %q (off %v)", err, out, x.poweredOff())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		probe := ag.FenceConfig(ctx, "node-x")
		probe.Request = fencessh.CheckRequest("node-x")
		if err := fence.ProbeSSH(ctx, fence.HostConfig{Name: "node-x", Address: x.ip, SSHPort: x.port, SSH: probe}, fencessh.CheckOK); err != nil {
			t.Fatalf("ProbeSSH: %v", err)
		}
		if x.poweredOff() {
			t.Fatal("a probe powered node-x off")
		}
	})
}

func itoa(n int) string { return strconv.Itoa(n) }
