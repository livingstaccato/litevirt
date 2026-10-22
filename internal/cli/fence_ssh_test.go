package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// localFenceSSHHost runs the install script with bash on this machine,
// against an sshd configuration of its own (FENCE_SSH_* overrides).
type localFenceSSHHost struct {
	name, addr string
	env        []string
	gotEnv     []string
}

func (h *localFenceSSHHost) Name() string    { return h.name }
func (h *localFenceSSHHost) Address() string { return h.addr }
func (h *localFenceSSHHost) RunScript(_ context.Context, env []string, script string) ([]byte, error) {
	h.gotEnv = env
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(append(os.Environ(), h.env...), env...)
	return cmd.CombinedOutput()
}

// statusClient answers a fanned-out GetFenceSSHStatus with each host's own
// view, every host accepting.
type statusClient struct {
	pb.LiteVirtClient
	calls int
	hosts []string
}

func (c *statusClient) GetFenceSSHStatus(context.Context, *pb.FenceSSHStatusRequest, ...grpc.CallOption) (*pb.FenceSSHStatus, error) {
	c.calls++
	st := &pb.FenceSSHStatus{}
	for _, h := range c.hosts {
		st.Nodes = append(st.Nodes, &pb.FenceSSHNode{Host: h, Reachable: true, Peers: []*pb.FenceSSHPeer{
			{Host: h, Row: fencessh.RowVerified, Accepting: true, Address: "10.77.0.9"}}})
	}
	return st, nil
}

// TestInstallFenceSSH_ProvisionsEveryHostForEveryPeer: each host's drop-in is
// evaluated for a fence from every other host's address, written and
// validated against a real sshd configuration; the command waits for every
// host to report accepting and says so.
func TestInstallFenceSSH_ProvisionsEveryHostForEveryPeer(t *testing.T) {
	sshd := "/usr/sbin/sshd"
	if _, err := os.Stat(sshd); err != nil {
		if os.Getenv("LITEVIRT_REQUIRE_SSHD") == "1" {
			t.Fatalf("LITEVIRT_REQUIRE_SSHD=1: no sshd at %s", sshd)
		}
		t.Skipf("no sshd at %s (set LITEVIRT_REQUIRE_SSHD=1 to fail instead)", sshd)
	}
	var hosts []FenceSSHHost
	var locals []*localFenceSSHHost
	all := map[string]string{}
	for i, name := range []string{"node-0", "node-1", "node-2"} {
		root := t.TempDir()
		ddir := filepath.Join(root, "sshd_config.d")
		os.MkdirAll(ddir, 0o755)
		hk := filepath.Join(root, "hk")
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hk).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
		cfg := filepath.Join(root, "sshd_config")
		os.WriteFile(cfg, []byte("HostKey "+hk+"\nPidFile none\nInclude "+ddir+"/*.conf\n"), 0o600)
		h := &localFenceSSHHost{name: name, addr: "10.77.0." + string(rune('1'+i)), env: []string{
			"FENCE_SSH_SSHD=" + sshd, "FENCE_SSH_SSHD_CONFIG=" + cfg, "FENCE_SSH_DROPIN_DIR=" + ddir,
			"FENCE_SSH_DIR=" + filepath.Join(root, "ssh"), "FENCE_SSH_RELOAD=true"}}
		hosts, locals = append(hosts, h), append(locals, h)
		all[name] = h.addr
	}
	var out bytes.Buffer
	c := &statusClient{hosts: []string{"node-0", "node-1", "node-2"}}
	if err := InstallFenceSSH(context.Background(), c, hosts, all, FenceSSHOptions{Out: &out, FreshAfter: time.Nanosecond}); err != nil {
		t.Fatalf("InstallFenceSSH: %v\n%s", err, out.String())
	}
	for _, h := range locals {
		var peers string
		for _, kv := range h.gotEnv {
			if strings.HasPrefix(kv, "FENCE_SSH_PEERS=") {
				peers = strings.TrimPrefix(kv, "FENCE_SSH_PEERS=")
			}
		}
		if strings.Contains(peers, h.addr) || len(strings.Fields(peers)) != 2 {
			t.Fatalf("%s evaluated for peers %q, want the two others", h.name, peers)
		}
		ddir := strings.TrimPrefix(h.env[2], "FENCE_SSH_DROPIN_DIR=")
		if _, err := os.Stat(filepath.Join(ddir, "60-litevirt-fence.conf")); err != nil {
			t.Fatalf("%s: no drop-in: %v\n%s", h.name, err, out.String())
		}
	}
	if !strings.Contains(out.String(), "Every host accepts the managed fence key") {
		t.Fatalf("output:\n%s", out.String())
	}
}
