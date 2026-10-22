package fleet

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// installedFenceSSHHost reports an install the script completed, without
// touching any sshd.
type installedFenceSSHHost struct{ name, addr string }

func (h installedFenceSSHHost) Name() string    { return h.name }
func (h installedFenceSSHHost) Address() string { return h.addr }
func (h installedFenceSSHHost) RunScript(context.Context, []string, string) ([]byte, error) {
	return []byte("fence ssh: /etc/ssh/sshd_config.d/60-litevirt-fence.conf installed\nlv-fence-ssh-result: " +
		fencessh.ResultInstalled + "\n"), nil
}

// TestFleet_FenceSSH_InstallConfirmsOnlyByEachHostsOwnRow: `lv host
// install-fence-ssh` confirms a host only by that host's own view of its own
// row, collected over real RPCs from the host the CLI asked: node-1's sshd
// does not accept the managed key, so a run naming it fails and names it, and
// a run naming node-0 and node-2 (node-2 answered only through the fan-out)
// succeeds.
//
// Mutation: read the status without fan_out — node-2's own view is missing,
// and the second run fails, red.
func TestFleet_FenceSSH_InstallConfirmsOnlyByEachHostsOwnRow(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleetWith(t, 3, 2623, func(name string) bool { return name != "node-1" },
		func(string) string { return fencessh.ModeAuto })
	for _, n := range c.Nodes {
		n.Server.SetFenceSSH(fs[n.Name].agent)
	}
	syncAll(t, fs["node-0"], fs["node-1"], fs["node-2"])

	all := map[string]string{}
	host := map[string]cli.FenceSSHHost{}
	for _, n := range c.Nodes {
		all[n.Name] = fs[n.Name].ip
		host[n.Name] = installedFenceSSHHost{name: n.Name, addr: fs[n.Name].ip}
	}
	opt := func(out *bytes.Buffer) cli.FenceSSHOptions {
		return cli.FenceSSHOptions{Out: out, Wait: time.Millisecond, FreshAfter: time.Nanosecond}
	}
	client := c.SelfClient(c.Nodes[0])

	var out bytes.Buffer
	err := cli.InstallFenceSSH(ctx, client, []cli.FenceSSHHost{host["node-0"], host["node-1"]}, all, opt(&out))
	if err == nil || !strings.Contains(err.Error(), "node-1") || strings.Contains(err.Error(), "node-0") {
		t.Fatalf("node-1 does not accept: err %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "not accepting") {
		t.Fatalf("node-1's reason is not shown:\n%s", out.String())
	}

	out.Reset()
	if err := cli.InstallFenceSSH(ctx, client, []cli.FenceSSHHost{host["node-0"], host["node-2"]}, all, opt(&out)); err != nil {
		t.Fatalf("node-0 and node-2 accept: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Every host accepts") {
		t.Fatalf("output:\n%s", out.String())
	}
}
