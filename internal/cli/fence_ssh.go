package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/ssh"
)

// FenceSSHHost is one host `lv host install-fence-ssh` provisions.
type FenceSSHHost interface {
	Name() string
	Address() string
	// RunScript runs script under bash with env and returns its output.
	RunScript(ctx context.Context, env []string, script string) ([]byte, error)
}

// FenceSSHOptions tunes InstallFenceSSH.
type FenceSSHOptions struct {
	Out io.Writer
	// Remove takes the drop-in out instead.
	Remove bool
	// Wait bounds how long it waits for every host to report that its sshd
	// accepts the managed fence key (0: 3 minutes; negative: do not wait).
	Wait time.Duration
}

// InstallFenceSSH gives every host's sshd the managed fence SSH drop-in, as
// `lv host init` and `lv host add` do for a new host: the migration of an
// existing cluster (docs/migration-failover.md "Managed fence SSH"). Each host
// is evaluated for a fence from every other host's address. It then waits
// until every host's row reports accepting, and prints what each host reports.
//
// It changes nothing about how fences run by itself: in auto (an upgraded
// cluster's mode) a host's fences take the managed path toward each host once
// that host's row says it accepts the key. The hand-made fence key and root's
// ssh config are left alone; a managed fence never reads them.
//
// all is every live host's address by name: a host is evaluated for a fence
// from each of the others, whether or not this run provisions them.
func InstallFenceSSH(ctx context.Context, c pb.LiteVirtClient, hosts []FenceSSHHost, all map[string]string, opt FenceSSHOptions) error {
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if opt.Wait == 0 {
		opt.Wait = 3 * time.Minute
	}
	var failed []string
	for _, h := range hosts {
		var peers []string
		for name, addr := range all {
			if name != h.Name() {
				peers = append(peers, addr)
			}
		}
		sort.Strings(peers)
		env := []string{"FENCE_SSH_PEERS=" + fencessh.PeerAddresses(strings.Join(peers, " ")),
			"FENCE_SSH_SELF=" + fencessh.PeerAddresses(h.Address())}
		if opt.Remove {
			env = append(env, "FENCE_SSH_REMOVE=1")
		}
		out, err := h.RunScript(ctx, env, fencessh.InstallScript+"\nlv_fence_ssh_install\n")
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if l != "" {
				fmt.Fprintf(opt.Out, "  %-20s %s\n", h.Name(), l)
			}
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", h.Name(), err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the drop-in could not be installed on %d host(s): %s; re-run once they are reachable",
			len(failed), strings.Join(failed, "; "))
	}
	if opt.Remove || opt.Wait < 0 {
		return nil
	}
	fmt.Fprintf(opt.Out, "Waiting up to %s for every host to report that its sshd accepts the managed fence key...\n", opt.Wait)
	deadline := time.Now().Add(opt.Wait)
	var last map[string]*pb.FenceSSHPeer
	for {
		st, err := c.GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{})
		if err != nil {
			return fmt.Errorf("read the cluster's fence ssh rows: %w", err)
		}
		last = map[string]*pb.FenceSSHPeer{}
		for _, n := range st.GetNodes() {
			for _, p := range n.GetPeers() {
				last[p.GetHost()] = p
			}
		}
		done := true
		for _, h := range hosts {
			p := last[h.Name()]
			if p == nil || p.GetRow() != fencessh.RowVerified || !p.GetAccepting() {
				done = false
			}
		}
		if done || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	var pending []string
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		p := last[name]
		switch {
		case p == nil || p.GetRow() == fencessh.RowMissing:
			fmt.Fprintf(opt.Out, "  %-20s no fence ssh row yet (the release must have latched and its daemon be up)\n", name)
			pending = append(pending, name)
		case p.GetRow() != fencessh.RowVerified:
			fmt.Fprintf(opt.Out, "  %-20s row %s: %s\n", name, p.GetRow(), p.GetRowDetail())
			pending = append(pending, name)
		case !p.GetAccepting():
			fmt.Fprintf(opt.Out, "  %-20s not accepting: %s\n", name, p.GetRowDetail())
			pending = append(pending, name)
		default:
			fmt.Fprintf(opt.Out, "  %-20s accepts the managed fence key from %s\n", name, p.GetAddress())
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("%d host(s) do not accept the managed fence key yet (%s): a host that never did is "+
			"fenced over the pinned legacy path, one that did over the managed key, which its sshd may refuse. "+
			"Check `lv doctor fence`", len(pending), strings.Join(pending, ", "))
	}
	fmt.Fprintln(opt.Out, "Every host accepts the managed fence key. Check the probe matrix with `lv doctor fence`;")
	fmt.Fprintln(opt.Out, "then set enforcement.fence_ssh: managed on each host so no fence falls back to root's own ssh setup.")
	return nil
}

// SSHFenceSSHHosts dials every live host as sshUser, as `lv host
// install-gossip-key` does, or only the named ones, and returns every live
// host's address by name.
func SSHFenceSSHHosts(ctx context.Context, c pb.LiteVirtClient, sshUser string, only []string) ([]FenceSSHHost, map[string]string, func(), error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list hosts: %w", err)
	}
	if sshUser == "" {
		sshUser = "root"
	}
	want := map[string]bool{}
	for _, n := range only {
		want[n] = true
	}
	var hosts []FenceSSHHost
	var conns []*ssh.Client
	closeAll := func() {
		for _, sc := range conns {
			sc.Close()
		}
	}
	all := map[string]string{}
	for _, h := range resp.GetHosts() {
		all[h.Name] = h.Address
	}
	for _, h := range resp.GetHosts() {
		if len(want) > 0 && !want[h.Name] {
			continue
		}
		delete(want, h.Name)
		if h.Address == "" {
			closeAll()
			return nil, nil, nil, fmt.Errorf("host %s has no recorded address to reach it on", h.Name)
		}
		sc, err := ssh.NewClient(sshUser + "@" + h.Address)
		if err != nil {
			closeAll()
			return nil, nil, nil, fmt.Errorf("SSH to %s (%s@%s): %w", h.Name, sshUser, h.Address, err)
		}
		conns = append(conns, sc)
		hosts = append(hosts, &sshFenceSSHHost{name: h.Name, addr: h.Address, sc: sc})
	}
	for n := range want {
		closeAll()
		return nil, nil, nil, fmt.Errorf("the cluster lists no host %s", n)
	}
	if len(hosts) == 0 {
		return nil, nil, nil, fmt.Errorf("the cluster lists no hosts")
	}
	return hosts, all, closeAll, nil
}

type sshFenceSSHHost struct {
	name, addr string
	sc         *ssh.Client
}

func (h *sshFenceSSHHost) Name() string    { return h.name }
func (h *sshFenceSSHHost) Address() string { return h.addr }

func (h *sshFenceSSHHost) RunScript(_ context.Context, env []string, script string) ([]byte, error) {
	sess, err := h.sc.Conn().NewSession()
	if err != nil {
		return nil, fmt.Errorf("SSH session: %w", err)
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader([]byte(script))
	return sess.CombinedOutput(shellEnvPrefix(env) + " bash -s")
}
