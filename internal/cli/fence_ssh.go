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
	// FreshAfter is how long after a host's install its own row is first
	// read as reflecting it (0: fencessh.RowFreshAfter, the bound the
	// daemon's agent keeps). Only tests whose agents sync on demand set it.
	FreshAfter time.Duration

	// Tests: the clock, and the pause between reads.
	now   func() time.Time
	pause func(context.Context, time.Duration) error
}

// fenceSSHResultMarker starts the line the install run prints last: the
// outcome the script set (fencessh.Result*). The script returns 0 on every
// path, so this line is the only way to tell an install from a refusal.
const fenceSSHResultMarker = "lv-fence-ssh-result: "

// fenceSSHPoll is how often InstallFenceSSH reads the hosts' own rows.
const fenceSSHPoll = 5 * time.Second

// InstallFenceSSH gives every host's sshd the managed fence SSH drop-in, as
// `lv host init` and `lv host add` do for a new host: the migration of an
// existing cluster (docs/migration-failover.md "Managed fence SSH"). Each host
// is evaluated for a fence from every other host's address. It then waits
// until every host's own row, read late enough to reflect an evaluation of
// its sshd made after this run changed it, reports accepting, and prints what
// each host reports. It fails when any host's script refused or did not
// reload sshd, and when any host does not confirm before the wait ends: a row
// that predates the run (it can say accepting for a minute or more after a
// --remove) never counts.
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
	if opt.FreshAfter == 0 {
		opt.FreshAfter = fencessh.RowFreshAfter
	}
	if opt.now == nil {
		opt.now = time.Now
	}
	if opt.pause == nil {
		opt.pause = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
	if !opt.Remove && opt.Wait > 0 && opt.Wait < opt.FreshAfter {
		return fmt.Errorf("--wait %s is shorter than the %s a host's row takes to reflect its sshd after a change, "+
			"so no host could confirm; nothing was changed", opt.Wait, opt.FreshAfter)
	}
	want := fencessh.ResultInstalled
	if opt.Remove {
		want = fencessh.ResultRemoved
	}
	var failed []string
	doneAt := map[string]time.Time{}
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
		out, err := h.RunScript(ctx, env, fencessh.InstallScript+"\nlv_fence_ssh_install\necho \""+
			fenceSSHResultMarker+"${LV_FENCE_SSH_RESULT:-}\"\n")
		doneAt[h.Name()] = opt.now()
		result := ""
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if r, ok := strings.CutPrefix(l, fenceSSHResultMarker); ok {
				result = strings.TrimSpace(r)
				continue
			}
			if l != "" {
				fmt.Fprintf(opt.Out, "  %-20s %s\n", h.Name(), l)
			}
		}
		switch {
		case err != nil:
			failed = append(failed, fmt.Sprintf("%s: %v", h.Name(), err))
		case result == fencessh.ResultUnreloaded:
			failed = append(failed, h.Name()+": sshd was not reloaded, so it does not read the change yet")
		case result != want:
			failed = append(failed, h.Name()+": refused (see its lines above)")
		}
	}
	if len(failed) > 0 {
		what := "installed on"
		if opt.Remove {
			what = "removed from"
		}
		return fmt.Errorf("the drop-in could not be %s %d host(s): %s; fix that and re-run",
			what, len(failed), strings.Join(failed, "; "))
	}
	if opt.Remove {
		// A host whose row ever said accepting stays on the managed path
		// (ever_accepting is sticky), so its sshd now refuses every fence of
		// it: there is no fallback to the legacy path.
		for _, h := range hosts {
			fmt.Fprintf(opt.Out, "  %-20s WARNING: if it ever accepted the managed fence key, peers still fence it over that key,\n"+
				"  %-20s which is now refused by its sshd: fences of it fail until `lv host install-fence-ssh --host %s`\n",
				h.Name(), "", h.Name())
		}
		return nil
	}
	if opt.Wait < 0 {
		return nil
	}
	fmt.Fprintf(opt.Out, "Waiting up to %s for every host to report that its sshd accepts the managed fence key\n"+
		"(a host's row counts once it is %s newer than its install)...\n", opt.Wait, opt.FreshAfter)
	deadline := opt.now().Add(opt.Wait)
	var why map[string]string
	for {
		// The installs already happened: a read that fails is retried until
		// the wait ends, and fails the run only then.
		st, err := c.GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{FanOut: true})
		if err != nil {
			if ctx.Err() != nil || !opt.now().Before(deadline) {
				return fmt.Errorf("read the hosts' fence ssh rows: %w", err)
			}
			fmt.Fprintf(opt.Out, "  (reading the hosts' fence ssh rows failed, retrying: %v)\n", err)
		} else {
			why = fenceSSHUnconfirmed(st, hosts, doneAt, opt.now(), opt.FreshAfter)
			if len(why) == 0 || !opt.now().Before(deadline) {
				break
			}
		}
		if err := opt.pause(ctx, fenceSSHPoll); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name())
	}
	sort.Strings(names)
	var pending []string
	for _, name := range names {
		if w, ok := why[name]; ok {
			fmt.Fprintf(opt.Out, "  %-20s %s\n", name, w)
			pending = append(pending, name)
		} else {
			fmt.Fprintf(opt.Out, "  %-20s accepts the managed fence key\n", name)
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("%d host(s) did not confirm that they accept the managed fence key (%s): a host that never did is "+
			"fenced over the pinned legacy path, one that did over the managed key, which its sshd may refuse. "+
			"Check `lv doctor fence`", len(pending), strings.Join(pending, ", "))
	}
	fmt.Fprintln(opt.Out, "Every host accepts the managed fence key. Check the probe matrix with `lv doctor fence`;")
	fmt.Fprintln(opt.Out, "then set enforcement.fence_ssh: managed on each host so no fence falls back to root's own ssh setup.")
	return nil
}

// fenceSSHUnconfirmed is, for each host that does not confirm yet, why: a
// host confirms only by its own view of its own row (no replication lag),
// read at least freshAfter after its install finished, from an agent whose
// last sync succeeded, verified and accepting.
func fenceSSHUnconfirmed(st *pb.FenceSSHStatus, hosts []FenceSSHHost, doneAt map[string]time.Time, now time.Time, freshAfter time.Duration) map[string]string {
	own := map[string]*pb.FenceSSHNode{}
	for _, n := range st.GetNodes() {
		own[n.GetHost()] = n
	}
	why := map[string]string{}
	for _, h := range hosts {
		name := h.Name()
		n := own[name]
		var p *pb.FenceSSHPeer
		for _, pp := range n.GetPeers() {
			if pp.GetHost() == name {
				p = pp
			}
		}
		switch {
		case n == nil || !n.GetReachable():
			why[name] = "its daemon did not answer for its own row: " + n.GetError()
		case n.GetError() != "":
			why[name] = "its daemon did not report its own row: " + n.GetError()
		case n.GetLastError() != "":
			why[name] = "its fence ssh agent's last sync failed, so its row may predate the install: " + n.GetLastError()
		case p == nil || p.GetRow() == fencessh.RowMissing:
			why[name] = "no fence ssh row yet (the release must have latched and its daemon be up)"
		case p.GetRow() != fencessh.RowVerified:
			why[name] = fmt.Sprintf("row %s: %s", p.GetRow(), p.GetRowDetail())
		case now.Sub(doneAt[name]) < freshAfter:
			why[name] = "its row predates the install's evaluation by its daemon"
		case !p.GetAccepting():
			why[name] = "not accepting: " + p.GetRowDetail()
		}
	}
	return why
}

// dialFenceSSHHost opens an SSH session to one host (tests swap it).
var dialFenceSSHHost = func(sshUser, name, addr string) (FenceSSHHost, func(), error) {
	sc, err := ssh.NewClient(sshUser + "@" + addr)
	if err != nil {
		return nil, nil, err
	}
	return &sshFenceSSHHost{name: name, addr: addr, sc: sc}, func() { sc.Close() }, nil
}

// SSHFenceSSHHosts dials every live host as sshUser, as `lv host
// install-gossip-key` does, or exactly the named ones, and returns every live
// host's address by name. A name the cluster does not list refuses the run
// before any host is dialed.
func SSHFenceSSHHosts(ctx context.Context, c pb.LiteVirtClient, sshUser string, only []string) ([]FenceSSHHost, map[string]string, func(), error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list hosts: %w", err)
	}
	if sshUser == "" {
		sshUser = "root"
	}
	all := map[string]string{}
	for _, h := range resp.GetHosts() {
		all[h.Name] = h.Address
	}
	// The selection is settled, every name checked, before anything is
	// dialed: the filter is the named set itself, never a set consumed while
	// walking the list.
	want := map[string]bool{}
	for _, n := range only {
		if _, ok := all[n]; !ok {
			return nil, nil, nil, fmt.Errorf("the cluster lists no host %q; nothing was changed", n)
		}
		want[n] = true
	}
	var selected []*pb.Host
	for _, h := range resp.GetHosts() {
		if len(only) > 0 && !want[h.Name] {
			continue
		}
		if h.Address == "" {
			return nil, nil, nil, fmt.Errorf("host %s has no recorded address to reach it on", h.Name)
		}
		selected = append(selected, h)
	}
	if len(selected) == 0 {
		return nil, nil, nil, fmt.Errorf("the cluster lists no hosts")
	}
	var hosts []FenceSSHHost
	var closers []func()
	closeAll := func() {
		for _, cl := range closers {
			cl()
		}
	}
	for _, h := range selected {
		fh, cl, err := dialFenceSSHHost(sshUser, h.Name, h.Address)
		if err != nil {
			closeAll()
			return nil, nil, nil, fmt.Errorf("SSH to %s (%s@%s): %w", h.Name, sshUser, h.Address, err)
		}
		closers = append(closers, cl)
		hosts = append(hosts, fh)
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
