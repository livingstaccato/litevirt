package fencessh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// installHint is the operator's next step toward a managed path.
const installHint = "run `lv host install-fence-ssh` and check `lv doctor fence`"

// FenceConfig decides how a fence from this host reaches target, from the
// target's host_fence_ssh row as this node holds it:
//
//   - no row: the legacy path, unpinned — today's fence, for a host that has
//     not published (the release has not latched, enforcement.fence_ssh:
//     legacy on it, or a certificate with no fence address).
//     enforcement.fence_ssh: managed refuses it, and so does auto once
//     release_2026_12_v1 has latched here: from then on every host not in
//     legacy publishes, so a row-less target has not synced yet or never
//     will, and an unpinned fence of it would power off whatever answers at
//     its address and count that a success. legacy still takes it (the
//     stand-down).
//   - a row that does not verify (forged, revoked, retired): refused. A host
//     that has published is never fenced without its pin, whatever the mode,
//     so breaking a row never earns an unchecked fence.
//   - a verified row whose host accepts the managed key, or accepted it once
//     (ever_accepting, its own signed bit): the managed path. Its `accepting`
//     is one host's evaluation of its own sshd, for every peer at once; a
//     false one (a peer it was not provisioned for, an evaluation that
//     failed) must not make it unfenceable, and trying the managed key is
//     never less safe than refusing: pin, restricted key, from= and forced
//     command all still apply. legacy mode takes the pinned path.
//   - a verified row whose host never accepted it: the legacy path with its
//     sshd keys pinned; managed mode refuses.
//
// The pinned path is refused toward a host whose sshd keys another host also
// publishes (a cloned image): the pin cannot tell them apart, and the legacy
// command has no forced command to refuse a request for another host.
func (a *Agent) FenceConfig(ctx context.Context, target string) fence.SSHFence {
	sf, _ := a.fenceConfig(ctx, target, PoweroffRequest(target))
	return sf
}

func (a *Agent) fenceConfig(ctx context.Context, target, request string) (fence.SSHFence, *Verified) {
	mode := a.Mode()
	refuse := func(format string, args ...any) fence.SSHFence {
		return fence.SSHFence{Refusal: fmt.Sprintf(format, args...)}
	}
	row, ok, err := corrosion.GetHostFenceSSH(ctx, a.cfg.DB, target)
	if err != nil {
		return refuse("read %s's fence ssh row: %v", target, err), nil
	}
	if !ok {
		if mode == ModeManaged {
			return refuse("enforcement.fence_ssh is managed and %s has published no fence ssh row (it does once the "+
				"cluster runs release_2026_12_v1 and its daemon is up); %s", target, installHint), nil
		}
		if mode == ModeAuto && a.fenceSSHLatched() {
			return refuse("enforcement.fence_ssh is auto and release_2026_12_v1 has latched, but %s has published no "+
				"fence ssh row, so it is not fenced without a pinned host key, and its workloads are not recovered "+
				"on this fence. A host just admitted publishes one on its daemon's first sync, within about 30s of "+
				"its daemon starting, and is refused until then; one in enforcement.fence_ssh: legacy, or whose "+
				"certificate names no single fence address, never does. %s. `lv doctor fence` lists every host "+
				"refused this way; enforcement.fence_ssh: legacy on this host fences it unpinned",
				target, fence.NotFencedWayOut(target)), nil
		}
		return fence.SSHFence{Path: fence.SSHPathLegacy}, nil
	}
	tr, err := TrustFromPKIDir(a.cfg.PKIDir)
	if err != nil {
		return refuse("cannot verify %s's fence ssh row: %v", target, err), nil
	}
	v, err := Verify(row, tr)
	if err != nil {
		return refuse("%s's fence ssh row does not verify (%v); a host that has published one is never fenced "+
			"without its pinned host key", target, err), nil
	}
	pinned := fence.SSHFence{Path: fence.SSHPathPinned, KnownHosts: KnownHostsLines(v), HostKeyAlias: Alias(target)}
	pinnedOr := func(why string) fence.SSHFence {
		other, err := a.sharedHostKey(ctx, target, v, tr)
		if err != nil {
			return refuse("%s; and this host cannot check whether another host publishes %s's sshd host keys (%v), "+
				"so the pinned legacy path cannot rule out a cloned image", why, target, err)
		}
		if other != "" {
			return refuse("%s; and %s publishes one of %s's sshd host keys (a cloned image?), so the pinned legacy "+
				"path cannot tell the two apart: regenerate the sshd host keys on one of them", why, other, target)
		}
		return pinned
	}
	if mode == ModeLegacy {
		return pinnedOr("enforcement.fence_ssh is legacy"), v
	}
	if !v.Accepting && !v.EverAccepting {
		if mode == ModeManaged {
			return refuse("enforcement.fence_ssh is managed and %s's sshd does not accept the managed fence key (%s); %s",
				target, orUnknown(v.Detail), installHint), v
		}
		return pinnedOr(target + " does not accept the managed fence key"), v
	}
	own, err := a.ownManaged()
	if err != nil {
		if mode == ModeManaged {
			return refuse("%s accepts the managed fence key, but this host cannot use it: %v", target, err), v
		}
		return pinnedOr("this host cannot use the managed fence key (" + err.Error() + ")"), v
	}
	own.KnownHosts, own.HostKeyAlias, own.Request = pinned.KnownHosts, pinned.HostKeyAlias, request
	return own, v
}

// fenceSSHLatched reports whether release_2026_12_v1 has durably latched
// here, from the local latch alone. No gate reads as not latched: the latch is
// monotone and local, so false means a cluster still rolling, where no host
// has published and refusing would strand every fence.
func (a *Agent) fenceSSHLatched() bool {
	return a.cfg.Gate != nil && a.cfg.Gate.ReleaseFeatureAvailable(capabilities.FeatureFenceSSH)
}

// sharedHostKey is another live host whose verified row publishes one of v's
// sshd host keys, "" for none. An error means it could not tell: the caller
// refuses rather than read that as "none".
func (a *Agent) sharedHostKey(ctx context.Context, target string, v *Verified, tr Trust) (string, error) {
	mine := map[string]bool{}
	for _, k := range v.HostKeys {
		mine[KeyLine(k)] = true
	}
	rows, err := listHostFenceSSH(ctx, a.cfg.DB)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.HostName == target || r.Deleted {
			continue
		}
		o, err := Verify(r, tr)
		if err != nil {
			continue
		}
		for _, k := range o.HostKeys {
			if mine[KeyLine(k)] {
				return r.HostName, nil
			}
		}
	}
	return "", nil
}

// listHostFenceSSH reads every row for sharedHostKey. A var only so a test
// can fail it.
var listHostFenceSSH = corrosion.ListHostFenceSSH

func orUnknown(s string) string {
	if s == "" {
		return "no reason recorded"
	}
	return s
}

// ownManaged is this host's half of a managed fence: its key and the address
// its peers accept it from.
func (a *Agent) ownManaged() (fence.SSHFence, error) {
	key := filepath.Join(a.cfg.Dir, KeyName)
	if _, err := os.Stat(key); err != nil {
		return fence.SSHFence{}, fmt.Errorf("no fence key at %s yet (%v)", key, err)
	}
	self, _, err := a.ownIdentity()
	if err != nil {
		return fence.SSHFence{}, err
	}
	addr, err := FenceAddress(self)
	if err != nil {
		return fence.SSHFence{}, err
	}
	return fence.SSHFence{Path: fence.SSHPathManaged, IdentityFile: key, BindAddress: addr.String(), User: a.cfg.SSHUser}, nil
}

// LastError is the last Sync failure, "" when the last one succeeded.
func (a *Agent) LastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}
