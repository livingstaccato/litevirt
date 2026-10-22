package fencessh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// installHint is the operator's next step toward a managed path.
const installHint = "run `lv host install-fence-ssh` and check `lv doctor fence`"

// FenceConfig decides how a fence from this host reaches target, from the
// target's host_fence_ssh row as this node holds it:
//
//   - no row: the legacy path, unpinned — today's fence, for a host that has
//     not published (the release has not latched). enforcement.fence_ssh:
//     managed refuses it.
//   - a row that does not verify (forged, revoked, retired, a certificate
//     with no address): refused. A host that has published is never fenced
//     without its pin, whatever the mode, so breaking a row never earns an
//     unchecked fence.
//   - a verified row: managed when the target accepts the managed key (and
//     the mode is not legacy); refused when it accepted it once and no
//     longer does, unless the mode is legacy (never downgraded: the bit is
//     the target's own signed ever_accepting, not this node's memory);
//     otherwise the legacy path with its sshd keys pinned.
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
	if mode == ModeLegacy {
		return pinned, v
	}
	if !v.Accepting {
		switch {
		case mode == ModeManaged:
			return refuse("enforcement.fence_ssh is managed and %s's sshd does not accept the managed fence key (%s); %s",
				target, orUnknown(v.Detail), installHint), v
		case v.EverAccepting:
			return refuse("%s accepted the managed fence key before and no longer does (%s); it is never fenced down "+
				"a lesser path (set enforcement.fence_ssh: legacy on this host to allow the pinned legacy path); %s",
				target, orUnknown(v.Detail), installHint), v
		}
		return pinned, v
	}
	own, err := a.ownManaged()
	if err != nil {
		return refuse("%s accepts the managed fence key, but this host cannot use it: %v", target, err), v
	}
	own.KnownHosts, own.HostKeyAlias, own.Request = pinned.KnownHosts, pinned.HostKeyAlias, request
	return own, v
}

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
