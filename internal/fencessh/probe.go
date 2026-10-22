package fencessh

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/metrics"
)

// probeTimeout bounds one peer's check.
const probeTimeout = 20 * time.Second

// ProbeAll checks the managed path to every live peer whose row accepts it,
// records each result for `lv doctor fence`, and sets
// litevirt_fence_ssh_probe_ok{peer}. A check proves the pin, the key, the
// source address and the target's forced command; it does not prove the
// power-off itself works, which nothing short of a fence can.
func (a *Agent) ProbeAll(ctx context.Context) {
	hosts, err := corrosion.ListHosts(ctx, a.cfg.DB)
	if err != nil {
		slog.Warn("fence ssh: probe could not list hosts", "error", err)
		return
	}
	for _, h := range hosts {
		if h.Name == a.cfg.Self {
			continue
		}
		res := a.probe(ctx, h)
		a.mu.Lock()
		a.probes[h.Name] = res
		a.mu.Unlock()
		metrics.FenceSSHProbe(h.Name, res.OK)
		if !res.OK {
			slog.Warn("fence ssh: the managed fence path to a peer is broken", "peer", h.Name, "detail", res.Detail)
		}
	}
}

func (a *Agent) probe(ctx context.Context, h corrosion.HostRecord) ProbeResult {
	now := time.Now()
	sf, v := a.fenceConfig(ctx, h.Name, CheckRequest(h.Name))
	switch {
	case sf.Refusal != "":
		return ProbeResult{Detail: sf.Refusal, At: now}
	case sf.Path != fence.SSHPathManaged:
		why := "it has published no fence ssh row (legacy path, unpinned)"
		if v != nil {
			why = "its sshd does not accept the managed fence key (" + orUnknown(v.Detail) + "); legacy path, pinned"
		}
		return ProbeResult{Detail: "no managed path: " + why, At: now}
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	err := fence.ProbeSSH(pctx, fence.HostConfig{Name: h.Name, Address: h.Address, SSHPort: h.SSHPort, SSH: sf}, CheckOK)
	if err != nil {
		return ProbeResult{Detail: err.Error(), At: now}
	}
	return ProbeResult{OK: true, Detail: "managed path checked", At: now}
}

// Probes is the last probe result per peer.
func (a *Agent) Probes() map[string]ProbeResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]ProbeResult, len(a.probes))
	for k, v := range a.probes {
		out[k] = v
	}
	return out
}
