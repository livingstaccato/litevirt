package fencessh

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// UpgradeModeTimeout bounds the fanned-out read CheckUpgradeModes makes.
const UpgradeModeTimeout = 30 * time.Second

// CheckUpgradeModes is the enforcement.fence_ssh preflight of an upgrade to
// this build: `lv host upgrade` and the UI's upgrade both run it before
// anything is pre-staged or swapped, and --force does not skip it. It reads
// every member's running mode (a fanned-out GetFenceSSHStatus) and refuses
// while any member still reports legacy (RemovedMode):
//
//   - a target: this binary refuses legacy at start, so its swapped daemon
//     would not come back;
//   - any other member: once release_2026_12_v1 has latched, a host on this
//     build refuses to fence a host that has published no fence ssh row, and
//     a host in legacy publishes none, so every fence of it from an upgraded
//     host would fail and its workloads would not be recovered.
//
// A read that fails, or a member that does not report its mode (a build
// without the read, or a host that does not answer), refuses nothing; it comes
// back as a warning. A target's daemon still checks its config at start.
func CheckUpgradeModes(ctx context.Context, client pb.LiteVirtClient, targets []string) (warnings []string, err error) {
	cctx, cancel := context.WithTimeout(ctx, UpgradeModeTimeout)
	defer cancel()
	st, err := client.GetFenceSSHStatus(cctx, &pb.FenceSSHStatusRequest{FanOut: true})
	if err != nil {
		return []string{fmt.Sprintf("could not read the members' enforcement.fence_ssh (%v); a host whose config "+
			"still says legacy will not start on this binary, and is not fenced by one that runs it: %s on it first",
			err, ModeFix)}, nil
	}
	var removedTargets, removedOthers, unknownTargets, unknownOthers []string
	seen := map[string]bool{}
	for _, n := range st.GetNodes() {
		target := slices.Contains(targets, n.GetHost())
		seen[n.GetHost()] = true
		switch {
		case RemovedMode(n.GetMode()) && target:
			removedTargets = append(removedTargets, n.GetHost())
		case RemovedMode(n.GetMode()):
			removedOthers = append(removedOthers, n.GetHost())
		case !n.GetReachable() || n.GetMode() == "":
			if target {
				unknownTargets = append(unknownTargets, n.GetHost())
			} else {
				unknownOthers = append(unknownOthers, n.GetHost())
			}
		}
	}
	for _, t := range targets {
		if !seen[t] {
			unknownTargets = append(unknownTargets, t)
		}
	}
	var refusals []string
	if len(removedTargets) > 0 {
		refusals = append(refusals, fmt.Sprintf("%s: enforcement.fence_ssh is legacy, which this binary refuses at "+
			"start, so the daemon would not come back after the swap", strings.Join(removedTargets, ", ")))
	}
	if len(removedOthers) > 0 {
		refusals = append(refusals, fmt.Sprintf("%s: enforcement.fence_ssh is legacy, so it publishes no fence ssh "+
			"row, and once release_2026_12_v1 has latched a host on this binary refuses to fence it: its "+
			"workloads would not be recovered if it failed", strings.Join(removedOthers, ", ")))
	}
	if len(refusals) > 0 {
		return nil, fmt.Errorf("%s. On each, %s in its config and restart its daemon, then upgrade again; nothing "+
			"was pre-staged or swapped", strings.Join(refusals, "; "), ModeFix)
	}
	if len(unknownTargets) > 0 {
		warnings = append(warnings, fmt.Sprintf("%s did not report its enforcement.fence_ssh; a host whose config "+
			"still says legacy will not start on this binary: %s first", strings.Join(unknownTargets, ", "), ModeFix))
	}
	if len(unknownOthers) > 0 {
		warnings = append(warnings, fmt.Sprintf("%s did not report its enforcement.fence_ssh; a host whose config "+
			"still says legacy is not fenced by one on this binary: %s on it", strings.Join(unknownOthers, ", "), ModeFix))
	}
	return warnings, nil
}
