// Package fence implements host fencing strategies for litevirt.
// Fencing = cutting off a host before stealing its workloads to prevent split-brain.
// Strategies are tried in order; callers choose which to use via HostRecord.FenceStrategy.
package fence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Result is returned by every fence strategy.
type Result struct {
	Method  string
	Detail  string
	Success bool
}

// HostConfig is the subset of corrosion.HostRecord fields needed for fencing.
// Using a local struct avoids a circular import.
type HostConfig struct {
	Name          string
	Address       string
	SSHUser       string
	SSHPort       int
	FenceStrategy string
	// IPMI — only used when FenceStrategy = "ipmi"
	IPMIAddress string
	IPMIUser    string
	IPMIPass    string
	// Watchdog — only used when FenceStrategy = "watchdog" (self-fencing)
	WatchdogDev string
}

// Execute runs the fencing strategy specified by h.FenceStrategy.
// Strategies:
//
//	"best-effort"  – try SSH poweroff; succeed regardless (never blocks failover)
//	"ssh"          – SSH poweroff; report failure if unreachable
//	"ipmi"         – IPMI/BMC power off via ipmitool; must succeed
//	"manual"       – log an alert and return Success=false; the coordinator will NOT
//	                 reschedule until an operator confirms via `lv host fence-confirm`
//	"watchdog"     – write to /dev/watchdog to stop heartbeat (self-fencing, caller is local)
//	""             – treated as "best-effort"
func Execute(ctx context.Context, h HostConfig) Result {
	raw := strings.ToLower(strings.TrimSpace(h.FenceStrategy))
	strategy := ResolveStrategy(h.FenceStrategy)
	if strategy == "best-effort" && raw != "" && raw != "best-effort" {
		slog.Warn("unknown fence strategy, falling back to best-effort", "strategy", raw, "host", h.Name)
	}

	switch strategy {
	case "ipmi":
		return fenceIPMI(ctx, h)
	case "ssh":
		return fenceSSH(ctx, h, false)
	case "manual":
		return fenceManual(h)
	case "watchdog":
		return fenceWatchdog(h)
	default: // "best-effort" — lenient fire-and-forget SSH
		return fenceSSH(ctx, h, true)
	}
}

// ResolveStrategy returns the effective fence strategy Execute will run for a
// (possibly empty, mixed-case, or unknown) configured value. "", an unrecognized
// value, and "best-effort" all resolve to "best-effort" (lenient SSH). This is
// the SINGLE source of that normalization: any caller that must reason about
// which effective strategy will run — notably the safe-fence policy, which gates
// the best-effort path — MUST use this so it sees exactly what Execute sees and
// can't drift (e.g. a host with fence_strategy="" or a typo'd value would
// otherwise slip past a literal "best-effort" comparison).
func ResolveStrategy(raw string) string {
	switch s := strings.ToLower(strings.TrimSpace(raw)); s {
	case "ipmi", "ssh", "manual", "watchdog":
		return s
	default:
		return "best-effort"
	}
}

// fenceSSH sends "systemctl poweroff" to the host over SSH.
// If lenient=true, failures are reported as successful (best-effort mode).
func fenceSSH(ctx context.Context, h HostConfig, lenient bool) Result {
	port := h.SSHPort
	if port == 0 {
		port = 22
	}
	user := h.SSHUser
	if user == "" {
		user = "root"
	}
	target := fmt.Sprintf("%s@%s", user, h.Address)

	slog.Info("fencing host via SSH", "host", h.Name, "target", target, "lenient", lenient)

	cmd := exec.CommandContext(ctx, "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout(ctx, 10)),
		"-p", fmt.Sprintf("%d", port),
		target,
		"systemctl poweroff 2>/dev/null || poweroff 2>/dev/null || true",
	)
	out, runErr := cmd.CombinedOutput()
	detail := fmt.Sprintf("SSH poweroff to %s: %s", target, strings.TrimSpace(string(out)))

	if runErr != nil {
		if lenient {
			slog.Warn("SSH fence failed (best-effort, ignoring)", "host", h.Name, "error", runErr)
			return Result{
				Method:  "best-effort-ssh",
				Detail:  fmt.Sprintf("SSH failed (%v), proceeding anyway: %s", runErr, strings.TrimSpace(string(out))),
				Success: true,
			}
		}
		return Result{Method: "ssh", Detail: detail, Success: false}
	}
	return Result{Method: "ssh", Detail: detail, Success: true}
}

// fenceIPMI powers off the host via ipmitool chassis power off, then confirms
// the chassis actually reports off. Requires ipmitool on the managing host.
//
// Only a CONFIRMED power-off returns Success. corrosion.FenceProofGrade accepts
// nothing weaker for a shared-disk cross-host transfer, so reporting an
// unconfirmed fence as success would authorize starting a writable shared disk
// on a second host while the first may still be writing it.
func fenceIPMI(ctx context.Context, h HostConfig) Result {
	if h.IPMIAddress == "" {
		return Result{
			Method:  "ipmi",
			Detail:  "ipmi_address not configured on host",
			Success: false,
		}
	}

	slog.Info("fencing host via IPMI", "host", h.Name, "bmc", h.IPMIAddress)

	cmd, cancel := ipmitoolCmd(ctx, h, "chassis", "power", "off")
	defer cancel()
	out, runErr := cmd.CombinedOutput()
	detail := fmt.Sprintf("ipmitool chassis power off %s: %s", h.IPMIAddress, strings.TrimSpace(string(out)))

	if runErr != nil {
		// Interpolate the error: a pre-exec failure (ipmitool missing from PATH,
		// a NUL byte in the password) produces no output at all, and this string
		// becomes the permanent fencing_log row an operator reads when deciding
		// whether to run `lv host fence-confirm`. A bare trailing colon tells
		// them nothing.
		return Result{
			Method:  "ipmi",
			Detail:  fmt.Sprintf("%s (failed: %v)", detail, runErr),
			Success: false,
		}
	}

	verified, lastErr := verifyIPMIPowerOff(ctx, h)
	if !verified {
		slog.Warn("IPMI fence sent but power-off not confirmed",
			"host", h.Name, "budget", PowerOffVerifyTimeout, "last_error", lastErr)
		// Name the cause. An auth failure, a disabled BMC LAN channel and a
		// chassis that is genuinely still on all end up here, and only the last
		// one makes refusing to reschedule the correct outcome — so the operator
		// needs to know which they are looking at rather than being pointed at
		// BMC latency.
		reason := fmt.Sprintf("power-off not confirmed within %s", PowerOffVerifyTimeout)
		if lastErr != nil {
			reason += fmt.Sprintf(": %v", lastErr)
		}
		return Result{
			Method:  "ipmi",
			Detail:  fmt.Sprintf("%s (%s)", detail, reason),
			Success: false,
		}
	}

	return Result{Method: "ipmi", Detail: detail, Success: true}
}

// ipmitoolPerCallTimeout bounds ONE ipmitool invocation.
//
// Measured: a `-I lanplus` call to an unreachable BMC takes ~20s to give up, so
// an unbounded call can outlast the whole verification budget and leave the loop
// with a single killed poll. With -N/-R pinned below, a healthy call is ~3s, so
// this is a safety net rather than the normal path.
const ipmitoolPerCallTimeout = 8 * time.Second

// ipmitoolCmd builds one ipmitool invocation for h's BMC. The caller MUST call
// the returned cancel.
//
// Credential handling: the password travels in the environment (-E), never as
// `-P <pass>`, because argv is world-readable via /proc/<pid>/cmdline — any
// local user could read the credential that powers off the fleet out of `ps`
// during a fence. Another user's environment is not readable without the same
// uid or root.
//
// BOTH IPMI_PASSWORD and IPMITOOL_PASSWORD are set, to the same value. ipmitool
// reads either under -E and IPMITOOL_PASSWORD TAKES PRECEDENCE, so setting only
// IPMI_PASSWORD would let any inherited IPMITOOL_PASSWORD — a systemd
// EnvironmentFile, a container -e, or the conventional operator habit of
// exporting it to keep the password out of shell history — silently override
// every per-host credential and fail authentication fleet-wide.
//
// -N/-R pin the retransmit interval and retry count so per-call latency is a
// known quantity instead of the ~20s the defaults spend on an unreachable BMC.
func ipmitoolCmd(ctx context.Context, h HostConfig, ipmiArgs ...string) (*exec.Cmd, context.CancelFunc) {
	cctx, cancel := context.WithTimeout(ctx, ipmitoolPerCallTimeout)
	args := append([]string{
		"-I", "lanplus",
		"-H", h.IPMIAddress,
		"-U", h.IPMIUser,
		"-E",
		"-N", "1",
		"-R", "2",
	}, ipmiArgs...)
	cmd := exec.CommandContext(cctx, "ipmitool", args...)
	cmd.Env = append(os.Environ(),
		"IPMI_PASSWORD="+h.IPMIPass,
		"IPMITOOL_PASSWORD="+h.IPMIPass,
	)
	// SIGTERM first so ipmitool can close its IPMI session: a SIGKILLed call
	// orphans a session on the BMC until its idle timeout, and BMC LAN channels
	// cap concurrent sessions low (commonly 4-16), so repeatedly killing polls
	// can exhaust the session table and make the next genuine fence unable to
	// authenticate. WaitDelay then bounds the wait for output to drain, so a
	// grandchild holding stdout cannot block Wait indefinitely after the signal.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	return cmd, cancel
}

// Power-off verification budget. Measured against a live BMC (Supermicro-class,
// 2026-09): one `chassis power status` round trip costs ~2.9s. The previous
// 15s deadline with an unconditional 2s sleep after each call therefore allowed
// only ~3 polls (2.9s call + 2s sleep = ~4.9s per iteration), so a chassis that
// took longer than ~15s to report `off` was recorded as an UNVERIFIED fence.
//
// That failure is not benign: FenceProofGrade accepts only a confirmed
// power-off, so an unverified IPMI fence blocks a cross-host ownership transfer
// of a shared-disk VM entirely (capabilities.SharedStorageFenceV1) and waits
// for an operator `lv host fence-confirm`. A false negative here stalls a
// legitimate failover, so the poll cadence is sized for real hardware rather
// than for a fast reply.
//
// The budget is NOT the safety bound on how long a fence may run — the failover
// coordinator derives that from the lease it actually holds and passes it in as
// the context deadline (see internal/failover.Coordinator.failover). This value
// only caps verification when the caller allows more.
// Both are vars, not consts, ONLY so tests can shrink them: a "not off" verdict
// is reached by exhausting the budget, so a test asserting one would otherwise
// have to wait out the real 15s.
var (
	PowerOffVerifyTimeout = 15 * time.Second
	powerOffPollInterval  = 2 * time.Second
)

// chassisPowerOff is what `ipmitool chassis power status` prints for a chassis
// that is off, lowercased. Matched as a SUFFIX of the trimmed output rather than
// as a substring anywhere: this predicate is the sole proof that authorizes
// starting a shared writable disk elsewhere, and a false positive means two
// hosts writing one disk. Other ipmitool subcommands print "off" in unrelated
// fields (`chassis status` reports "Power Restore Policy : always-off" while the
// system is ON), so an unanchored match would certify a running host as fenced.
const chassisPowerOff = "chassis power is off"

// verifyIPMIPowerOff polls "chassis power status" until the chassis reports off,
// the caller's context ends, or PowerOffVerifyTimeout elapses. It returns the
// last error seen so the caller can say WHY a fence went unconfirmed.
//
// Polls are PACED from the start of each call rather than slept for a full
// interval after it: the call itself blocks for seconds against a real BMC
// (~2.9s measured), and adding an interval on top spends most of the budget
// idle. Each call is separately bounded (ipmitoolPerCallTimeout), so one stalled
// invocation cannot consume the whole budget.
func verifyIPMIPowerOff(ctx context.Context, h HostConfig) (bool, error) {
	vctx, cancel := context.WithTimeout(ctx, PowerOffVerifyTimeout)
	defer cancel()

	var lastErr error
	for {
		if err := vctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			return false, lastErr
		}

		started := time.Now()
		cmd, cancelCall := ipmitoolCmd(vctx, h, "chassis", "power", "status")
		out, err := cmd.Output()
		cancelCall()

		switch {
		case err == nil && strings.HasSuffix(strings.ToLower(strings.TrimSpace(string(out))), chassisPowerOff):
			return true, nil
		case err != nil:
			// Keep the stderr ipmitool wrote: "Unable to establish IPMI v2 /
			// RMCP+ session" is the signature of a wrong password, which is
			// otherwise indistinguishable here from a slow chassis.
			lastErr = err
			var ee *exec.ExitError
			if errors.As(err, &ee) && len(ee.Stderr) > 0 {
				lastErr = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
			}
			slog.Debug("IPMI power-off poll failed", "host", h.Name, "error", lastErr)
		default:
			lastErr = fmt.Errorf("chassis reported: %s", strings.TrimSpace(string(out)))
		}

		// Pace from when this poll STARTED, so a slow call does not also cost a
		// full sleep. time.After fires immediately on a non-positive duration,
		// which is the normal case at the measured BMC latency.
		select {
		case <-vctx.Done():
			return false, lastErr
		case <-time.After(powerOffPollInterval - time.Since(started)):
		}
	}
}

// fenceManual logs an alert but does not attempt any automated action.
// The operator is expected to manually power off the host and acknowledge.
//
// Returns Success=false so the coordinator's split-brain guard refuses to
// reschedule VMs without operator confirmation. A separate path (e.g.
// "lv host fence-confirm <host>") writes a fencing_log row with method
// "manual-confirmed" that the coordinator can detect via recentlyFenced
// before its next failover cycle.
//
// Old behavior (Success=true) silently bypassed the split-brain guard and
// could cause the same VM to run on two hosts simultaneously when the
// operator hadn't actually pulled the plug.
func fenceManual(h HostConfig) Result {
	msg := fmt.Sprintf("MANUAL FENCE REQUIRED: host %q (address %s) must be powered off by an operator and confirmed via 'lv host fence-confirm %s' before its VMs are restarted elsewhere", h.Name, h.Address, h.Name)
	slog.Warn(msg, "host", h.Name, "fence_strategy", "manual")
	// In a real deployment you would fire a webhook/alert here.
	return Result{
		Method:  "manual",
		Detail:  msg,
		Success: false,
	}
}

// fenceWatchdog stops the local watchdog heartbeat so the hardware watchdog
// reboots this node. Only meaningful when running on the node being fenced.
func fenceWatchdog(h HostConfig) Result {
	dev := h.WatchdogDev
	if dev == "" {
		dev = "/dev/watchdog"
	}
	slog.Warn("self-fencing via watchdog — stopping heartbeat", "dev", dev)

	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return Result{
			Method:  "watchdog",
			Detail:  fmt.Sprintf("open %s: %v", dev, err),
			Success: false,
		}
	}
	// Deliberately do NOT write 'V' (magic close) — just close without keepalive.
	// The watchdog driver will expire and reboot the system.
	f.Close()

	return Result{
		Method:  "watchdog",
		Detail:  fmt.Sprintf("watchdog heartbeat stopped on %s; system will reboot", dev),
		Success: true,
	}
}

// connectTimeout returns min(seconds, remaining ctx seconds).
func connectTimeout(ctx context.Context, seconds int) int {
	if dl, ok := ctx.Deadline(); ok {
		rem := int(time.Until(dl).Seconds())
		if rem < seconds {
			return rem
		}
	}
	return seconds
}
