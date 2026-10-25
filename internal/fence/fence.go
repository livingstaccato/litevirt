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
	"sync"
	"syscall"
	"time"
)

// Result is returned by every fence strategy.
type Result struct {
	Method  string
	Detail  string
	Success bool
	// Dialled marks a best-effort SSH fence that ran ssh and did not confirm
	// the power-off: the request may or may not have reached the host. It is
	// a failure (Success false) and proves nothing. The failover coordinator
	// counts it only when it relies on the host's own partition pause and has
	// waited that pause out (docs/design/partition-pause.md §4).
	Dialled bool
	// WrongHost marks an SSH fence whose pinned host key did not match: a
	// different machine answered at the host's address. Nothing about the
	// host itself is known, not even that it lost the majority, so not even
	// its partition pause is relied on.
	WrongHost bool
	// Answered marks an SSH fence the host's sshd answered past the host-key
	// check, whose command still did not confirm the power-off (permission
	// denied, commands failed, exit 0 without the marker). The host is
	// reachable, so it has not lost the majority and paused: the likelier
	// cause is a hung daemon, which pauses nothing. Like WrongHost, not even
	// the host's partition pause is relied on.
	Answered bool
	// Path is the path an SSH fence took (managed, legacy-pinned,
	// legacy-unpinned, refused), set by fenceSSH from the path it was
	// handed, never from anything the remote machine printed.
	Path string
	// Unproven marks a result the failover coordinator stopped counting as a
	// fence: it reported success, but nothing proves the host is off.
	Unproven bool
}

// ConfirmedOverPin reports whether r is an SSH power-off the remote shell
// confirmed (method ssh, a success: the marker was seen), reached over the
// host's pinned sshd key: the managed or the legacy-pinned path. The path is
// r.Path, set by fenceSSH; a result read back from fencing_log, which has
// none, takes it from its recorded detail (RecordedPath). An unpinned
// success, or a row that names no path (an earlier build's), is not one.
func ConfirmedOverPin(r Result) bool {
	if r.Method != "ssh" || !r.Success {
		return false
	}
	path := r.Path
	if path == "" {
		path = RecordedPath(r.Detail)
	}
	return path == "managed" || path == "legacy-pinned"
}

// RecordedPath is the path label an SSH fence's detail records: its last
// "[path=<label>]" token. The remote machine's output in a detail cannot
// carry one (remoteOutput rewrites it), so the token fenceSSH appends is the
// only one a detail it wrote holds. "" when there is none.
func RecordedPath(detail string) string {
	i := strings.LastIndex(detail, "[path=")
	if i < 0 {
		return ""
	}
	rest := detail[i+len("[path="):]
	j := strings.IndexByte(rest, ']')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// Trust tokens: the decision, made when a confirmed SSH power-off is judged,
// whether its host trusted one (the host's litevirt.trust_ssh_poweroff then).
// The coordinator appends one to the fence's detail before it records the row
// (WithTrust), and every later judgement of that fence, a successor's resume
// included, reads it back (RecordedTrust) rather than the label as it reads
// now: trust is never retroactive.
const (
	trustOn  = "[trust=on]"
	trustOff = "[trust=off]"
)

// WithTrust is detail with the trust decision appended.
func WithTrust(detail string, trusted bool) string {
	if trusted {
		return detail + " " + trustOn
	}
	return detail + " " + trustOff
}

// RecordedTrust reports whether detail records that its fence was judged
// trusted: its last "[trust=" token is "[trust=on]" and follows the last
// "[path=" token, which the remote machine's output cannot carry either
// (remoteOutput). A detail with no token (an earlier build's row) records no
// trust: the fence is held.
func RecordedTrust(detail string) bool {
	i := strings.LastIndex(detail, "[trust=")
	if i < 0 || !strings.HasPrefix(detail[i:], trustOn) {
		return false
	}
	return strings.LastIndex(detail, "[path=") < i
}

// remoteOutput is what the machine that answered an SSH fence printed, as a
// fence detail records it: trimmed, with any "[path=" or "[trust=" rewritten
// so that it cannot pass for the path token fenceSSH appends (RecordedPath)
// or the trust token the coordinator appends (RecordedTrust).
func remoteOutput(out []byte) string {
	s := strings.ReplaceAll(strings.TrimSpace(string(out)), "[path=", "[path:")
	return strings.ReplaceAll(s, "[trust=", "[trust:")
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
	// IPMICredentialRetired: the host's fence credential was retired (the host
	// was removed or re-admitted) and no password has been set since.
	IPMICredentialRetired bool
	// Redfish — only used when FenceStrategy = "redfish"
	Redfish RedfishConfig
	// Watchdog — only used when FenceStrategy = "watchdog" (self-fencing)
	WatchdogDev string
	// IsSelf reports that this process is running ON the host being fenced.
	//
	// Only the watchdog strategy reads it, and it FAILS CLOSED: a caller that
	// forgets to set it gets a refusal, not somebody else's watchdog armed.
	IsSelf bool
	// SSH is how an ssh or best-effort fence reaches the host: the managed
	// path, the legacy path with the host's published sshd keys pinned, a
	// refusal, or (the zero value) the legacy path unpinned. The caller
	// decides it from the target's verified host_fence_ssh row
	// (fencessh.Agent.FenceConfig).
	SSH SSHFence
}

// The paths an SSH fence takes (SSHFence.Path).
const (
	// SSHPathLegacy is the command fenceSSH always ran: root's own ssh
	// configuration and keys, and no host-key check. Only for a host that
	// has published no fence SSH row.
	SSHPathLegacy = ""
	// SSHPathPinned is the legacy command with the host's published sshd
	// keys pinned: a machine answering at its address with any other key
	// fails before it is asked to do anything.
	SSHPathPinned = "pinned"
	// SSHPathManaged is this host's own fence key, pinned, with no ssh
	// configuration of root's in play, asking the target's forced command
	// to power off the host the request names.
	SSHPathManaged = "managed"
)

// SSHFence is an SSH fence's path to its target (HostConfig.SSH).
type SSHFence struct {
	Path string
	// Refusal, when set, fails the fence without dialling anything, and says
	// why. A managed failure is never retried down another path.
	Refusal string
	// KnownHosts is the target's pinned sshd keys in known_hosts form under
	// HostKeyAlias (pinned and managed).
	KnownHosts   []byte
	HostKeyAlias string
	// The managed path's own key, source address, account and request.
	IdentityFile string
	BindAddress  string
	User         string
	Request      string
}

// pathLabel is the path as fencing_log records it.
func (s SSHFence) pathLabel() string {
	if s.Refusal != "" {
		return "refused"
	}
	switch s.Path {
	case SSHPathManaged:
		return "managed"
	case SSHPathPinned:
		return "legacy-pinned"
	default:
		return "legacy-unpinned"
	}
}

// Execute runs the fencing strategy specified by h.FenceStrategy.
// Strategies:
//
//	"best-effort"  – try an SSH forced power-off; one that does not confirm it is a
//	                 failure (Dialled when ssh ran), as under "ssh", which the
//	                 coordinator counts only on the host's partition pause
//	"ssh"          – SSH forced (immediate) power-off; report failure if unreachable
//	"ipmi"         – IPMI/BMC power off via ipmitool; must succeed
//	"redfish"      – Redfish/BMC ComputerSystem.Reset ForceOff over HTTPS, then
//	                 PowerState Off observed; must succeed (redfish.go)
//	"manual"       – log an alert and return Success=false; the coordinator will NOT
//	                 reschedule until an operator confirms via `lv host fence-confirm`
//	"watchdog"     – write to /dev/watchdog to stop heartbeat. SELF-fencing only:
//	                 refused unless h.IsSelf, because it arms the CALLING node
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
	case "redfish":
		return fenceRedfish(ctx, h)
	case "ssh":
		return fenceSSH(ctx, h, false)
	case "manual":
		return fenceManual(h)
	case "watchdog":
		// A watchdog fence is a SELF-fence: fenceWatchdog opens WatchdogDev on
		// THIS node. Dispatched at a peer it either arms the coordinator's own
		// hardware watchdog -- rebooting a healthy node in the middle of a
		// recovery it is running -- or fails on a missing device. The first case
		// is the dangerous one, because it then reports Success: true and the
		// coordinator reads a started LOCAL countdown as a verified power-off of
		// the REMOTE host, and reschedules its VMs onto shared storage the
		// original may still be writing to.
		//
		// Refused rather than silently downgraded to SSH: the configured
		// strategy is what an operator chose for this host, and quietly running
		// a different one is how a fence comes to mean three things. A refusal
		// leaves the host unfenced and the coordinator declining to reschedule,
		// which is the safe direction.
		if !h.IsSelf {
			return Result{
				Method: "watchdog",
				Detail: fmt.Sprintf("fence_strategy=watchdog is self-only and %q is not this host; "+
					"a watchdog fence arms the CALLING node. Configure ipmi or redfish (or ssh) for a remotely "+
					"fenceable host, or confirm manually with `lv host fence-confirm %s`", h.Name, h.Name),
				Success: false,
			}
		}
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
	case "ipmi", "redfish", "ssh", "manual", "watchdog":
		return s
	default:
		return "best-effort"
	}
}

// SSHOnly reports whether a host with fence strategy raw is fenced only over
// SSH (ssh, or best-effort, which unset and unknown values resolve to): no
// fence of it ever proves a power-off.
func SSHOnly(raw string) bool {
	switch ResolveStrategy(raw) {
	case "ssh", "best-effort":
		return true
	}
	return false
}

// sshFenceArmed is the line the remote fence command prints once it is running
// on the target and about to power it off. See sshPowerOffCommand.
const sshFenceArmed = "litevirt-fence-armed"

// sshPowerOffCommand is the remote command an SSH fence runs. It powers the
// host off IMMEDIATELY, not gracefully.
//
// It used to be `systemctl poweroff || poweroff`, which is an orderly shutdown:
// systemctl queues the job and returns 0 at once, and the host then runs its
// stop units — including libvirt-guests, which waits for every VM to shut down
// cleanly. On the lab the fence read "fenced" at 02:25:12 and the host powered
// down at ~02:27:55, with its VM running throughout. A coordinator that
// rescheduled on that fence started a second copy of a VM that was still
// writing to its disks. A fence has to stop the machine now.
//
//   - `systemctl poweroff --force --force` calls reboot(2) directly, skipping
//     every unit (libvirt-guests included) — the equivalent of pulling power.
//   - `echo o > /proc/sysrq-trigger` is the fallback for a host without
//     systemd: the kernel powers off without involving userspace at all.
//
// The marker is printed FIRST, by the remote shell, so the caller can tell a
// session the power-off killed from one that never ran (see fenceSSH). It is
// assembled by printf so the literal marker never appears in the command text
// itself, which is what ssh would be echoing if anything ever echoed it. The
// one-second pause lets the marker leave the host before the power-off takes
// the network down with it; without it the marker races the kernel and a
// successful fence can read as a failure.
//
// There is no trailing `|| true`. It was once here, and it meant a host whose
// shutdown commands BOTH failed still exited 0, so the fence returned
// Method:"ssh", Success:true for a machine that was still running. That
// success is load-bearing: a coordinator reschedules on it, and a later
// coordinator resumes the reschedule from its record alone (it never proves
// the host off — see Assurance — but it is still authority to recover). When
// both commands here fail, the shell exits non-zero (and not 255: neither
// systemctl nor a failed redirect exits 255), and that is reported as a
// failure.
const sshPowerOffCommand = "printf '%s-%s\\n' litevirt-fence armed; sleep 1; " +
	"systemctl poweroff --force --force || echo o > /proc/sysrq-trigger"

// sshBinary is the ssh client a fence runs. A var only so a test can wrap it.
var sshBinary = "ssh"

// OverrideSSHBinaryForTest makes every SSH fence run path instead of ssh and
// returns the function that restores it. Tests only: a test's stand-in for
// root's own ssh configuration on the legacy path.
func OverrideSSHBinaryForTest(path string) (restore func()) {
	prev := sshBinary
	sshBinary = path
	return func() { sshBinary = prev }
}

// knownHostsProbeTimeout bounds the KnownHostsCommand probe. A var so a test
// can shorten it.
var knownHostsProbeTimeout = 5 * time.Second

// knownHostsOption caches, per ssh binary path, whether the client there
// accepts KnownHostsCommand, together with the identity of the file it was
// asked of (sshClientID). Only a definite answer is cached, and only for that
// file: an openssh-client upgraded in place is asked again, so a fence leaves
// the option out no longer than the old client is there.
var knownHostsOption sync.Map // path → knownHostsAnswer

type knownHostsAnswer struct {
	id        sshClientID
	supported bool
}

// sshClientID identifies the file at an ssh binary's path. A package manager
// renames a new file over the old one (a new inode); a hand copy rewrites it
// (size and mtime).
type sshClientID struct {
	ino         uint64
	size, mtime int64
}

func sshClientIdentity(path string) (sshClientID, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return sshClientID{}, false
	}
	id := sshClientID{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		id.ino = uint64(st.Ino)
	}
	return id, true
}

// knownHostsCommandSupported reports whether bin accepts KnownHostsCommand,
// which OpenSSH added in 8.5. It asks ssh itself (`ssh -G` parses the options
// and connects nowhere) rather than reading a version string a vendor may
// have patched. A client that predates the option rejects it as a "Bad
// configuration option" and exits 255; anything else, including a probe that
// could not run or did not answer in time, answers true, so the pin is never
// loosened on a guess — a client that cannot run cannot fence either way.
// (OpenSSH's "Unsupported option" is a warning on an option it knows and was
// built without, and exits 0: it never reaches the failure branch.)
func knownHostsCommandSupported(ctx context.Context, bin string) bool {
	if p, err := exec.LookPath(bin); err == nil {
		bin = p
	}
	id, known := sshClientIdentity(bin)
	if v, ok := knownHostsOption.Load(bin); ok && known && v.(knownHostsAnswer).id == id {
		return v.(knownHostsAnswer).supported
	}
	pctx, cancel := context.WithTimeout(ctx, knownHostsProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(pctx, bin, "-G", "-F", "/dev/null",
		"-o", "KnownHostsCommand=none", "litevirt-fence-probe")
	// Killed at the deadline, ssh may leave a child holding its output open
	// (a wrapper script): stop waiting for that output soon after.
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	answer := func(supported bool) bool {
		if known {
			knownHostsOption.Store(bin, knownHostsAnswer{id: id, supported: supported})
		}
		return supported
	}
	if err == nil {
		return answer(true)
	}
	if l := strings.ToLower(string(out)); strings.Contains(l, "knownhostscommand") && strings.Contains(l, "bad configuration option") {
		return answer(false)
	}
	return true
}

// sshArgs is the ssh argument list for h's path, ending with the target and
// remote command, and a cleanup for the pinned known_hosts file it writes.
func sshArgs(ctx context.Context, h HostConfig, remote string) (target string, args []string, cleanup func(), err error) {
	cleanup = func() {}
	port := h.SSHPort
	if port == 0 {
		port = 22
	}
	user := h.SSHUser
	if h.SSH.Path == SSHPathManaged {
		// The drop-in covers root only; ssh_user is for the legacy path.
		user = h.SSH.User
	}
	if user == "" {
		user = "root"
	}
	target = fmt.Sprintf("%s@%s", user, h.Address)

	var kh string
	if h.SSH.Path == SSHPathManaged || h.SSH.Path == SSHPathPinned {
		if len(h.SSH.KnownHosts) == 0 || h.SSH.HostKeyAlias == "" {
			return target, nil, cleanup, errors.New("no pinned host key to check the target against")
		}
		f, ferr := os.CreateTemp("", "litevirt-fence-known-hosts-")
		if ferr != nil {
			return target, nil, cleanup, ferr
		}
		kh = f.Name()
		cleanup = func() { os.Remove(kh) }
		if _, werr := f.Write(h.SSH.KnownHosts); werr != nil {
			f.Close()
			cleanup()
			return target, nil, func() {}, werr
		}
		if cerr := f.Close(); cerr != nil {
			cleanup()
			return target, nil, func() {}, cerr
		}
	}

	switch h.SSH.Path {
	case SSHPathManaged:
		// -F /dev/null: root's own ssh configuration — a hand-made fence key,
		// a Host stanza, an agent — plays no part in a managed fence.
		args = []string{"-F", "/dev/null",
			"-i", h.SSH.IdentityFile,
			"-o", "IdentitiesOnly=yes",
			"-o", "IdentityAgent=none",
			"-o", "StrictHostKeyChecking=yes",
			"-o", "UserKnownHostsFile=" + kh,
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "VerifyHostKeyDNS=no",
			"-o", "HostKeyAlias=" + h.SSH.HostKeyAlias,
			"-o", "CheckHostIP=no",
			"-o", "UpdateHostKeys=no",
			"-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no",
			"-o", "ControlMaster=no",
			"-o", "ControlPath=none",
			"-o", "ProxyCommand=none",
			"-o", "ProxyJump=none",
			"-o", "ForwardAgent=no",
			"-o", "ClearAllForwardings=yes",
		}
		// The source address must be the one the target's authorized_keys
		// accepts this key from: on a multi-homed host the default route's
		// would be refused.
		if h.SSH.BindAddress != "" {
			args = append(args, "-o", "BindAddress="+h.SSH.BindAddress)
		}
	case SSHPathPinned:
		// Root's configuration still supplies the identity, so a hand-made
		// fence key keeps working; only the host-key check changes. Options on
		// the command line override root's ssh_config.
		args = []string{
			"-o", "StrictHostKeyChecking=yes",
			"-o", "UserKnownHostsFile=" + kh,
			"-o", "GlobalKnownHostsFile=/dev/null",
		}
		// A KnownHostsCommand or an SSHFP lookup in root's config would add
		// keys to the pin. A client older than OpenSSH 8.5 has no
		// KnownHostsCommand, so root's config cannot set one, and it rejects
		// the option outright: passing it there fails every pinned fence.
		if knownHostsCommandSupported(ctx, sshBinary) {
			args = append(args, "-o", "KnownHostsCommand=none")
		}
		args = append(args,
			"-o", "VerifyHostKeyDNS=no",
			// A multiplexed session never checks a host key: a master
			// connection root's config left open to the address (one that
			// reached the wrong machine) would carry the fence past the pin.
			"-o", "ControlMaster=no",
			"-o", "ControlPath=none",
			"-o", "HostKeyAlias="+h.SSH.HostKeyAlias,
			"-o", "CheckHostIP=no",
			"-o", "UpdateHostKeys=no",
		)
	default:
		args = []string{"-o", "StrictHostKeyChecking=no"}
	}
	args = append(args,
		"-o", "BatchMode=yes",
		// Root's ssh_config (the pinned and legacy paths read it) can set
		// LogLevel QUIET, which hides "Host key verification failed." and
		// would let a host-key mismatch pass for an unreachable host
		// (hostKeyMismatch). ERROR keeps it, and nothing chattier.
		"-o", "LogLevel=ERROR",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout(ctx, 10)),
		// A forced power-off takes the host down without closing the TCP
		// connection, so no FIN or RST ever arrives. Without a keepalive the
		// client waits on a machine that no longer exists until the fence's
		// context kills it — and a killed ssh is not a classifiable result.
		// This bounds that to ~6s and turns it into ssh's own exit 255.
		"-o", "ServerAliveInterval=2",
		"-o", "ServerAliveCountMax=3",
		"-p", fmt.Sprintf("%d", port),
		target,
		remote,
	)
	return target, args, cleanup, nil
}

// fenceSSH powers the host off immediately over SSH (see sshPowerOffCommand).
// If lenient=true, failures are reported as successful (best-effort mode).
//
// h.SSH decides the path, and it is taken as given: a managed or pinned
// failure is never retried down a path with less checking, because whoever
// can break the checked path would otherwise earn the unchecked one.
func fenceSSH(ctx context.Context, h HostConfig, lenient bool) Result {
	path := " [path=" + h.SSH.pathLabel() + "]"
	if h.SSH.Refusal != "" {
		return sshNotAttempted(h, lenient, errors.New(h.SSH.Refusal), "SSH fence refused before dialling"+path)
	}
	remote := sshPowerOffCommand
	if h.SSH.Path == SSHPathManaged {
		remote = h.SSH.Request
	}
	target, args, cleanup, err := sshArgs(ctx, h, remote)
	defer cleanup()
	if err != nil {
		return sshNotAttempted(h, lenient, err, "SSH fence could not start"+path)
	}
	if h.SSH.Path == SSHPathLegacy {
		slog.Warn("fencing host via SSH WITHOUT a pinned host key: it has published no fence SSH row, so a machine "+
			"answering at its address would be powered off in its place. Its row is published once the cluster "+
			"runs release_2026_12_v1; `lv doctor fence` lists every host fenced this way",
			"host", h.Name, "target", target)
	}

	slog.Info("fencing host via SSH", "host", h.Name, "target", target, "lenient", lenient, "path", h.SSH.pathLabel())

	cmd := exec.CommandContext(ctx, sshBinary, args...)
	out, runErr := cmd.CombinedOutput()
	armed := sawFenceArmed(out)
	detail := fmt.Sprintf("SSH forced poweroff to %s: %s%s", target, remoteOutput(out), path)

	// Classification. A success requires the marker, always: it is the only
	// evidence that OUR command ran on the target. An exit 0 without it means
	// something else answered — e.g. an authorized_keys forced command.
	//
	//   - exit 0 + marker: the command returned success (in practice the sysrq
	//     write, whose power-off lands just after the shell exits).
	//   - exit 255 + marker: the connection died AFTER the remote shell had
	//     started the forced power-off. This is the normal signature of a
	//     fence that worked, because `systemctl poweroff --force --force` never
	//     returns: the host is gone before any exit status can be sent, and
	//     ServerAliveInterval turns the silence into ssh's 255. It is classified
	//     as a SUCCESS — reported exactly like the exit 0 the old graceful
	//     command produced, i.e. "requested" assurance, which already means
	//     nobody checked the host went down. Reading it as a failure instead
	//     would make every working SSH fence strand its host's VMs.
	//
	//     The residual risk is a connection that drops for an unrelated reason
	//     in the one second between the marker and the power-off, followed by
	//     BOTH power-off commands failing. That needs a coincident network
	//     failure and a host that cannot power itself off; it is accepted.
	//   - exit 255 without the marker: ssh never got our command running
	//     (unreachable, refused, auth failed, dropped before the shell ran).
	//     Not a fence.
	//   - any other non-zero status: the remote shell ran and both power-off
	//     commands failed. Not a fence — this is the `|| true` case.
	//   - killed by the context: not a fence, marker or not. With the keepalive
	//     above this needs the fence budget to run out first, and an unfinished
	//     call is not evidence the host went down.
	switch {
	case runErr == nil && armed:
		return Result{Method: "ssh", Detail: detail, Success: true, Path: h.SSH.pathLabel()}
	case armed && sshExitCode(runErr) == 255:
		return Result{
			Method:  "ssh",
			Detail:  detail + " (connection lost after the forced power-off was issued)",
			Success: true,
			Path:    h.SSH.pathLabel(),
		}
	}
	// A marker the host printed is the host's shell running: it answered,
	// whatever became of the session after (a power-off hung in
	// device_shutdown with the NIC still up, killed by the context).
	answered := armed || sshAnswered(runErr, out)
	if runErr == nil {
		runErr = errors.New("remote command exited 0 without confirming it ran")
	}
	return sshFailure(h, lenient, runErr, answered, detail, out)
}

// sshNotAttempted is an SSH fence that was never sent: its path was refused,
// or ssh could not be started. It is a failure under every strategy,
// best-effort included. best-effort's assumed success stands for an attempt
// that may have landed; one never made cannot have, and counting it fenced
// would recover the host's workloads while they may still run there. The
// detail names the ways out, because no retry can succeed until one is taken
// or the refusal clears.
func sshNotAttempted(h HostConfig, lenient bool, why error, detail string) Result {
	method := "ssh"
	if lenient {
		method = "best-effort-ssh"
	}
	slog.Error("SSH fence not attempted, so the host is NOT fenced", "host", h.Name, "lenient", lenient, "error", why)
	detail = fmt.Sprintf("%s (%v); not attempted, so it does not count as a fence", detail, why)
	if way := NotFencedWayOut(h.Name); !strings.Contains(detail, way) {
		detail += ". " + way
	}
	return Result{Method: method, Detail: detail, Path: h.SSH.pathLabel()}
}

// NotFencedWayOut is what an operator does about a host no fence reached:
// confirm it off by hand, or give it a fence that does not need its sshd.
func NotFencedWayOut(host string) string {
	return fmt.Sprintf("Power %s off and run `lv host fence-confirm %s`, or give it an ipmi or redfish fence strategy "+
		"(`lv host config %s --fence-strategy ipmi|redfish`)", host, host, host)
}

// sshFailure is an SSH fence that ran ssh and did not land. It is a failure
// under every strategy: nothing confirms the host went down. A lenient
// (best-effort) one is marked Dialled, which the failover coordinator counts
// only on the host's own partition pause (Result.Dialled). A host-key mismatch
// is marked WrongHost: another machine answered at the address. One where the
// host's sshd answered (sshAnswered) is marked Answered: the host is
// reachable, so it is not paused for want of a majority.
func sshFailure(h HostConfig, lenient bool, runErr error, answered bool, detail string, out []byte) Result {
	wrong := hostKeyMismatch(out)
	answered = answered && !wrong
	note := wrongHostNote(wrong)
	if answered {
		note = " (the host's sshd answered: it is reachable, so it has not paused for want of a majority)"
	}
	if lenient {
		slog.Warn("best-effort SSH fence did not confirm the power-off; it is not a fence", "host", h.Name,
			"error", runErr, "wrong_host", wrong, "answered", answered)
		return Result{
			Method: "best-effort-ssh",
			Detail: fmt.Sprintf("SSH failed (%v): %s [path=%s]", runErr, remoteOutput(out),
				h.SSH.pathLabel()) + note,
			Dialled:   true,
			WrongHost: wrong,
			Answered:  answered,
			Path:      h.SSH.pathLabel(),
		}
	}
	return Result{Method: "ssh", Detail: fmt.Sprintf("%s (%v)", detail, runErr) + note, WrongHost: wrong,
		Answered: answered, Path: h.SSH.pathLabel()}
}

// sshAnswered reports whether an SSH fence that did not land was answered by
// the host's sshd past the host-key check: the remote shell ran (any exit
// other than ssh's own 255, exit 0 without the marker included), or the
// login was refused (Permission denied). A connection that never got that
// far (exit 255 otherwise), or a call the context killed, is not.
func sshAnswered(runErr error, out []byte) bool {
	if runErr == nil {
		return true
	}
	if strings.Contains(string(out), "Permission denied") {
		return true
	}
	code := sshExitCode(runErr)
	return code != 255 && code != -1
}

func wrongHostNote(wrong bool) string {
	if !wrong {
		return ""
	}
	return " (the host key did not match: a different machine answered at this address)"
}

// hostKeyMismatch reports whether ssh's output says the target's host key did
// not match the pin (or was not in it): what OpenSSH prints when
// StrictHostKeyChecking refuses the key.
func hostKeyMismatch(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "Host key verification failed") ||
		strings.Contains(s, "REMOTE HOST IDENTIFICATION HAS CHANGED")
}

// ProbeSSH checks h's managed path end to end without arming anything: the
// pin, the key, the source address and the target's forced command, which
// answers a check request naming it with CheckOK. It never powers anything
// off: a check is not the poweroff request, and the forced command prints no
// marker for it.
func ProbeSSH(ctx context.Context, h HostConfig, checkOK string) error {
	if h.SSH.Refusal != "" {
		return errors.New(h.SSH.Refusal)
	}
	if h.SSH.Path != SSHPathManaged {
		return fmt.Errorf("%s has no managed fence path", h.Name)
	}
	_, args, cleanup, err := sshArgs(ctx, h, h.SSH.Request)
	defer cleanup()
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, sshBinary, args...).CombinedOutput()
	if sawFenceArmed(out) {
		return fmt.Errorf("the check ARMED a fence on %s: its forced command is not litevirt's", h.Name)
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == checkOK {
			return nil
		}
	}
	return fmt.Errorf("the target answered without %q: %s", checkOK, strings.TrimSpace(string(out)))
}

// sawFenceArmed reports whether out contains the fence marker as a whole line.
func sawFenceArmed(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == sshFenceArmed {
			return true
		}
	}
	return false
}

// sshExitCode returns the process exit status carried by err, or -1 when err
// is not an exit status (e.g. the process was killed by a signal).
func sshExitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// fenceIPMI powers off the host via ipmitool chassis power off.
// Requires ipmitool to be installed on the managing host.
func fenceIPMI(ctx context.Context, h HostConfig) Result {
	if h.IPMIAddress == "" {
		return Result{
			Method:  "ipmi",
			Detail:  "ipmi_address not configured on host",
			Success: false,
		}
	}
	// A retired credential is never sent as an empty password: it means the
	// machine's password went with its removal, not that it has none.
	if h.IPMICredentialRetired {
		return Result{
			Method: "ipmi",
			Detail: "no IPMI password: the host's fence credential was retired when it was removed or re-admitted; " +
				"set it with `lv host config " + h.Name + " --ipmi-pass <secret>`",
			Success: false,
		}
	}
	// A password that was never set is sent empty, as before: a BMC user with
	// a null password authenticates that way. Said so, in the log and in the
	// result, so a failure here can be read for what it is.
	if h.IPMIPass == "" {
		slog.Warn("fencing via IPMI with an empty password (no IPMI password is configured for this host)",
			"host", h.Name, "bmc", h.IPMIAddress)
		r := fenceIPMIRun(ctx, h)
		r.Detail += " (sent with an empty IPMI password: none is configured; set one with `lv host config " +
			h.Name + " --ipmi-pass <secret>` unless the BMC user has none)"
		return r
	}
	return fenceIPMIRun(ctx, h)
}

// fenceIPMIRun is the IPMI power-off and its verification, once the
// preconditions in fenceIPMI hold.
func fenceIPMIRun(ctx context.Context, h HostConfig) Result {
	slog.Info("fencing host via IPMI", "host", h.Name, "bmc", h.IPMIAddress)

	cmd, cancel := ipmitoolCmd(ctx, h, "chassis", "power", "off")
	out, runErr := cmd.CombinedOutput()
	cancel()
	detail := fmt.Sprintf("ipmitool chassis power off %s: %s", h.IPMIAddress, strings.TrimSpace(string(out)))

	if runErr != nil {
		return Result{Method: "ipmi", Detail: fmt.Sprintf("%s (%v)", detail, runErr), Success: false}
	}

	// The power-off command returning 0 means the BMC ACCEPTED the request, not
	// that the chassis is down. Only the polled status proves the host cannot
	// still be writing to shared storage, so an unconfirmed fence is a failure.
	verified, verifyErr := verifyIPMIPowerOff(ctx, h)
	if !verified {
		slog.Warn("IPMI fence sent but power-off not confirmed",
			"host", h.Name, "within", PowerOffVerifyTimeout, "error", verifyErr)
		return Result{
			Method: "ipmi",
			Detail: fmt.Sprintf("%s (power-off not confirmed within %s: %v)",
				detail, PowerOffVerifyTimeout, verifyErr),
			Success: false,
		}
	}

	return Result{Method: "ipmi", Detail: detail, Success: true}
}

// ipmitoolPerCallTimeout bounds ONE ipmitool invocation. Without it a BMC that
// accepts the TCP connection and then stops answering hangs the call for as
// long as the caller's context allows — during a fence that is the whole
// failover budget spent on a single unresponsive controller.
const ipmitoolPerCallTimeout = 8 * time.Second

// The power-off verification budget. These are vars rather than consts ONLY so
// tests can shrink them; nothing in production reassigns them.
var (
	// PowerOffVerifyTimeout is the total wall-clock budget for confirming the
	// chassis is off, across however many polls fit inside it.
	PowerOffVerifyTimeout = 15 * time.Second
	powerOffPollInterval  = 2 * time.Second
)

// WorstCasePowerOff is the longest a single fenceIPMI or fenceRedfish call can
// legitimately take: the power-off command's own per-call budget plus the full
// verification budget, which runs after it. (A Redfish fence splits the
// per-call budget between the request phase and its session logout, so the
// same figure bounds it.) A caller that bounds a fence by less than this
// converts a slow-but-successful power-off into an UNCONFIRMED one — the
// chassis goes down, the context expires mid-verify, and the result is reported
// as a failed fence, so the VMs on that host are never rescheduled.
//
// A function, not a constant, because PowerOffVerifyTimeout is a var that tests
// shrink; anything deriving a budget from it must see the same value the fence
// will actually spend.
func WorstCasePowerOff() time.Duration {
	return ipmitoolPerCallTimeout + PowerOffVerifyTimeout
}

// chassisPowerOff is ipmitool's power-status line for a chassis that is off,
// lowercased. Matched as a SUFFIX, never as a substring — see isChassisOff.
const chassisPowerOff = "chassis power is off"

// ipmitoolCmd builds one ipmitool invocation against h's BMC, with the password
// passed through the environment instead of argv.
//
// `-P <pass>` puts the BMC password in the process table, where every local
// user can read it off `ps` for the lifetime of the call. `-E` makes ipmitool
// read it from the environment instead, which is not world-readable.
//
// Both IPMI_PASSWORD and IPMITOOL_PASSWORD are set to the same value on
// purpose. Under `-E` ipmitool PREFERS IPMITOOL_PASSWORD, so setting only
// IPMI_PASSWORD would let a value inherited from the daemon's own environment
// silently override the per-host credential — every fence would then
// authenticate with the wrong password and fail closed cluster-wide.
//
// `-N 1 -R 2` bounds the RMCP retry behaviour so an unreachable BMC fails in
// about a second instead of sitting in ipmitool's default retry loop; the
// returned CancelFunc must be called by the caller to release the timeout.
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
	// SIGTERM first so ipmitool can close its RMCP session; SIGKILL follows if
	// it ignores that. Without WaitDelay a wedged child keeps the pipes open and
	// Output() blocks past the timeout it was supposed to enforce.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	return cmd, cancel
}

// verifyIPMIPowerOff polls "chassis power status" until the BMC reports the
// chassis off, the budget expires, or ctx is done.
//
// It returns (true, nil) ONLY on a positive, anchored power-off reading. Any
// other outcome returns false plus the last substantive READING — the BMC said
// the chassis is still on, or the BMC refused, or it never answered — so the
// caller can record WHY it could not confirm. Those are very different facts
// about a host that may still be writing to shared storage, and the old bool
// return collapsed them into one indistinguishable false.
//
// "Substantive" excludes a call this function's own budget killed: that error is
// "signal: terminated", which describes our timeout rather than the BMC, and
// letting it win would erase the reading it interrupted. Reporting the earlier
// reading is deliberate, so a caller must not read the returned error as
// describing the FINAL attempt. When no reading landed at all, the error says
// exactly that.
func verifyIPMIPowerOff(ctx context.Context, h HostConfig) (bool, error) {
	vctx, cancel := context.WithTimeout(ctx, PowerOffVerifyTimeout)
	defer cancel()

	lastErr := errors.New("no power-status reading was taken")
	for {
		// Checked at the top so an already-expired budget cannot slip one more
		// ipmitool call past the deadline.
		if vctx.Err() != nil {
			return false, lastErr
		}

		started := time.Now()
		cmd, cancelCall := ipmitoolCmd(vctx, h, "chassis", "power", "status")
		out, err := cmd.Output()
		cancelCall()

		switch {
		case err != nil:
			// A call OUR OWN budget killed is not a reading, and must not
			// overwrite one. cmd.Output() reports the SIGTERM as "signal:
			// terminated", which carries neither the exit status nor the BMC's
			// stderr — so letting it win replaces the operator's only
			// explanation of why the power-off was unconfirmed with a
			// description of our timeout. fencing_log.detail is where that
			// explanation is read, when deciding whether to run
			// `lv host fence-confirm` on a host that may still be running.
			//
			// Whichever substantive reading came before is the one worth
			// keeping. If none did, lastErr still says no reading was taken,
			// which is both true and more use than the signal name.
			if vctx.Err() != nil {
				return false, lastErr
			}
			lastErr = ipmitoolError(err)
		case isChassisOff(out):
			return true, nil
		default:
			lastErr = fmt.Errorf("chassis not off: %q", strings.TrimSpace(string(out)))
		}

		// Pace from the START of the attempt, not its end: a call that already
		// spent the interval should poll again immediately rather than adding
		// another interval on top and wasting the budget.
		if wait := powerOffPollInterval - time.Since(started); wait > 0 {
			select {
			case <-vctx.Done():
				return false, lastErr
			case <-time.After(wait):
			}
		}
	}
}

// isChassisOff reports whether out is ipmitool's power-status line for an off
// chassis.
//
// The match is anchored at the end of the trimmed output. A substring search
// for "off" — which is what this used to do — reads as confirmed power-off on
// text that says nothing of the kind: an authentication failure mentioning
// "Set Session Privilege Level failed", a "Powering off" transitional line, or
// any BMC banner containing those three letters. Confirming a fence that never
// happened is the one error this function must not make: it is the last check
// between a live host and another node starting its VMs on the same disks.
func isChassisOff(out []byte) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(string(out))), chassisPowerOff)
}

// ipmitoolError folds a failed run's stderr into the returned error. exec's
// ExitError prints only "exit status 1", which tells an operator reading the
// fence log nothing about whether the BMC refused the credentials, was
// unreachable, or rejected the command.
func ipmitoolError(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if msg := strings.TrimSpace(string(ee.Stderr)); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
	}
	return err
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
