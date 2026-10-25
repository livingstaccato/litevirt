package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// binaryVersion runs `<path> --version` and returns the stamped version (the
// token after "version=" in the output), or "" if the binary can't be probed
// (e.g. a cross-arch binary that won't exec locally). Used so the upgrade
// "outdated" check compares each host to the version we're about to deploy —
// not to the connected daemon's running version, which would no-op on a
// version-uniform cluster.
func binaryVersion(ctx context.Context, path string) string {
	// A probe runs once before an upgrade, and treating scheduler delay as
	// "unprobeable" silently turns a real rollout into "already up-to-date".
	// Leave enough headroom for a busy virtualization host.
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(string(out)) {
		if v, ok := strings.CutPrefix(f, "version="); ok {
			return v
		}
	}
	return ""
}

// UpgradeOpts configures a rolling host upgrade.
type UpgradeOpts struct {
	BinaryPath string   // path to new litevirtd binary
	HostNames  []string // empty = all outdated hosts
	Yes        bool     // skip confirmation prompt
	Force      bool     // skip preflight blocks (warnings still printed)
	NoPreStage bool     // skip the cluster-wide schema pre-stage pass
	// SkipPreStage names members outside the upgrade that are down: each is
	// pre-staged if it answers, and otherwise left behind with a warning.
	SkipPreStage []string
}

// checkSkipPreStage refuses --skip-prestage without the pre-stage pass, and
// a name that is not a member this upgrade would pre-stage without swapping:
// a target is always pre-staged before its swap, and a member already on the
// binary's build is neither swapped nor pre-staged.
func checkSkipPreStage(opts UpgradeOpts, hosts, targets, others []*pb.Host) error {
	if len(opts.SkipPreStage) == 0 {
		return nil
	}
	if opts.NoPreStage {
		return fmt.Errorf("--skip-prestage has no effect with --no-prestage, which pre-stages no host; pass one or the other")
	}
	find := func(list []*pb.Host, name string) *pb.Host {
		for _, h := range list {
			if h.Name == name {
				return h
			}
		}
		return nil
	}
	for _, n := range opts.SkipPreStage {
		h := find(hosts, n)
		switch {
		case h == nil:
			return fmt.Errorf("--skip-prestage %s: %s is not a member (lv host ls)", n, n)
		case find(targets, n) != nil:
			return fmt.Errorf("--skip-prestage %s: %s is a target of this upgrade; only a member outside it can be skipped", n, n)
		case find(others, n) == nil:
			return fmt.Errorf("--skip-prestage %s: %s already runs %s, the binary's version, so this upgrade neither swaps nor pre-stages it",
				n, n, versionLabel(h.Version))
		}
	}
	return nil
}

// sameBuild reports whether a member running version runs the build probed
// from the binary. Only a version that names one commit says so: not an
// unprobed binary, not "dev", and not a -dirty tree.
func sameBuild(probed, version string) bool {
	if probed == "" || probed == "dev" || strings.HasSuffix(probed, "-dirty") {
		return false
	}
	return version == probed
}

func skipSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// hostResult tracks the outcome of upgrading a single host.
type hostResult struct {
	Name       string
	Address    string
	OldVersion string
	NewVersion string
	Status     string // "ok", "skipped", "error"
	Error      string
}

// HostUpgrade performs a rolling upgrade of litevirtd across cluster hosts.
//
// The binary at opts.BinaryPath (local to the machine running `lv`) is pushed
// to every target host via SSH. This works whether `lv` runs on a dev laptop
// (remote mode via LV_HOST) or directly on a cluster node (local mode).
//
// When running in local mode the connected host is upgraded last, because
// restarting its daemon kills our gRPC connection. The SSH session for the
// self-upgrade still completes — only the post-upgrade gRPC Ping check is
// skipped (systemctl verification is sufficient).
func HostUpgrade(ctx context.Context, client pb.LiteVirtClient, opts UpgradeOpts) error {
	// Verify the binary exists and is executable.
	info, err := os.Stat(opts.BinaryPath)
	if err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a binary", opts.BinaryPath)
	}

	// Identify the host we're connected to (so we can upgrade it last).
	pingResp, _ := client.Ping(ctx, &pb.PingRequest{})
	connectedHost := ""
	if pingResp != nil {
		connectedHost = pingResp.HostName
	}

	// The target is the version of the binary we're distributing — probe it
	// directly. Using the connected daemon's running version instead would
	// make no-arg `lv host upgrade --binary X` a no-op on a version-uniform
	// cluster (every host matches the connected daemon, so nothing looks
	// "outdated", even though X is newer). Fall back to the connected daemon's
	// version only if the binary can't be probed (e.g. cross-arch).
	probedVersion := binaryVersion(ctx, opts.BinaryPath)
	targetVersion := probedVersion
	if targetVersion == "" && pingResp != nil {
		targetVersion = pingResp.Version
	}

	if len(opts.HostNames) == 0 && probedVersion == "" {
		// All-hosts mode picks the outdated hosts by the binary's version.
		// The connected daemon's says nothing about the binary: a member on
		// it would be skipped, neither swapped nor pre-staged, while the
		// others moved to the binary's schema. Refuse before anything is
		// probed, pre-staged or swapped.
		return fmt.Errorf("cannot tell which hosts are outdated: the version of %s could not be read "+
			"(`%s --version` did not run here, e.g. a binary built for another architecture); "+
			"check the path given to --binary, or name the hosts to upgrade (lv host upgrade <host>...), "+
			"which pre-stages the schema on every other member",
			opts.BinaryPath, opts.BinaryPath)
	}

	// List all hosts.
	resp, err := client.ListHosts(ctx, nil)
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	if len(resp.Hosts) == 0 {
		fmt.Println("No hosts in cluster.")
		return nil
	}

	// Filter to hosts that need upgrading.
	filterSet := make(map[string]bool)
	for _, n := range opts.HostNames {
		filterSet[n] = true
	}
	named := len(filterSet) > 0

	var remoteTargets []*pb.Host // other hosts — upgraded first
	var selfTarget *pb.Host      // the connected host — upgraded last
	var others []*pb.Host        // members left on their binary — pre-staged only

	for _, h := range resp.Hosts {
		// Current only when the version names one build: never dev or -dirty.
		current := sameBuild(targetVersion, h.Version)
		if named && !filterSet[h.Name] {
			// A member already on the version of the binary has its schema.
			// Only a probed version says so: the connected daemon's says
			// nothing about the binary, so without one every member is
			// pre-staged.
			if !sameBuild(probedVersion, h.Version) {
				others = append(others, h)
			}
			continue
		}
		// In "all" mode, skip hosts already on the target (the --binary's)
		// version. An explicitly-named host is ALWAYS (re)deployed: the
		// operator asked for it (e.g. re-seeding the same version after a
		// manual change), so a version match must not silently skip it — that
		// no-op once forced the unsafe bare-restart workaround. See
		// docs/upgrades.md.
		if !named && current {
			continue
		}
		if h.Name == connectedHost {
			selfTarget = h
		} else {
			remoteTargets = append(remoteTargets, h)
		}
	}

	// Build ordered list: remote hosts first, connected host last.
	targets := remoteTargets
	if selfTarget != nil {
		targets = append(targets, selfTarget)
	}

	if err := checkSkipPreStage(opts, resp.Hosts, targets, others); err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("All hosts are up-to-date.")
		return nil
	}

	if err := checkFenceSSHModes(ctx, client, targets); err != nil {
		return err
	}

	// Print upgrade plan.
	fmt.Printf("Upgrade plan: %d host(s) → %s\n\n", len(targets), versionLabel(targetVersion))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  HOST\tADDRESS\tCURRENT\tNOTE\n")
	for _, h := range targets {
		note := ""
		if h.Name == connectedHost {
			note = "(connected — upgraded last)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", h.Name, h.Address, versionLabel(h.Version), note)
	}
	tw.Flush()
	if len(others) > 0 && !opts.NoPreStage {
		names := make([]string, len(others))
		for i, h := range others {
			names[i] = h.Name
		}
		fmt.Printf("\n  schema also pre-staged, binary unchanged: %s\n", strings.Join(names, ", "))
		if probedVersion == "" {
			fmt.Println("  (the binary's version could not be probed, so every member is pre-staged)")
		}
	}
	fmt.Println()

	// Confirm unless --yes.
	if !opts.Yes {
		ok, err := Confirm(ctx, os.Stdin, os.Stdout, "Proceed?")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Phase 1 — pre-stage schema on every member BEFORE swapping any binary:
	// the targets, and every member this upgrade leaves on its binary, which
	// would otherwise refuse each push from an upgraded target.
	// This streams the new binary to each host and runs its `schema-migrate`
	// against the live state.db (safe: WAL + busy-timeout, idempotent). After
	// this pass every node's DB has the new schema, so the rolling restart in
	// phase 2 never produces a peer that's missing columns — which is the only
	// thing that makes a multi-version rolling upgrade unsafe. Targets on older
	// daemons without the PreStageUpgrade RPC report Unimplemented and are
	// skipped (they migrate themselves on restart; single-version skew
	// self-heals). Every member is probed first, and a member that cannot be
	// pre-staged refuses the upgrade with nothing pre-staged, unless
	// --skip-prestage names it.
	if !opts.NoPreStage {
		if err := preStageSchema(ctx, client, targets, others, opts.BinaryPath, skipSet(opts.SkipPreStage)); err != nil {
			return err
		}
	}

	// Phase 2 — upgrade each host sequentially (swap + re-exec).
	results := make([]hostResult, 0, len(targets))
	for i, h := range targets {
		isSelf := h.Name == connectedHost
		label := ""
		if isSelf {
			label = " (self)"
		}
		fmt.Printf("[%d/%d] Upgrading %s (%s)%s...\n", i+1, len(targets), h.Name, h.Address, label)
		res := upgradeOneHost(ctx, client, h, opts.BinaryPath, targetVersion, opts.Force)
		results = append(results, res)
		if res.Status == "ok" {
			fmt.Printf("  done: %s upgraded to %s\n", h.Name, versionLabel(res.NewVersion))
		} else {
			fmt.Fprintf(os.Stderr, "  FAILED: %s: %s\n", h.Name, res.Error)
		}
	}

	// Print summary.
	fmt.Println("\n--- Upgrade Summary ---")
	tw = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "HOST\tOLD\tNEW\tSTATUS\n")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			r.Name, versionLabel(r.OldVersion), versionLabel(r.NewVersion), r.Status)
	}
	tw.Flush()

	// Check for failures.
	var failures int
	for _, r := range results {
		if r.Status == "error" {
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d host(s) failed to upgrade", failures)
	}
	return nil
}

// HostPreflightUpgrade reports, on w, what would block or warn an upgrade of
// host to this build, without performing it: the daemon's preflight
// findings, and the same enforcement.fence_ssh check `lv host upgrade` runs
// (checkFenceSSHModes), which a daemon on the old build cannot make for the
// new one. It returns an error when either blocks.
func HostPreflightUpgrade(ctx context.Context, client pb.LiteVirtClient, host string, w io.Writer) error {
	resp, err := client.PreflightUpgrade(ctx, &pb.PreflightUpgradeRequest{TargetHost: host})
	if err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if resp.Host != "" {
		host = resp.Host
	}
	blocking := 0
	for _, f := range resp.Findings {
		if f.Severity == "block" {
			blocking++
		}
	}
	findings := slices.Clone(resp.Findings)
	if ferr := checkFenceSSHModes(ctx, client, []*pb.Host{{Name: host}}); ferr != nil {
		findings = append(findings, &pb.PreflightFinding{Severity: "block", Code: "fence_ssh_legacy", Message: ferr.Error()})
		blocking++
	}
	if len(findings) == 0 {
		fmt.Fprintf(w, "Host %s: no findings, upgrade is safe.\n", host)
		return nil
	}
	fmt.Fprintf(w, "Host %s preflight findings:\n", host)
	for _, f := range findings {
		fmt.Fprintf(w, "  [%s] %s: %s\n", f.Severity, f.Code, f.Message)
	}
	if !resp.Ok || blocking > 0 {
		return fmt.Errorf("upgrade blocked by %d finding(s)", blocking)
	}
	return nil
}

// checkFenceSSHModes is fencessh.CheckUpgradeModes for this upgrade's
// targets: it refuses while any member, target or not, still reports
// enforcement.fence_ssh: legacy, and prints what it could not read.
func checkFenceSSHModes(ctx context.Context, client pb.LiteVirtClient, targets []*pb.Host) error {
	names := make([]string, 0, len(targets))
	for _, h := range targets {
		names = append(names, h.Name)
	}
	warnings, err := fencessh.CheckUpgradeModes(ctx, client, names)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning: "+w)
	}
	return err
}

func upgradeOneHost(ctx context.Context, client pb.LiteVirtClient, h *pb.Host, binaryPath, targetVersion string, force bool) hostResult {
	res := hostResult{
		Name:       h.Name,
		Address:    h.Address,
		OldVersion: h.Version,
	}

	// Read binary and compute checksum.
	fmt.Printf("  streaming binary via gRPC...\n")
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		res.Status = "error"
		res.Error = fmt.Sprintf("read binary: %v", err)
		return res
	}
	checksum := sha256sum(data)

	stream, err := client.UpgradeHost(ctx)
	if err != nil {
		res.Status = "error"
		res.Error = fmt.Sprintf("open upgrade stream: %v", err)
		return res
	}

	// Send first chunk with metadata.
	const chunkSize = 64 * 1024
	first := &pb.UpgradeHostRequest{
		Checksum:   checksum,
		TargetHost: h.Name,
		Force:      force, // server-side preflight blocks are only skippable when this is set
	}
	if len(data) > chunkSize {
		first.Chunk = data[:chunkSize]
		data = data[chunkSize:]
	} else {
		first.Chunk = data
		data = nil
	}
	if err := stream.Send(first); err != nil {
		res.Status = "error"
		res.Error = upgradeErrorHint(fmt.Sprintf("send first chunk: %v", err))
		return res
	}

	// Send remaining chunks.
	for len(data) > 0 {
		end := chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&pb.UpgradeHostRequest{Chunk: data[:end]}); err != nil {
			res.Status = "error"
			res.Error = upgradeErrorHint(fmt.Sprintf("send chunk: %v", err))
			return res
		}
		data = data[end:]
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		res.Status = "error"
		res.Error = upgradeErrorHint(fmt.Sprintf("upgrade failed: %v", err))
		return res
	}

	res.Status = resp.Status
	res.NewVersion = resp.NewVersion
	if resp.Error != "" {
		res.Error = resp.Error
	}
	if res.NewVersion == "" {
		res.NewVersion = targetVersion
	}
	return res
}

// upgradeErrorHint appends a hint when the error looks like the remote daemon
// doesn't support the UpgradeHost RPC (e.g. first upgrade from an older build).
func upgradeErrorHint(msg string) string {
	if strings.Contains(msg, "EOF") || strings.Contains(msg, "Unimplemented") {
		return msg + " (host may be running an older daemon without gRPC upgrade support — deploy the new binary manually with scp + systemctl restart)"
	}
	return msg
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func versionLabel(v string) string {
	if v == "" {
		return "(unknown)"
	}
	return v
}
