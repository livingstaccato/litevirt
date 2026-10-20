package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// HostRemove takes a host out of the cluster and revokes the certificate it holds.
//
// Removal used to be a tombstone and nothing else. The row is soft-deleted, the
// certificate serial is logged, and the certificate itself keeps chaining to the
// cluster CA — so whether a decommissioned node can still act as a peer depends
// entirely on that tombstone reaching every other node. One node that never
// receives it goes on accepting the removed host, and nothing reports the fact.
//
// That was survivable while peer trust required a live host row, because an
// unreplicated row meant "not a peer" anyway. It is not survivable now that trust
// falls back to the certificate for a host with no row — the fallback that lets a
// fresh cluster form. The two changes have to land together: absent means trust the
// certificate, so the certificate has to stop being trustworthy.
//
// The CRL is that second mechanism and every piece of it already existed —
// pki.AppendToCRL, a crl.pem each daemon re-reads when its mtime changes, and a
// health check that publishes every node's CRL version and warns on a mismatch.
// Nothing called them, and nothing carried the CRL between nodes.
//
// It is carried by replication now, like every other cluster fact. Minting it
// still happens here because it has to: revoking a certificate means signing with
// the cluster CA's private key, which lives with the operator and never on a
// daemon. So this command produces the CRL and PublishCRL hands it to the cluster.
func HostRemove(ctx context.Context, c pb.LiteVirtClient, hostName string, force bool) error {
	return hostRemove(ctx, c, hostName, force, "")
}

// hostRemove is HostRemove of the row of hostName, refused before anything
// is revoked unless that row holds certificate want ("" for any).
func hostRemove(ctx context.Context, c pb.LiteVirtClient, hostName string, force bool, want string) error {
	// A current voter keeps its vote whatever its hosts row says, so the daemon
	// refuses to remove one. Ask BEFORE revoking: the revocation below is not
	// undone by that refusal, and a revoked voter can no longer sign a vote.
	if err := refuseVoterRemoval(ctx, c, hostName); err != nil {
		return err
	}
	listed := listedHost(ctx, c, hostName)
	// Read and revoke BEFORE the tombstone. Once RemoveHost succeeds, ListHosts
	// deliberately hides the row and there is no supported way to recover its
	// certificate serial. A mint or publish failure must therefore leave the row
	// intact so the operator can repair the cause and retry this command.
	serial, version, err := revokeAndPublish(ctx, c, &pb.RemoveHostRequest{Name: hostName, Force: force, ExpectedCertSerial: want})
	if err != nil {
		return err
	}

	// Close the host's audit signing contract while removal still has the CA
	// key in hand — this command already runs on the only machine that can
	// sign a retirement. Left open, the published certificate keeps declaring
	// "this host's rows are signed": every unsigned row it ever wrote reads as
	// tampering on every node, and a later re-admission under the same name
	// starts life permanently TAMPERED (its fresh key can't resume the old
	// contract). Best-effort by design: the CRL above is the security
	// boundary, and a retirement that cannot complete right now stays
	// available as `lv host retire-audit-key`.
	closeRemovedHostAuditContract(ctx, c, hostName)

	rerun := "lv host rm " + hostName
	if force {
		rerun = "lv host rm --force " + hostName
	}
	if want != "" {
		rerun += " --serial " + want
	}
	removed, err := removeAfterRevoke(ctx, c, &pb.RemoveHostRequest{Name: hostName, Force: force, ExpectedCertSerial: serial}, rerun)
	if err != nil {
		return err
	}
	printRemoved(hostName, removed, "Host %s removed from cluster.\n")
	fmt.Printf("  revoked certificate %s in CRL %d before removing the host\n", serial, version)
	fmt.Println("  `lv health` warns for as long as any peer's CRL version is behind another's")
	// A joining host is often an add stranded after its admission, which left
	// the admitted (now revoked) pair staged on the machine for a rerun.
	// Its cleanup is part of the removal: one that fails is reported as
	// unfinished, with the command that finishes it (the row is gone, so
	// it selects the admission by serial).
	if listed != nil && listed.GetState() == pb.HostState_HOST_JOINING && listed.GetAddress() != "" {
		if err := removeStagedAdmission(listed.GetAddress(), serial); err != nil {
			if !settleName(hostName) {
				// `lv host rm` with no row refuses this name: no command is
				// printed that would only be refused.
				return fmt.Errorf("%s is removed and its certificate %s revoked, but removing what its unfinished "+
					"`lv host add` left on %s failed (%v). Its name is not one `lv host rm --serial` takes: check that "+
					"machine for the files tagged .add-%s- and an install record %s of certificate %s", strconv.Quote(hostName),
					canonOr(serial), listed.GetAddress(), err, canonOr(serial), addInstalledMarker, canonOr(serial))
			}
			return fmt.Errorf("%s is removed and its certificate %s revoked, but removing what its unfinished "+
				"`lv host add` left on %s failed (%v). Run `%s` to finish it",
				hostName, canonOr(serial), listed.GetAddress(), err, settleRmCmd(hostName, serial, listed.GetAddress()))
		}
	}
	return nil
}

// settleRmCmd is `lv host rm <host> --serial <serial> [--address <addr>]`,
// each word shell-safe.
func settleRmCmd(hostName, serial, addr string) string {
	cmd := fmt.Sprintf("lv host rm %s --serial %s", shellWord(hostName), shellWord(canonOr(serial)))
	if addr != "" {
		cmd += " --address " + shellWord(addr)
	}
	return cmd
}

// canonOr is serial's canonical form, or serial when it is not one.
func canonOr(serial string) string {
	if c := canonSerial(serial); c != "" {
		return c
	}
	return serial
}

// listedHost is hostName's ListHosts entry, or nil when it cannot be read.
func listedHost(ctx context.Context, c pb.LiteVirtClient, hostName string) *pb.Host {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return nil
	}
	for _, h := range resp.GetHosts() {
		if h.GetName() == hostName {
			return h
		}
	}
	return nil
}

// HostRemoveDead is `lv host rm --dead <host>` (docs/design/recovery-claims.md
// §3.12): the one command that turns a host that is fenced and gone for good
// into supersede evidence for every recovery decided for it. In order:
//
//  1. refuse unless the host is fenced proof-grade, naming the fence command;
//  2. if it is a member of the adopted voter generation, remove it first
//     through `lv cluster voter rm` (seal and transfer) — and if no majority of
//     the generation is reachable, stop and name force-reconfigure;
//  3. remove the host as `lv host rm` does, including the CRL publication;
//     its workloads stay in place for the recovery claims to supersede;
//  4. report how many stranded recoveries will now retry, naming each.
//
// dryRun runs every check and prints the same plan and count without
// changing anything. There is no command that asserts a decision away: an
// operator only removes the host the decision named.
func HostRemoveDead(ctx context.Context, c pb.LiteVirtClient, hostName string, dryRun bool) error {
	plan, err := c.PlanDeadHostRemoval(ctx, &pb.PlanDeadHostRemovalRequest{Name: hostName})
	if err != nil {
		return fmt.Errorf("plan the removal of %s: %w", hostName, err)
	}
	printDeadRemovalPlan(plan)
	if !plan.GetFenced() {
		return fmt.Errorf("%s is not fenced proof-grade (%s): power it off, then run `%s` — `lv host rm --dead` "+
			"removes only a host proven off", hostName, orDash(plan.GetFenceDetail()), plan.GetFenceCommand())
	}
	if dryRun && plan.GetVoter() {
		// The daemon refuses to remove a voter's host, so its preflight can
		// only answer once the real run has removed the vote.
		fmt.Println("  removal check: runs after the voter removal, so not in a dry run")
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if dryRun {
		// Ask the daemon whether it would make the removal, as the real run
		// does before it revokes, so the plan is not one it would refuse.
		serial, err := hostCertSerial(ctx, c, hostName)
		if err != nil {
			return fmt.Errorf("read %s's certificate serial: %w", hostName, err)
		}
		pre := &pb.RemoveHostRequest{Name: hostName, Dead: true, ExpectedCertSerial: serial}
		if _, err := c.PreflightRemoveHost(ctx, pre); err != nil && status.Code(err) != codes.Unimplemented {
			return fmt.Errorf("the removal of %s would be refused: %w", hostName, err)
		}
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if plan.GetVoter() {
		if _, err := c.ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: hostName}); err != nil {
			if status.Code(err) == codes.Unavailable {
				return fmt.Errorf("remove %s from voter generation %d: %w\nno majority of the generation is reachable; "+
					"if a majority of the voters is gone for good, fence each lost host and run "+
					"`lv cluster voter force-reconfigure --lost %s,...`", hostName, plan.GetVoterGeneration(), err, hostName)
			}
			return fmt.Errorf("remove %s from voter generation %d: %w", hostName, plan.GetVoterGeneration(), err)
		}
		fmt.Printf("  removed %s from the voter set (it was a member of generation %d)\n", hostName, plan.GetVoterGeneration())
	}
	serial, version, err := revokeAndPublish(ctx, c, &pb.RemoveHostRequest{Name: hostName, Dead: true})
	if err != nil {
		return err
	}
	closeRemovedHostAuditContract(ctx, c, hostName)
	removed, err := removeAfterRevoke(ctx, c, &pb.RemoveHostRequest{Name: hostName, Dead: true, ExpectedCertSerial: serial},
		"lv host rm --dead "+hostName)
	if err != nil {
		return err
	}
	printRemoved(hostName, removed, "Host %s removed from the cluster for good.\n")
	fmt.Printf("  revoked certificate %s in CRL %d before removing the host\n", serial, version)
	n := 0
	for _, s := range plan.GetStranded() {
		if s.GetNextAttempt() > 0 {
			n++
		}
	}
	fmt.Printf("  %d stranded recover%s will now retry at the next claim attempt, once the removal and the CRL have replicated\n",
		n, map[bool]string{true: "y", false: "ies"}[n == 1])
	return nil
}

func printDeadRemovalPlan(plan *pb.PlanDeadHostRemovalResponse) {
	fmt.Printf("Removing %s for good (state %s):\n", plan.GetHost(), plan.GetHostState())
	if plan.GetFenced() {
		fmt.Printf("  fence:   %s\n", plan.GetFenceDetail())
	} else {
		fmt.Printf("  fence:   NONE proof-grade — run `%s` once it is powered off\n", plan.GetFenceCommand())
	}
	if plan.GetVoter() {
		fmt.Printf("  voter:   a member of generation %d; removed first with `lv cluster voter rm %s`\n",
			plan.GetVoterGeneration(), plan.GetHost())
	} else {
		fmt.Println("  voter:   not a member of the adopted voter generation")
	}
	fmt.Println("  certificate revoked and the CRL published, then the host row removed")
	retry := 0
	for _, s := range plan.GetStranded() {
		if s.GetNextAttempt() > 0 {
			retry++
		}
	}
	fmt.Printf("  stranded recoveries that will retry: %d\n", retry)
	for _, s := range plan.GetStranded() {
		fmt.Printf("    %s\n", s.GetDetail())
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// removeAfterRevoke is RemoveHost once the host's certificate is revoked and
// the CRL published. The preflight passed moments before, so an Unavailable
// now is most likely a voter's link or the currency pull failing for a
// moment: it is retried after each removeRetryBackoff wait, and one that is
// still Unavailable names rerun, which finishes it (the revocation is already
// in place). A NotFound on a retry, for a host no longer listed, is the
// removal itself. Any other refusal is returned at once.
func removeAfterRevoke(ctx context.Context, c pb.LiteVirtClient, req *pb.RemoveHostRequest, rerun string) (*pb.RemoveHostResponse, error) {
	for attempt := 0; ; attempt++ {
		removed, err := c.RemoveHost(ctx, req)
		if err == nil {
			return removed, nil
		}
		// The host was there when this command began, so a NotFound on a
		// retry may be an earlier attempt's removal whose reply was lost. A
		// daemon also answers NotFound when it could not read the row, so
		// the host must be absent from a fresh list to count as removed.
		if attempt > 0 && status.Code(err) == codes.NotFound {
			if _, lerr := hostCertSerial(ctx, c, req.GetName()); errors.Is(lerr, errHostNotListed) {
				fmt.Printf("  %s is no longer in the cluster: an earlier attempt whose reply was lost removed it, "+
					"or another removal did\n", req.GetName())
				return &pb.RemoveHostResponse{}, nil
			}
			return nil, fmt.Errorf("remove host after publishing its certificate revocation: %w\n"+
				"the certificate is revoked; run `%s` to finish the removal", err, rerun)
		}
		if status.Code(err) != codes.Unavailable {
			return nil, fmt.Errorf("remove host after publishing its certificate revocation: %w", err)
		}
		if attempt >= len(removeRetryBackoff) {
			return nil, fmt.Errorf("remove host after publishing its certificate revocation: %w\n"+
				"the certificate is revoked; run `%s` to finish the removal", err, rerun)
		}
		fmt.Printf("  removal unavailable (%v); retrying in %s\n", err, removeRetryBackoff[attempt])
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("remove host after publishing its certificate revocation: %w\n"+
				"the certificate is revoked; run `%s` to finish the removal", ctx.Err(), rerun)
		case <-time.After(removeRetryBackoff[attempt]):
		}
	}
}

// removeRetryBackoff are the waits before each retry of a RemoveHost that
// failed Unavailable after the revocation. A var so tests can shorten it.
var removeRetryBackoff = []time.Duration{10 * time.Second, 20 * time.Second}

// revokeAndPublish revokes the certificate of req's host in this machine's
// CRL, once the daemon has said it would make the removal req asks for, and
// publishes the CRL to the cluster: the part of a removal only the machine
// holding the CA key can do. A request with an ExpectedCertSerial is refused,
// before anything is revoked, unless the host's row holds that certificate.
func revokeAndPublish(ctx context.Context, c pb.LiteVirtClient, req *pb.RemoveHostRequest) (string, int64, error) {
	hostName := req.GetName()
	serial, err := hostCertSerial(ctx, c, hostName)
	if err != nil {
		return "", 0, fmt.Errorf("read %s's certificate serial before removal: %w", hostName, err)
	}
	if want := req.GetExpectedCertSerial(); want != "" && (canonSerial(want) == "" || canonSerial(want) != canonSerial(serial)) {
		return "", 0, fmt.Errorf("%s's row holds certificate %s now, not %s: nothing was revoked or removed", hostName, serial, want)
	}
	// Ask the daemon whether it would remove the host BEFORE revoking: a
	// refusal after the revocation leaves a member cut off from its peers
	// while its row stays live. A daemon from before this check answers
	// Unimplemented, and makes none of the refusals it covers.
	pre := &pb.RemoveHostRequest{Name: hostName, Force: req.GetForce(), Dead: req.GetDead(), ExpectedCertSerial: serial}
	if _, err := c.PreflightRemoveHost(ctx, pre); err != nil && status.Code(err) != codes.Unimplemented {
		return "", 0, fmt.Errorf("refusing to revoke %s's certificate: the removal would be refused: %w", hostName, err)
	}
	if err := revokeHostCert(PKIDir(), hostName, serial); err != nil {
		return "", 0, fmt.Errorf("refusing to remove %s before its certificate is revoked: %w", hostName, err)
	}
	version, err := publishClusterCRL(ctx, c, PKIDir())
	if err != nil {
		return "", 0, fmt.Errorf("refusing to remove %s before its certificate revocation is published: %w",
			hostName, err)
	}
	return serial, version, nil
}

// PublishClusterCRL hands this machine's CRL to the cluster, for `lv host
// publish-crl` — the recovery path when the publish inside `lv host rm` failed.
func PublishClusterCRL(ctx context.Context, c pb.LiteVirtClient) error {
	version, err := publishClusterCRL(ctx, c, PKIDir())
	if err != nil {
		return fmt.Errorf("publish %s to the cluster: %w", filepath.Join(PKIDir(), "crl.pem"), err)
	}
	fmt.Printf("Published CRL %d to the cluster; each daemon installs it within a minute.\n", version)
	fmt.Println("`lv health` warns for as long as any peer's CRL version is behind another's")
	return nil
}

// publishClusterCRL hands the freshly-minted CRL to the cluster to replicate.
func publishClusterCRL(ctx context.Context, c pb.LiteVirtClient, pkiDir string) (int64, error) {
	crlPEM, err := os.ReadFile(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		return 0, fmt.Errorf("read the CRL just written: %w", err)
	}
	resp, err := c.PublishCRL(ctx, &pb.PublishCRLRequest{CrlPem: string(crlPEM)})
	if err != nil {
		return 0, err
	}
	return resp.Version, nil
}

// errHostNotListed is hostCertSerial's answer for a host ListHosts does not
// list (removed, or never there).
var errHostNotListed = errors.New("host is not present")

// hostCertSerial reads a host's certificate serial, best-effort: a removal must not
// be blocked by a lookup, and a missing serial only costs the revocation.
func hostCertSerial(ctx context.Context, c pb.LiteVirtClient, hostName string) (string, error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return "", err
	}
	for _, h := range resp.Hosts {
		if h.Name == hostName {
			if h.CertSerial == "" || strings.EqualFold(h.CertSerial, "unknown") {
				return "", fmt.Errorf("host has no recorded certificate serial")
			}
			return h.CertSerial, nil
		}
	}
	return "", errHostNotListed
}

// closeRemovedHostAuditContract retires the removed host's live audit signing
// key so its published certificate stops standing as an open contract. A host
// that never signed answers "nothing to retire" — the quiet common case. A
// half-finished rotation leaves several live keys, each with its own boundary,
// which retirement refuses to collapse into one call — surfaced with per-key
// instructions. Any other failure warns and lets removal proceed.
func closeRemovedHostAuditContract(ctx context.Context, c pb.LiteVirtClient, hostName string) {
	err := HostRetireAuditKey(ctx, c, hostName, "", nil, false)
	switch {
	case err == nil:
		// Retired; HostRetireAuditKey already printed the boundary.
	case strings.Contains(err.Error(), "no live audit signing certificate"):
		// Never signed, or already closed — nothing standing.
	case strings.Contains(err.Error(), "live signing certificates"):
		fmt.Printf("  WARNING: %s has multiple live audit signing keys (a rotation that never "+
			"finished); its contract is still open. Retire each with:\n"+
			"    lv host retire-audit-key %s --key-id <id>\n  detail: %v\n",
			hostName, hostName, err)
	default:
		fmt.Printf("  WARNING: could not retire %s's audit signing key; until it is retired, "+
			"every unsigned row it wrote is reported as tampering and a re-admitted %s "+
			"cannot sign cleanly. Retry with: lv host retire-audit-key %s\n  detail: %v\n",
			hostName, hostName, hostName, err)
	}
}

// revokeHostCert appends a removed host's certificate serial to the cluster CRL.
func revokeHostCert(pkiDir, hostName, serial string) error {
	if serial == "" || strings.EqualFold(serial, "unknown") {
		return fmt.Errorf("host %s has no recorded certificate serial", hostName)
	}
	caCert := filepath.Join(pkiDir, "ca.crt")
	caKey := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caKey); err != nil {
		return fmt.Errorf("no cluster CA private key at %s: revoking a certificate has to be "+
			"signed by the CA, which lives on the machine that ran `lv host init`", caKey)
	}
	if err := pki.AppendToCRL(caCert, caKey, filepath.Join(pkiDir, "crl.pem"), serial); err != nil {
		return fmt.Errorf("append %s to the CRL: %w", serial, err)
	}
	return nil
}

// refuseVoterRemoval refuses `lv host rm` of a member of the adopted voter
// generation, naming the command that removes the vote (recovery-claims.md
// §4.3). A daemon without the voter RPC (an older build) has no voter set to
// protect, so Unimplemented is not a refusal.
func refuseVoterRemoval(ctx context.Context, c pb.LiteVirtClient, hostName string) error {
	resp, err := c.GetVoterConfig(ctx, &pb.GetVoterConfigRequest{})
	if status.Code(err) == codes.Unimplemented {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the voter set before removing %s: %w", hostName, err)
	}
	for _, m := range resp.GetMembers() {
		if m.GetName() == hostName {
			return fmt.Errorf("%s is a member of voter generation %d; removing the host would not remove its "+
				"vote. Run `lv cluster voter rm %s` first, then remove the host — or, if it is fenced and gone "+
				"for good, `lv host rm --dead %s`, which does both", hostName, resp.GetAdoptedGeneration(), hostName, hostName)
		}
	}
	return nil
}

// printRemoved prints what a removal tombstoned: the incarnation and serial
// the daemon reports, or, from a daemon too old to report them, plain.
func printRemoved(hostName string, removed *pb.RemoveHostResponse, plain string) {
	if removed.GetCertSerial() == "" {
		fmt.Printf(plain, hostName)
		return
	}
	fmt.Printf("Host %s removed (incarnation %d, serial %s).\n", hostName,
		removed.GetIncarnation(), removed.GetCertSerial())
}

// removeStagedAdmission removes, over SSH as root, what a stranded `lv host
// add` admitted with certificate serial left staged on the host at addr. The host is often dead or half set up, so the
// connection is bounded (stagedCleanupTimeout). A seam so the removal can be
// tested without a host.
var removeStagedAdmission = func(addr, serial string) error {
	r, done, err := dialAdmissionMachine(addr)
	if err != nil {
		return err
	}
	defer done()
	return removeStagedPair(r, serial)
}

// stagedCleanupTimeout bounds removeStagedAdmission's whole SSH session:
// connect, handshake and the commands it runs.
const stagedCleanupTimeout = 10 * time.Second

// addStagedTargets are the files an add stages at fixed destinations (its
// config, staged at the path config.yaml resolves to, is the default one's
// here).
func addStagedTargets() []string {
	return []string{
		filepath.Join(remotePKIDir, "host.crt"), filepath.Join(remotePKIDir, "host.key"),
		filepath.Join(remotePKIDir, "ca.crt"), filepath.Join(remotePKIDir, pki.GossipKeyName),
		filepath.Join(remoteMigrationDir, pki.MigrationCAName), filepath.Join(remoteMigrationDir, pki.MigrationHostCertName),
		filepath.Join(remoteMigrationDir, pki.MigrationHostKeyName), remoteConfig, remoteBinary,
	}
}

// removeStagedPair deletes on r what the adds admitted with serial, the one
// this removal revoked, left staged: every attempt's files tagged with it
// (<serial>-<nonce>), including the config staged beside the file
// config.yaml resolves to, and only those, so another admission's on the
// machine are not touched. A pair an earlier release's add staged untagged
// goes only when its certificate is serial's (removeLegacyStagedPair).
// Serials are unique to the CA, so another machine at a reused address never
// matches, and nothing there is touched.
func removeStagedPair(r addRemote, serial string) error {
	return removeStaged(r, serial, releaseRemoved)
}

// removeStaged is removeStagedPair, its install record released as how says
// (releaseInstallRecord), and a settle's claim of serial removed last.
func removeStaged(r addRemote, serial string, how releaseMode) error {
	serial = canonSerial(serial)
	if serial == "" {
		return fmt.Errorf("not a certificate serial")
	}
	if err := removeStagedFiles(r, serial); err != nil {
		return err
	}
	if err := releaseInstallRecord(r, serial, how); err != nil {
		return err
	}
	if err := removeLegacyStagedPair(r, serial); err != nil {
		return err
	}
	// Last: until the rest is gone, no add of serial runs on the machine.
	return dropSettleClaim(r, serial, "")
}

// removeStagedFiles removes every attempt's staged files and records tagged
// with serial (canonical), and nothing else.
func removeStagedFiles(r addRemote, serial string) error {
	targets := addStagedTargets()
	q := ssh.ShellQuote(r.Path(remoteConfig))
	if out, err := r.Shell("config", fmt.Sprintf("if [ -e %s ]; then readlink -f -- %s; fi", q, q)); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" && !strings.ContainsAny(p, "\n\x00") {
			targets = append(targets, r.Unpath(p))
		}
	}
	var cmd strings.Builder
	cmd.WriteString("rc=0; ")
	for _, t := range targets {
		// The serial is hex (validAttemptTag), and the glob is all that is
		// left unquoted.
		fmt.Fprintf(&cmd, "rm -f -- %s* || rc=1; ", ssh.ShellQuote(r.Path(addStagedPath(t, serial+"-"))))
	}
	cmd.WriteString("exit $rc")
	_, err := r.Shell("unstage", cmd.String())
	return err
}

// afterMarkerRead is a test seam: it runs between releaseInstallRecord's
// read of the record and its change.
var afterMarkerRead func()

// settleClaimPath is the claim `lv host rm --serial` takes of the machine
// while it settles the admission serial (settleAbsentAdmission): a file of
// that serial's alone, which no add of serial runs past (machineClaim). A
// settle never writes the machine's install record (addInstalledMarker);
// it removes it only when it is serial's own (releaseInstallRecord).
func settleClaimPath(serial string) string {
	return "/etc/litevirt/.lv-add-settle-" + serial
}

// settlePriorPath is where a settle of an earlier build of this branch kept
// the install record its claim replaced (its claim was the install record
// itself; "" stood for none). Read only to put that record back while the
// install record is still that claim (releaseInstallRecord), and never
// removed otherwise.
func settlePriorPath(serial string) string {
	return addInstalledMarker + ".settle-" + serial
}

// legacySettleCopy is, when the install record line is a claim of serial X
// that an earlier build's settle of X wrote (settlePriorPath(X) exists),
// the record that claim replaced. Such a claim is no add's.
func legacySettleCopy(r addRemote, line string) (string, bool, error) {
	f := markerFields(line)
	if len(f) < 5 || f[4] != "installing" || canonSerial(f[1]) == "" {
		return "", false, nil
	}
	b, ok, err := r.ReadFile(settlePriorPath(canonSerial(f[1])))
	if err != nil || !ok {
		return "", false, err
	}
	return strings.TrimRight(string(b), "\n"), true, nil
}

// namesSerial reports whether the install record line is of serial, in any
// spelling.
func namesSerial(line, serial string) bool {
	f := markerFields(line)
	return len(f) >= 3 && canonSerial(f[1]) != "" && canonSerial(f[1]) == canonSerial(serial)
}

// isClaimOf reports whether the install record line is a claim of serial's
// add, not an install.
func isClaimOf(line, serial string) bool {
	f := markerFields(line)
	return namesSerial(line, serial) && len(f) >= 5 && f[4] == "installing"
}

// releaseMode is what releaseInstallRecord leaves of a record of the serial.
type releaseMode int

const (
	// releaseRemoved: the serial's admission is revoked and its row removed;
	// a record of it goes.
	releaseRemoved releaseMode = iota
	// releaseSettled: the serial is revoked with no row (a settle); only its
	// add's claim goes, and an install record of it stays.
	releaseSettled
)

// fileIs is the shell test that the file at path holds content (without
// its trailing newline; "" also for no file).
func fileIs(r addRemote, path, content string) string {
	return fmt.Sprintf("[ \"$(cat -- %s 2>/dev/null)\" = %s ]", ssh.ShellQuote(r.Path(path)), ssh.ShellQuote(content))
}

// writeSyncedCmd writes content to path as setMarkerCmd writes the record:
// synced, renamed into place, its directory synced.
func writeSyncedCmd(r addRemote, path, content, nonce string) string {
	p := ssh.ShellQuote(r.Path(path))
	tmp := ssh.ShellQuote(r.Path(path) + ".new-" + nonce)
	return fmt.Sprintf("umask 077; printf '%%s' %s > %s && sync -- %s && mv -fT -- %s %s && sync -- %s",
		ssh.ShellQuote(content), tmp, tmp, tmp, p, ssh.ShellQuote(filepath.Dir(r.Path(path))))
}

// removeSyncedCmd removes path and syncs its directory.
func removeSyncedCmd(r addRemote, path string) string {
	return fmt.Sprintf("rm -f -- %s && sync -- %s", ssh.ShellQuote(r.Path(path)), ssh.ShellQuote(filepath.Dir(r.Path(path))))
}

// releaseInstallRecord takes the admission serial, which this removal
// revoked, off the machine's install record (addInstalledMarker), under the
// add lock and only while the record is exactly as read. Only a record of
// serial is changed: a record of serial goes as how says, and any other
// admission's record, whenever it was written, is left as it is.
//
// The one record of serial that is put back rather than removed is an
// earlier build's settle claim of serial, with the record it replaced
// (settlePriorPath): that record goes back exactly, and its copy with it.
// The copy is otherwise left, unless another admission's finished install
// has replaced the claim since.
func releaseInstallRecord(r addRemote, serial string, how releaseMode) error {
	b, ok, err := r.ReadFile(addInstalledMarker)
	if err != nil {
		return err
	}
	line := strings.TrimRight(string(b), "\n")
	kb, kept, err := r.ReadFile(settlePriorPath(serial))
	if err != nil {
		return err
	}
	prior := strings.TrimRight(string(kb), "\n")
	cond := markerAbsent(r)
	if ok {
		cond = markerIs(r, line)
	}
	var body string
	switch {
	case kept && (!ok || isClaimOf(line, serial)):
		put := prior
		if namesSerial(prior, serial) && (how == releaseRemoved || isClaimOf(prior, serial)) {
			put = ""
		}
		cond += " && " + fileIs(r, settlePriorPath(serial), prior)
		body = "{ " + setMarkerCmd(r, put, nonceOr(serial)) + "; } && " + removeSyncedCmd(r, settlePriorPath(serial))
	case kept && !namesSerial(line, serial) && finishedInstall(line):
		// Another admission installed the machine since: what the copy kept
		// is no record any more, and no rollback gives the claim back.
		cond += " && " + fileIs(r, settlePriorPath(serial), prior)
		body = removeSyncedCmd(r, settlePriorPath(serial))
	case !ok:
		return nil
	case how == releaseRemoved && namesSerial(line, serial), how == releaseSettled && isClaimOf(line, serial):
		body = setMarkerCmd(r, "", nonceOr(serial))
	default:
		return nil // another admission's record, or an install of a settled serial: it stays
	}
	if afterMarkerRead != nil {
		afterMarkerRead()
	}
	_, err = r.Shell("unstage", lockedCmd(r, cond, body))
	if exitStatus(err) == notOurMachine {
		return nil // another add's record since: left
	}
	if err != nil {
		return fmt.Errorf("take the removed admission's record %s off the machine: %w", addInstalledMarker, err)
	}
	return nil
}

// finishedInstall reports whether the install record line is a finished
// install (an earlier release's form has no state), not a claim.
func finishedInstall(line string) bool {
	f := markerFields(line)
	return len(f) >= 3 && (len(f) < 5 || f[4] == "installed")
}

// dropSettleClaim removes serial's settle claim (settleClaimPath) under the
// add lock: only while it is line, or whatever it is when line is "".
func dropSettleClaim(r addRemote, serial, line string) error {
	p := settleClaimPath(serial)
	if line == "" {
		_, ok, err := r.ReadFile(p)
		if err != nil || !ok {
			return err
		}
	}
	cond := "true"
	if line != "" {
		cond = fileIs(r, p, line)
	}
	_, err := r.Shell("unstage", lockedCmd(r, cond, removeSyncedCmd(r, p)))
	if exitStatus(err) == notOurMachine {
		return nil // another run's claim since: it is that run's to remove
	}
	if err != nil {
		return fmt.Errorf("remove the settle's claim %s of the machine: %w", p, err)
	}
	return nil
}

// nonceOr is a fresh attempt nonce, or serial when none can be made (it only
// names a temporary file).
func nonceOr(serial string) string {
	if n, err := attemptNonce(); err == nil {
		return n
	}
	return serial
}

// HostRemoveAdmission is `lv host rm <host> --serial <serial> [--address <ip>]`:
// the removal of one admission, selected by its certificate rather than by
// the row the name has now. The serial is taken in any spelling of the
// number (case, leading zeroes, 0x) and compared only in its canonical form
// (pki.CanonicalSerial), the one the CRL uses.
//
// When the row of hostName holds the serial, it is HostRemove of that row,
// with every gate of an ordinary removal and refused if the row changes
// first. Otherwise no row is touched (settleAbsentAdmission).
func HostRemoveAdmission(ctx context.Context, c pb.LiteVirtClient, hostName, serialArg, address string, force bool) error {
	serial, err := pki.CanonicalSerial(serialArg)
	if err != nil {
		return fmt.Errorf("--serial: %w", err)
	}
	if address != "" {
		if ip := net.ParseIP(address); ip == nil || ip.To4() == nil || strings.Contains(address, ":") {
			return fmt.Errorf("--address %q is not an IPv4 address", address)
		}
	}
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list the cluster's hosts: %w", err)
	}
	var holder *pb.Host
	for _, h := range resp.GetHosts() {
		if canonSerial(h.GetCertSerial()) != serial {
			continue
		}
		if h.GetName() != hostName {
			return fmt.Errorf("certificate %s is %s's, not %s's: nothing was revoked or removed", serial, h.GetName(), hostName)
		}
		holder = h
	}
	if holder != nil {
		if address != "" && holder.GetAddress() != address {
			return fmt.Errorf("%s (certificate %s) is at %s, not %s: nothing was revoked or removed",
				hostName, serial, holder.GetAddress(), address)
		}
		return hostRemove(ctx, c, hostName, force, holder.GetCertSerial())
	}
	// With no row to check the name against: a name that prints safely, which
	// the machine's trace must name exactly (settleTrace) before anything is
	// revoked. One the CLI would not take otherwise (a blank, say) is an
	// existing host's that an add recorded, and printed commands quote it.
	if !settleName(hostName) {
		return fmt.Errorf("%q is not a host name an add could have recorded; nothing was revoked", hostName)
	}
	if address == "" {
		return fmt.Errorf("no host row holds certificate %s; pass --address with the machine its add was run "+
			"against, which must hold that admission's staged files or record", serial)
	}
	return settleAbsentAdmission(ctx, c, hostName, serial, address)
}

// settleAbsentAdmission revokes serial, which no row holds, and removes what
// its adds left on the machine at address: its staged files and records,
// and an install record of its own add's claim; never the installed
// identity, and never another admission's install record. In order:
//
//  1. the daemon runs an ordinary removal's gates (admin, caught up, voter
//     majority, a pull of the hosts table) and confirms that no row of
//     hostName and no live row holds serial (PreflightRemoveHost);
//  2. on the machine, under its add lock, the serial must have left a trace
//     naming hostName (a record, an install record or a staged certificate),
//     no add may hold the machine, and the machine must not serve serial,
//     which could be a completed add (then only the serial's staged files
//     go, and nothing is revoked); the command then claims the machine for
//     serial (settleClaimPath, compared with the install record and the
//     certificate it checked), so no add of serial runs there until the
//     cleanup is done;
//  3. serial is revoked and the CRL published;
//  4. the cleanup, its claim last.
//
// A step that fails names this same command, which finishes it: once the
// serial is revoked here, a rerun publishes the CRL and cleans up.
func settleAbsentAdmission(ctx context.Context, c pb.LiteVirtClient, hostName, serial, address string) error {
	again := settleRmCmd(hostName, serial, address)
	revoked := serialRevokedHere(PKIDir(), serial)
	if !revoked {
		if err := confirmAdmissionAbsent(ctx, c, hostName, serial); err != nil {
			return err
		}
	}
	r, done, err := dialAdmissionMachine(address)
	if err != nil {
		if revoked {
			return fmt.Errorf("certificate %s is revoked, but %s could not be reached to remove what its adds left "+
				"there (%v). Run `%s` to finish it", serial, address, err, again)
		}
		return fmt.Errorf("could not reach %s to check it before revoking certificate %s (%v); nothing was revoked",
			address, serial, err)
	}
	defer done()
	if !revoked {
		claim, err := takeSettleClaim(r, hostName, serial, address)
		if err != nil {
			return err
		}
		if err := revokeHostCert(PKIDir(), hostName, serial); err != nil {
			// Nothing was revoked: the claim goes.
			if uerr := dropSettleClaim(r, serial, claim); uerr != nil {
				return fmt.Errorf("%w; removing its claim %s of the machine failed too (%v), and it keeps that "+
					"admission's adds out. Run `%s` once the revocation can be made", err, settleClaimPath(serial), uerr, again)
			}
			return err
		}
	}
	version, err := publishClusterCRL(ctx, c, PKIDir())
	if err != nil {
		return fmt.Errorf("certificate %s is revoked in %s, but publishing the CRL failed (%v); its claim %s keeps "+
			"that admission's adds off the machine at %s. Run `%s` to publish it and finish", serial,
			filepath.Join(PKIDir(), "crl.pem"), err, settleClaimPath(serial), address, again)
	}
	if err := removeStaged(r, serial, releaseSettled); err != nil {
		return fmt.Errorf("certificate %s is revoked and CRL %d published, but removing what its adds left on %s "+
			"failed (%v). Run `%s` to finish it", serial, version, address, err, again)
	}
	fmt.Printf("Revoked certificate %s in CRL %d; no host row holds it, and none was removed.\n", serial, version)
	fmt.Printf("  removed its adds' staged files and records on %s; the machine's installed identity and any other "+
		"admission's install record are as they were\n", address)
	return nil
}

// confirmAdmissionAbsent asks the daemon, through an ordinary removal's
// gates, that no row of hostName and no live row holds serial.
func confirmAdmissionAbsent(ctx context.Context, c pb.LiteVirtClient, hostName, serial string) error {
	_, err := c.PreflightRemoveHost(ctx, &pb.RemoveHostRequest{Name: hostName, ExpectedCertSerial: serial})
	switch {
	case err == nil:
		return fmt.Errorf("%s's row holds certificate %s (it reached this replica just now); nothing was revoked. "+
			"Run `%s` again, which removes it as `lv host rm` does", hostName, serial, settleRmCmd(hostName, serial, ""))
	case admissionAbsent(err):
		return nil
	case status.Code(err) == codes.NotFound || status.Code(err) == codes.Unimplemented:
		return fmt.Errorf("the daemon answering cannot confirm, after a pull of the hosts table, that no row holds "+
			"certificate %s (it is an earlier release); nothing was revoked. Run this against an upgraded host", serial)
	default:
		return fmt.Errorf("refusing to revoke certificate %s: %w; nothing was revoked", serial, err)
	}
}

// admissionAbsent reports whether err is PreflightRemoveHost's refusal
// marked as decided after a pull (apimeta.AdmissionAbsentReason): no row of
// the name, or another admission's, and no live row holding the serial.
func admissionAbsent(err error) bool {
	st, ok := status.FromError(err)
	if !ok || err == nil {
		return false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == apimeta.AdmissionAbsentReason &&
			info.GetDomain() == apimeta.AdmissionAbsentDomain {
			return true
		}
	}
	return false
}

// beforeSettleClaim is a test seam: it runs between claimForSettle's checks
// and its claim.
var beforeSettleClaim func()

// claimForSettle is takeSettleClaim without the claim it took.
func claimForSettle(r addRemote, hostName, serial, address string) error {
	_, err := takeSettleClaim(r, hostName, serial, address)
	return err
}

// takeSettleClaim checks the machine r for settleAbsentAdmission and claims
// it for serial (settleClaimPath), the claim compared under the add lock
// with the install record and the certificate it checked. It returns the
// claim. The install record is read, never written.
func takeSettleClaim(r addRemote, hostName, serial, address string) (string, error) {
	crt := filepath.Join(remotePKIDir, "host.crt")
	pemB, now, err := remoteCert(r, crt)
	if err != nil {
		return "", err
	}
	if now == serial {
		if err := removeStagedFiles(r, serial); err != nil {
			return "", fmt.Errorf("the machine at %s serves certificate %s: a completed add cannot be ruled out, so nothing "+
				"was revoked; removing its staged files failed too (%v)", address, serial, err)
		}
		return "", fmt.Errorf("the machine at %s serves certificate %s: a completed add cannot be ruled out, so nothing "+
			"was revoked. Its staged files were removed; the machine's identity and install record are as they were. "+
			"If its row is still to arrive, run `lv host rm %s` on a host that lists it", address, serial, shellWord(hostName))
	}
	b, ok, err := r.ReadFile(addInstalledMarker)
	if err != nil {
		return "", err
	}
	prior := ""
	if ok {
		prior = strings.TrimRight(string(b), "\n")
	}
	f := markerFields(prior)
	if len(f) >= 5 && f[4] == "installing" {
		// An add's claim, unless an earlier build's settle wrote it.
		_, settling, err := legacySettleCopy(r, prior)
		if err != nil {
			return "", err
		}
		at, _ := strconv.ParseInt(f[2], 10, 64)
		if !settling && addNow().Sub(time.Unix(at, 0)) < staleClaim {
			return "", fmt.Errorf("an `lv host add` holds the machine at %s (claimed less than %s ago); nothing was revoked. "+
				"Run this again once it has finished", address, staleClaim)
		}
	}
	trace, err := settleTrace(r, hostName, serial, f)
	if err != nil {
		return "", err
	}
	if !trace {
		return "", fmt.Errorf("the machine at %s holds no staged file, record or install record of certificate %s for %s, "+
			"so it is not where that admission's add ran; nothing was revoked", address, serial, hostName)
	}
	if beforeSettleClaim != nil {
		beforeSettleClaim()
	}
	nonce, err := attemptNonce()
	if err != nil {
		return "", err
	}
	cond := markerAbsent(r)
	if ok {
		cond = markerIs(r, prior)
	}
	q := ssh.ShellQuote(r.Path(crt))
	if pemB == nil {
		cond += fmt.Sprintf(" && [ ! -e %s ]", q)
	} else {
		sum := sha256.Sum256(pemB)
		cond += fmt.Sprintf(" && [ \"$(sha256sum < %s | cut -d' ' -f1)\" = %s ]", q, hex.EncodeToString(sum[:]))
	}
	// The claim is serial's own file, taken over one an earlier run of this
	// command left: the install record stays as it is.
	claim := settleClaimLine(hostName, serial, nonce)
	_, err = r.Shell("claim", lockedCmd(r, cond, writeSyncedCmd(r, settleClaimPath(serial), claim+"\n", nonce)))
	if exitStatus(err) == notOurMachine {
		return "", fmt.Errorf("the machine at %s changed while it was checked; nothing was revoked. Run `%s` again",
			address, settleRmCmd(hostName, serial, address))
	}
	if err != nil {
		return "", fmt.Errorf("claim the machine at %s before revoking: %w; nothing was revoked", address, err)
	}
	return claim, nil
}

// settleClaimLine is a settle's claim of the machine for serial.
func settleClaimLine(hostName, serial, nonce string) string {
	return markerLine(hostName, serial, addNow().Unix(), nonce, "settling")
}

// settleName reports whether hostName may be settled with no row to check it
// against: printable (printableName) and not taken for a flag.
func settleName(hostName string) bool {
	return printableName(hostName) && !strings.HasPrefix(hostName, "-")
}

// settleTrace reports whether the machine holds a trace of serial's add for
// hostName: a record of it naming hostName, an install record (fields f)
// naming both, or a staged certificate of serial issued to hostName.
func settleTrace(r addRemote, hostName, serial string, f []string) (bool, error) {
	if len(f) >= 3 && f[0] == hostName && canonSerial(f[1]) == serial {
		return true, nil
	}
	recs, err := addRecords(r, serial)
	if err != nil {
		return false, err
	}
	for _, rec := range recs {
		if !rec.bad && rec.name == hostName {
			return true, nil
		}
	}
	crt := filepath.Join(remotePKIDir, "host.crt")
	tags, err := stagedAttempts(r, crt, serial)
	if err != nil {
		return false, err
	}
	paths := []string{legacyStagedPath(crt)}
	for _, t := range tags {
		paths = append(paths, addStagedPath(crt, t))
	}
	for _, p := range paths {
		b, ok, err := r.ReadFile(p)
		if err != nil {
			return false, err
		}
		if ok && installedSerial(b) == serial && certIssuedTo(b, hostName) {
			return true, nil
		}
	}
	return false, nil
}

// certIssuedTo reports whether the PEM certificate b names hostName.
func certIssuedTo(b []byte, hostName string) bool {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return false
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	return err == nil && cert.Subject.CommonName == hostName
}

// dialAdmissionMachine opens the machine at addr, over SSH as root, for
// `lv host rm`'s checks and cleanup; done closes it. The host is often dead
// or half set up, so the connection is bounded (stagedCleanupTimeout). A
// seam so the removal can be tested without a host.
var dialAdmissionMachine = func(addr string) (addRemote, func(), error) {
	sc, err := ssh.NewClientDeadline("root@"+addr, stagedCleanupTimeout)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, nil, fmt.Errorf("SSH connect: gave up after %s: %w", stagedCleanupTimeout, err)
		}
		return nil, nil, fmt.Errorf("SSH connect: %w", err)
	}
	return &sshAddRemote{sshRemotePKI{sc: sc}}, func() { sc.Close() }, nil
}
