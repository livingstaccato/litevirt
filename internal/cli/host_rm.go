package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	serial, version, err := revokeAndPublish(ctx, c, &pb.RemoveHostRequest{Name: hostName, Force: force})
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
	removed, err := removeAfterRevoke(ctx, c, &pb.RemoveHostRequest{Name: hostName, Force: force, ExpectedCertSerial: serial}, rerun)
	if err != nil {
		return err
	}
	printRemoved(hostName, removed, "Host %s removed from cluster.\n")
	fmt.Printf("  revoked certificate %s in CRL %d before removing the host\n", serial, version)
	fmt.Println("  `lv health` warns for as long as any peer's CRL version is behind another's")
	// A joining host is often an add stranded after its admission, which left
	// the admitted (now revoked) pair staged on the machine for a rerun.
	if listed != nil && listed.GetState() == pb.HostState_HOST_JOINING && listed.GetAddress() != "" {
		if err := removeStagedAdmission(listed.GetAddress(), serial); err != nil {
			fmt.Printf("  could not remove the credentials an unfinished `lv host add` may have staged on %s "+
				"(%v); they are revoked. Remove %s/.host.crt.add-%s and .host.key.add-%s there by hand\n",
				listed.GetAddress(), err, remotePKIDir, strings.ToLower(serial), strings.ToLower(serial))
		}
	}
	return nil
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
// holding the CA key can do.
func revokeAndPublish(ctx context.Context, c pb.LiteVirtClient, req *pb.RemoveHostRequest) (string, int64, error) {
	hostName := req.GetName()
	serial, err := hostCertSerial(ctx, c, hostName)
	if err != nil {
		return "", 0, fmt.Errorf("read %s's certificate serial before removal: %w", hostName, err)
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
	sc, err := ssh.NewClientDeadline("root@"+addr, stagedCleanupTimeout)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("SSH connect: gave up after %s: %w", stagedCleanupTimeout, err)
		}
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()
	return removeStagedPair(&sshAddRemote{sshRemotePKI{sc: sc}}, serial)
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

// removeStagedPair deletes on r what the add admitted with serial, the one
// this removal revoked, left staged: the files tagged with serial, and only
// those, so another attempt's on the machine are not touched. A pair an
// earlier release's add staged untagged goes only when its certificate is
// serial's. Serials are unique to the CA, so another machine at a reused
// address never matches, and nothing there is touched.
func removeStagedPair(r addRemote, serial string) error {
	serial = strings.ToLower(serial)
	if !validAttemptTag(serial) {
		return fmt.Errorf("serial %q is not one", serial)
	}
	gone := stagedPaths(addStagedTargets(), serial)
	crt := legacyStagedPath(filepath.Join(remotePKIDir, "host.crt"))
	b, ok, err := r.ReadFile(crt)
	if err != nil {
		return err
	}
	if ok && installedSerial(b) == serial {
		gone = append(gone, crt, legacyStagedPath(filepath.Join(remotePKIDir, "host.key")))
	}
	_, err = r.Shell("unstage", removeCmd(r, gone))
	return err
}
