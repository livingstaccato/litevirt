package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
	"github.com/litevirt/litevirt/internal/ssh"
)

// HostRenewCert replaces a running host's cluster (mTLS) certificate with a
// successor from the same CA, without restarting it, partitioning it, or
// giving any peer a reason to fence it.
//
// Why each step is where it is:
//
//   - The host generates the new key and a certificate request
//     (`litevirt host-pki gen-csr`, pki.GenerateRenewalCSR); this machine signs
//     only the request (pki.SignRenewal). The private key never crosses SSH or
//     sits in this process.
//   - The successor names the installed certificate as its predecessor. Peers
//     pin each host's serial, and that pin is what keeps a re-admitted name's
//     old certificate out — so it cannot just be relaxed. A peer whose record
//     still names the predecessor accepts the successor at once. The command
//     refuses if the cluster's record and the installed certificate disagree.
//   - The host installs it as ONE atomic switch (pki.InstallRenewal), so a
//     crash or a dropped connection at any point leaves a pair the daemon can
//     start with, and the daemon repairs an interrupted switch at start.
//   - The daemon serves its identity from disk at handshake time and re-records
//     its own serial within a minute, so installing is the whole hand-over.
//     The command CHECKS that the host presents the new certificate.
//   - It rolls back only when the host demonstrably still presents the old
//     certificate and the cluster does not record the new one. A probe that
//     merely fails proves nothing either way, so nothing is undone on it. A
//     successor that was issued and then abandoned is revoked.
//   - Then the replaced certificate is revoked (RevokeReplacedCertificate):
//     at once — or, only while some node does not pin accepts to unreplaced
//     certificates (an older build, auth.trust_rotated_peer_certs) and
//     revoking would leave the newest voter generation unverifiable for it,
//     as an owed revocation the cluster publishes itself once that ends.
//   - An audit admission record (audit-rejoin.json) is bound to the host
//     certificate's serial; it is re-signed for the new serial.
//
// libvirt's TLS listener is asked to reload; libvirt does not consult the
// cluster CRL, so a listener still on the old certificate keeps working.
// Migration-TLS certificates (pki_dir/migration, a separate CA) are not touched.
type RenewCertOptions struct {
	// SSHTarget reaches the host; default root@<host>.
	SSHTarget string
	// GRPCPort is the host's gRPC port, dialled to confirm the certificate it
	// presents. Default 7443.
	GRPCPort int
	// KeepOld leaves the replaced certificate unrevoked.
	KeepOld bool
	// RevokeOld revokes the replaced certificate immediately, even when a
	// hold would apply.
	RevokeOld bool
	// Force renews although hosts run different builds.
	Force bool
	// Wait bounds each confirmation (served certificate, re-recorded serial).
	Wait time.Duration
}

const remotePKIDir = "/etc/litevirt/pki"

// remotePKI is what renewal and the UI certificate need from the host's
// machine. sshRemotePKI runs it over SSH; LocalRemotePKI on a directory.
type remotePKI interface {
	// ReadFile returns path's contents, or ok=false when it does not exist.
	ReadFile(path string) (data []byte, ok bool, err error)
	// GenCSR has the host generate a new key and return a request for it,
	// plus where a legacy host.key outside the PKI directory lives ("" if none).
	GenCSR(hostName string) (staging string, csrPEM []byte, outsideKey string, err error)
	// DiscardIdentity deletes an unused identity (an abandoned successor).
	DiscardIdentity(serial string) error
	// InstallIdentity atomically switches the host to certPEM over the staged key.
	InstallIdentity(staging string, certPEM []byte) error
	// AbandonStaging discards a staged key that will not be installed.
	AbandonStaging(staging string) error
	// RollbackIdentity switches the host back to serial.
	RollbackIdentity(serial string) error
	// CommitIdentity deletes every identity but the current one.
	CommitIdentity() error
	// InstallFiles puts each file in place (each by rename), keeping the
	// files it replaces so RollbackFiles can restore them.
	InstallFiles(files []installFile) error
	RollbackFiles(files []installFile) error
	CommitFiles(files []installFile) error
	// ReloadLibvirtTLS asks libvirt's TLS listener to re-read its certificate.
	ReloadLibvirtTLS() error
	// Remove deletes each path, in order; an absent path is not an error.
	Remove(paths []string) error
}

type installFile struct {
	path string
	data []byte
	mode os.FileMode
}

// servedCertProbe returns the certificate the host presents now.
type servedCertProbe func(ctx context.Context) (*x509.Certificate, error)

func HostRenewCert(ctx context.Context, c pb.LiteVirtClient, hostName string, opts RenewCertOptions) error {
	if hostName == "" {
		return fmt.Errorf("host name required")
	}
	if err := requireCAKey(PKIDir(), "renewing a host certificate"); err != nil {
		return err
	}
	addr, err := hostAddress(ctx, c, hostName)
	if err != nil {
		return err
	}
	rt, err := sshTargetForHost(hostName, opts.SSHTarget, addr)
	if err != nil {
		return err
	}
	sc, err := ssh.NewClientResolved(rt)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()
	return renewHostCert(ctx, c, &sshRemotePKI{sc: sc}, GRPCProbe(addr, opts.GRPCPort), hostName, opts)
}

// RenewHostCertOn renews hostName through r — LocalRemotePKI for a host whose
// pki directory this machine can reach directly — confirming with probe.
func RenewHostCertOn(ctx context.Context, c pb.LiteVirtClient, r *LocalRemotePKI, probe func(context.Context) (*x509.Certificate, error),
	hostName string, opts RenewCertOptions) error {
	return renewHostCert(ctx, c, r, probe, hostName, opts)
}

// GRPCProbe dials addr:port with this machine's cluster credentials and
// returns the certificate it presents.
func GRPCProbe(addr string, port int) func(context.Context) (*x509.Certificate, error) {
	if port == 0 {
		port = 7443
	}
	return func(ctx context.Context) (*x509.Certificate, error) {
		return dialServedCert(ctx, net.JoinHostPort(addr, strconv.Itoa(port)))
	}
}

// renewHostCert is HostRenewCert past the connections.
func renewHostCert(ctx context.Context, c pb.LiteVirtClient, r remotePKI, probe servedCertProbe,
	hostName string, opts RenewCertOptions) error {
	if opts.Wait == 0 {
		opts.Wait = 90 * time.Second
	}
	pkiDir := PKIDir()
	certPath := filepath.Join(remotePKIDir, "host.crt")
	prevPEM, ok, err := r.ReadFile(certPath)
	if err != nil || !ok {
		return fmt.Errorf("read %s on %s: %v", certPath, hostName, orNotFound(err))
	}
	prev, err := pki.ParseCertPEM(prevPEM)
	if err != nil {
		return fmt.Errorf("parse %s on %s: %w", certPath, hostName, err)
	}
	prevSerial := strings.ToLower(prev.SerialNumber.Text(16))

	hosts, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	recorded := ""
	for _, h := range hosts.Hosts {
		if h.Name == hostName {
			recorded = strings.ToLower(h.CertSerial)
		}
	}
	if recorded != prevSerial {
		return fmt.Errorf("the cluster records certificate %q for %s, but the host holds %s. A successor "+
			"of a certificate the cluster does not record would be refused by every peer until "+
			"replication catches up. At incarnation 0, or for a renewal or the host's own admission, the "+
			"daemon re-records its own serial within a minute of starting (or of adopting a renewal) — "+
			"wait for `lv host inspect %s` to show %s, then retry. Otherwise `lv health` on the host shows "+
			"own_row_held and how to recover",
			recorded, hostName, prevSerial, hostName, prevSerial)
	}
	if err := sameBuildEverywhere(hosts.Hosts, hostName); err != nil && !opts.Force {
		return err
	}

	staging, csr, outsideKey, err := r.GenCSR(hostName)
	if err != nil {
		return fmt.Errorf("have %s generate its new key (it needs this build of litevirt): %w", hostName, err)
	}
	certPEM, err := pki.SignRenewal(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"), prev, hostName, csr)
	if err != nil {
		_ = r.AbandonStaging(staging)
		return fmt.Errorf("sign the renewal: %w", err)
	}
	next, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return err
	}
	nextSerial := strings.ToLower(next.SerialNumber.Text(16))
	logRenewal(pkiDir, renewalEntry{Host: hostName, Previous: prevSerial, Serial: nextSerial, State: "issued"})

	rejoin, err := resignedRejoin(r, pkiDir, hostName, prevPEM, prevSerial, nextSerial)
	if err != nil {
		_ = r.AbandonStaging(staging)
		return errors.Join(err, abandonIssued(ctx, c, hostName, nextSerial, "its audit admission record did not verify"))
	}

	slog.Info("installing renewed host certificate", "host", hostName, "serial", nextSerial, "replaces", prevSerial)
	if err := r.InstallIdentity(staging, certPEM); err != nil {
		// Did the switch happen before the error (a dropped connection after
		// it)? Ask the host's files rather than guess.
		cur, ok, rerr := r.ReadFile(certPath)
		switch {
		case rerr == nil && ok && servedSerialOf(cur) == nextSerial:
			slog.Warn("the install reported an error after switching; continuing", "error", err)
		case rerr == nil && ok && servedSerialOf(cur) == prevSerial:
			// Positively not switched: the successor will never be presented.
			_ = r.AbandonStaging(staging)
			_ = r.DiscardIdentity(nextSerial)
			return errors.Join(fmt.Errorf("install the renewed certificate on %s: %w", hostName, err),
				abandonIssued(ctx, c, hostName, nextSerial, "it was never installed"))
		default:
			// Cannot tell whether the switch happened: revoking the successor
			// could cut off a host that already presents it.
			return fmt.Errorf("install the renewed certificate on %s: %w, and its installed certificate could not "+
				"be read back (%v). Nothing was revoked. Check what %s/host.crt is: if it is %s the renewal took "+
				"effect — revoke the replaced certificate with `lv host revoke-cert %s --serial %s`; if it is %s, "+
				"revoke the unused successor with `lv host revoke-cert %s --serial %s`", hostName, err, rerr,
				remotePKIDir, nextSerial, hostName, prevSerial, prevSerial, hostName, nextSerial)
		}
	}
	if rejoin != nil {
		if err := r.InstallFiles([]installFile{*rejoin}); err != nil {
			fmt.Printf("  WARNING: could not re-sign the audit admission record on %s (%v); a restart before "+
				"its audit history arrives would not hold it\n", hostName, err)
		} else {
			_ = r.CommitFiles([]installFile{*rejoin})
		}
	}

	served, sawServed, perr := waitServedSerial(ctx, probe, nextSerial, opts.Wait)
	if perr != nil {
		recordedNow, _ := hostCertSerial(ctx, c, hostName)
		switch {
		case strings.EqualFold(recordedNow, nextSerial):
			// Adopted and recorded: the probe is what failed. Rolling back now
			// would make the host present a certificate peers no longer record.
			fmt.Printf("  NOTE: could not confirm what %s presents (%v), but the cluster records the "+
				"renewed serial, so the host adopted it\n", hostName, perr)
		case sawServed && served == prevSerial:
			// Demonstrably not adopted, not recorded: put it back, confirm, and
			// revoke the successor nobody will ever present.
			if rbErr := r.RollbackIdentity(prevSerial); rbErr != nil {
				return fmt.Errorf("%s still presents %s, and switching it back failed: %v — check %s by hand. "+
					"Nothing was revoked", hostName, prevSerial, rbErr, remotePKIDir)
			}
			if _, back, err := waitServedSerial(ctx, probe, prevSerial, opts.Wait); err != nil || !back {
				return fmt.Errorf("%s was switched back to %s but its presented certificate could not be confirmed (%v); "+
					"the unused successor %s was NOT revoked — revoke it with `lv host revoke-cert %s --serial %s` once "+
					"the host is confirmed on %s", hostName, prevSerial, err, nextSerial, hostName, nextSerial, prevSerial)
			}
			_ = r.DiscardIdentity(nextSerial)
			return errors.Join(fmt.Errorf("%s did not start presenting the renewed certificate (%v); it is back on "+
				"%s. Check `journalctl -u litevirt` on %s", hostName, perr, prevSerial, hostName),
				abandonIssued(ctx, c, hostName, nextSerial, "the host never adopted it"))
		default:
			return fmt.Errorf("could not confirm what %s presents (%v; last: %s) and the cluster does not record "+
				"the renewed serial yet. Nothing was rolled back or revoked: the renewal is installed on the host. "+
				"Re-run `lv host inspect %s` until it shows %s, then revoke the replaced certificate with "+
				"`lv host revoke-cert %s --serial %s`", hostName, perr, served, hostName, nextSerial, hostName, prevSerial)
		}
	}
	if err := r.CommitIdentity(); err != nil {
		fmt.Printf("  NOTE: could not remove the replaced identity under %s/host.d: %v\n", remotePKIDir, err)
	}
	logRenewal(pkiDir, renewalEntry{Host: hostName, Previous: prevSerial, Serial: nextSerial, State: "installed"})

	fmt.Printf("Host certificate renewed for %s\n", hostName)
	fmt.Printf("  serial %s replaces %s; valid until %s\n", nextSerial, prevSerial, next.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("  %s generated the new key itself and presents the certificate now — no restart\n", hostName)
	if outsideKey != "" {
		fmt.Printf("  NOTE: the replaced key was served from %s, outside %s; it is no longer used —\n", outsideKey, remotePKIDir)
		fmt.Println("  remove it once nothing else needs it (the renewal cannot know)")
	}
	cleanupErr := removeCAMachineCopy(pkiDir, hostName, prev)
	if _, ok, err := r.ReadFile(filepath.Join(remotePKIDir, pki.AuditSigningCertName)); err == nil && !ok {
		// Without a dedicated audit pair the daemon signs audit rows with the
		// host key it loaded at boot — the REPLACED one — until it restarts,
		// and audit verification does not consult the CRL. A restart (or
		// rotate-audit-key, which restarts) retires it at a signed boundary.
		fmt.Printf("  NOTE: %s signs audit rows with its host key and keeps using the replaced one until its\n", hostName)
		fmt.Printf("  daemon restarts; run `%s` to retire it now at a signed boundary\n", rotateAuditKeyHint(hostName, opts.SSHTarget))
	}
	if rejoin != nil {
		fmt.Println("  the host's audit admission record was re-signed for the new serial")
	}
	if err := r.ReloadLibvirtTLS(); err != nil {
		fmt.Printf("  NOTE: libvirt's TLS listener did not reload (%v); it keeps serving the previous\n", err)
		fmt.Println("  certificate for qemu+tls:// migration until it restarts (libvirt does not read the CRL)")
	} else {
		fmt.Println("  libvirt's TLS listener reloaded the renewed certificate")
	}
	if waitRecordedSerial(ctx, c, hostName, nextSerial, opts.Wait) {
		fmt.Println("  the cluster now records the renewed serial")
	} else {
		fmt.Printf("  NOTE: the cluster does not record %s yet; peers accept it as the recorded\n", nextSerial)
		fmt.Println("  certificate's successor meanwhile, and the daemon keeps re-recording it")
	}

	switch {
	case opts.KeepOld:
		fmt.Printf("  the previous certificate %s was NOT revoked (--keep-old); it stays CA-valid until %s.\n",
			prevSerial, prev.NotAfter.UTC().Format("2006-01-02"))
		fmt.Printf("  Revoke it with `lv host revoke-cert %s --serial %s`\n", hostName, prevSerial)
		return cleanupErr
	case opts.RevokeOld:
		return errors.Join(revokeAndPublishSerial(ctx, c, hostName, prevSerial), cleanupErr)
	}
	return errors.Join(revokeReplaced(ctx, c, hostName, prevSerial), cleanupErr)
}

// revokeReplaced hands the cluster a CRL revoking serial and lets it decide:
// published now, or owed until the voter chain allows it. The CRL is minted
// WITHOUT updating this machine's crl.pem, so a held serial does not ride
// along in the next CRL minted here before it is safe.
func revokeReplaced(ctx context.Context, c pb.LiteVirtClient, hostName, serial string) error {
	pkiDir := PKIDir()
	crlPath := filepath.Join(pkiDir, "crl.pem")
	crl, err := pki.MintCRLWith(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"), crlPath, serial)
	if err != nil {
		return fmt.Errorf("mint the CRL revoking %s: %w", serial, err)
	}
	resp, err := c.RevokeReplacedCertificate(ctx, &pb.RevokeReplacedCertificateRequest{
		Host: hostName, Serial: serial, CrlPem: string(crl)})
	if status.Code(err) == codes.Unimplemented {
		// A daemon on an older build cannot judge the voter chain; revoke
		// directly, the way `lv host rm` does.
		return revokeAndPublishSerial(ctx, c, hostName, serial)
	}
	if err != nil {
		return fmt.Errorf("the renewal is complete, but handing the cluster the revocation of %s failed: %w. "+
			"Nothing is revoked or owed yet. `lv host revoke-cert %s --serial %s` revokes it IMMEDIATELY, without "+
			"the voter-chain check that would have held it as owed — use it once a voter change has happened "+
			"since, or if revoking now is what you want", serial, err, hostName, serial)
	}
	if resp.Revoked {
		if err := secretfile.Write(crlPath, crl, 0o644); err != nil {
			fmt.Printf("  NOTE: published, but could not update %s: %v\n", crlPath, err)
		}
		logRenewal(pkiDir, renewalEntry{Host: hostName, Serial: serial, State: "revoked"})
		fmt.Printf("  revoked the replaced certificate %s (CRL %d)\n", serial, resp.Version)
		return nil
	}
	logRenewal(pkiDir, renewalEntry{Host: hostName, Serial: serial, State: "owed"})
	for _, l := range owedRevocationNote(hostName, serial, resp.Reason) {
		fmt.Println(l)
	}
	return nil
}

// owedRevocationNote is what `lv host renew-cert` prints for a revocation the
// cluster holds as owed, by why it is held.
func owedRevocationNote(hostName, serial, reason string) []string {
	out := []string{fmt.Sprintf("  the replaced certificate %s is OWED revocation, not revoked yet: %s.", serial, reason)}
	if strings.HasPrefix(reason, fencessh.RevocationHoldPrefix) {
		out = append(out,
			"  It is held until "+hostName+"'s daemon re-signs its fence ssh row with the renewed certificate,",
			"  which it does within a minute of adopting it; revoked first, every peer would refuse to fence",
			"  "+hostName+" meanwhile. The cluster holds the signed CRL as a degraded condition",
			"  (certificate/revocation_owed) and publishes it by itself once the row is re-signed. Every node",
			"  on this build already refuses the replaced certificate on every RPC.")
	} else {
		out = append(out,
			"  A hold applies only while some node does not pin accepts to unreplaced certificates (an",
			"  older build, or auth.trust_rotated_peer_certs on). The cluster holds the signed CRL as a",
			"  degraded condition (certificate/revocation_owed), publishes it by itself once that is no",
			"  longer so, and notifies certificate.revocation_owed daily meanwhile. Every node on this",
			"  build already refuses the replaced certificate: as a voter, as a claim signer, and on",
			"  every RPC.")
	}
	return append(out, fmt.Sprintf("  To revoke it now regardless: `lv host revoke-cert %s --serial %s`", hostName, serial))
}

// abandonIssued revokes a successor that was signed but will never be
// presented: it is a CA-valid certificate naming the host, and peers would
// accept it as the recorded certificate's successor.
func abandonIssued(ctx context.Context, c pb.LiteVirtClient, hostName, serial, why string) error {
	logRenewal(PKIDir(), renewalEntry{Host: hostName, Serial: serial, State: "abandoned"})
	if err := revokeAndPublishSerial(ctx, c, hostName, serial); err != nil {
		return fmt.Errorf("the unused successor %s (%s) could not be revoked: %w — revoke it with "+
			"`lv host revoke-cert %s --serial %s`", serial, why, err, hostName, serial)
	}
	return nil
}

// rotateAuditKeyHint is the rotate-audit-key command for hostName, reaching it
// the way this renewal did: an explicit --ssh target is passed on, or the
// command would dial root@<host> and fail where the renewal succeeded.
func rotateAuditKeyHint(hostName, sshTarget string) string {
	if sshTarget != "" && sshTarget != "root@"+hostName {
		return fmt.Sprintf("lv host rotate-audit-key %s --ssh %s", hostName, sshTarget)
	}
	return "lv host rotate-audit-key " + hostName
}

// removeCAMachineCopy deletes the copy of the replaced host pair that `lv host
// init` (<host>.key and <host>.crt) or `lv host add` (hosts/<host>/host.key
// and host.crt) left in this machine's pki directory, when it is that pair: a
// renewal retires the key, and a copy here would outlive it. The key goes only
// when it matches the replaced certificate; the certificate goes with it,
// never alone, and only when it IS the replaced certificate — so no half pair
// is left behind for a later `lv host add` or a human to trip on.
//
// It refuses, and returns why, when a copy's path is not this host's to
// remove: a name that leaves the directory (checked before either place is
// looked at), or a path that is one of the directory's own files (a host an
// older build admitted as "ca"), in either place. Both places are tried; the
// first refusal is returned. The renewal itself is complete either way.
func removeCAMachineCopy(pkiDir, hostName string, prev *x509.Certificate) error {
	if err := pki.ValidateHostPathName(hostName); err != nil {
		fmt.Printf("  NOTE: this machine's copy of %s's replaced pair was not looked for: %v\n", hostName, err)
		return fmt.Errorf("the renewal is complete, but this machine's copy of the replaced pair was not removed: %w", err)
	}
	first := removeCAMachineCopyAt(pkiDir, hostName, filepath.Join(pkiDir, hostName+".key"), filepath.Join(pkiDir, hostName+".crt"), prev)
	if dir := keptHostDir(pkiDir, hostName); dir != "" {
		if err := removeCAMachineCopyAt(pkiDir, hostName, filepath.Join(dir, "host.key"), filepath.Join(dir, "host.crt"), prev); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// removeCAMachineCopyAt is removeCAMachineCopy for one place: keyPath and
// crtPath, under pkiDir.
func removeCAMachineCopyAt(pkiDir, hostName, keyPath, crtPath string, prev *x509.Certificate) error {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil
	}
	if _, err := tls.X509KeyPair(pemOfCert(prev), b); err != nil {
		return nil // not the replaced key; leave it
	}
	// The replaced key under one of the directory's own names: an older lv
	// minted the host's pair over it. Left, and said.
	for _, p := range []string{keyPath, crtPath} {
		if fixed, ok := pki.OperatorPKIFileIn(pkiDir, p); ok {
			fmt.Printf("  NOTE: left %s: it holds %s's replaced pair, but it is this directory's %s\n", p, hostName, fixed)
			return fmt.Errorf("the renewal is complete, but %s was left: it holds %s's replaced pair under "+
				"this directory's own %s, overwritten by an older release; restore %s from a backup", p, hostName, fixed, fixed)
		}
	}
	if err := os.Remove(keyPath); err != nil {
		fmt.Printf("  NOTE: could not remove this machine's copy of the replaced key %s: %v\n", keyPath, err)
		return nil
	}
	fmt.Printf("  removed this machine's copy of the replaced key (%s)\n", keyPath)
	if cb, err := os.ReadFile(crtPath); err == nil {
		if c, err := pki.ParseCertPEM(cb); err == nil && c.Equal(prev) {
			if err := os.Remove(crtPath); err != nil {
				fmt.Printf("  NOTE: could not remove this machine's copy of the replaced certificate %s: %v\n", crtPath, err)
				return nil
			}
			fmt.Printf("  removed this machine's copy of the replaced certificate (%s)\n", crtPath)
		}
	}
	return nil
}

func pemOfCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// sameBuildEverywhere refuses a renewal while live hosts run different
// builds: a peer on an older release does not honour the successor and
// refuses the renewed host until the re-recorded serial reaches it by
// anti-entropy (anti_entropy_interval_sec, 60s by default).
func sameBuildEverywhere(hosts []*pb.Host, target string) error {
	want := ""
	for _, h := range hosts {
		if h.Name == target {
			want = h.Version
		}
	}
	var differ []string
	for _, h := range hosts {
		if h.Version != want {
			differ = append(differ, fmt.Sprintf("%s (%s)", h.Name, h.Version))
		}
	}
	if len(differ) == 0 {
		return nil
	}
	return fmt.Errorf("hosts run a different build from %s (%s): %s. Peers on an older release refuse the "+
		"renewed host until its new serial reaches them by anti-entropy; finish the upgrade first, or pass "+
		"--force", target, want, strings.Join(differ, ", "))
}

func servedSerialOf(certPEM []byte) string {
	c, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return ""
	}
	return strings.ToLower(c.SerialNumber.Text(16))
}

// HostRevokeCert revokes one certificate serial issued to hostName and
// publishes the CRL immediately — the manual path for a serial a renewal
// replaced or abandoned (`--keep-old`, an owed revocation, a failed renewal).
//
// It accepts only a serial known to be hostName's: one this machine's
// renewal log records for it, or the predecessor named by the certificate the
// host presents. A serial any host is recorded with is refused unless it is
// hostName's own live one and force is set — that cuts the host off from every
// peer and gets it fenced. When the host's presented certificate cannot be
// read, it refuses unless force is set.
func HostRevokeCert(ctx context.Context, c pb.LiteVirtClient, hostName, serial string, grpcPort int, force bool) error {
	return hostRevokeCert(ctx, c, hostName, serial, force, nil, grpcPort)
}

func hostRevokeCert(ctx context.Context, c pb.LiteVirtClient, hostName, serial string, force bool,
	probe servedCertProbe, grpcPort int) error {
	serial = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(serial), "0x"))
	if serial == "" {
		return fmt.Errorf("--serial is required")
	}
	if err := requireCAKey(PKIDir(), "revoking a certificate"); err != nil {
		return err
	}
	hosts, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	var addr string
	found := false
	for _, h := range hosts.Hosts {
		if h.Name == hostName {
			found, addr = true, h.Address
		}
		if strings.EqualFold(h.CertSerial, serial) {
			if h.Name != hostName {
				return fmt.Errorf("%s is the certificate the cluster records for %s, not %s; refusing", serial, h.Name, hostName)
			}
			if !force {
				return fmt.Errorf("%s is %s's LIVE certificate. Revoking it cuts %s off from every peer and gets it "+
					"FENCED. Renew first (`lv host renew-cert %s`); pass --force only to take the host out deliberately",
					serial, hostName, hostName, hostName)
			}
			fmt.Printf("  WARNING: revoking %s's live certificate — its peers will refuse it and fence it\n", hostName)
			return revokeAndPublishSerial(ctx, c, hostName, serial)
		}
	}
	if !found {
		return fmt.Errorf("host %s is not in the cluster", hostName)
	}
	if probe == nil {
		probe = GRPCProbe(addr, grpcPort)
	}
	presented, perr := probe(ctx)
	switch {
	case perr != nil && !force:
		return fmt.Errorf("could not read the certificate %s presents (%v), so cannot rule out that %s is it; "+
			"refusing (pass --force when the host is known to be on another certificate)", hostName, perr, serial)
	case perr == nil && strings.EqualFold(presented.SerialNumber.Text(16), serial):
		if !force {
			return fmt.Errorf("%s is the certificate %s presents right now; revoking it cuts the host off and gets it "+
				"FENCED. Pass --force only to take the host out deliberately", serial, hostName)
		}
		fmt.Printf("  WARNING: revoking the certificate %s presents — its peers will refuse it and fence it\n", hostName)
		return revokeAndPublishSerial(ctx, c, hostName, serial)
	}
	known := false
	if perr == nil {
		if prev, ok := pki.RenewedFromSerial(presented); ok && prev == serial {
			known = true
		}
	}
	for _, e := range readRenewalLog(PKIDir()) {
		if e.Host == hostName && (e.Serial == serial || e.Previous == serial) {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%s is not a certificate this machine renewed for %s (see %s), nor the predecessor of the "+
			"one it presents; refusing to revoke an unknown serial", serial, hostName, filepath.Join(PKIDir(), renewalLogName))
	}
	return revokeAndPublishSerial(ctx, c, hostName, serial)
}

func revokeAndPublishSerial(ctx context.Context, c pb.LiteVirtClient, hostName, serial string) error {
	pkiDir := PKIDir()
	if err := revokeHostCert(pkiDir, hostName, serial); err != nil {
		return err
	}
	version, err := publishClusterCRL(ctx, c, pkiDir)
	if err != nil {
		return fmt.Errorf("%s is revoked in %s, but publishing the CRL failed: %w. Retry with `lv host publish-crl`",
			serial, filepath.Join(pkiDir, "crl.pem"), err)
	}
	logRenewal(pkiDir, renewalEntry{Host: hostName, Serial: serial, State: "revoked"})
	fmt.Printf("Revoked certificate %s of %s in CRL %d; every node installs it within a minute\n", serial, hostName, version)
	return nil
}

// The renewal log: what this CA machine issued and replaced, per host — the
// record `lv host revoke-cert` checks a serial against.
const renewalLogName = "renewals.json"

type renewalEntry struct {
	Host     string `json:"host"`
	Previous string `json:"previous,omitempty"`
	Serial   string `json:"serial"`
	State    string `json:"state"` // issued | installed | abandoned | owed | revoked
	At       string `json:"at"`
}

func readRenewalLog(pkiDir string) []renewalEntry {
	b, err := os.ReadFile(filepath.Join(pkiDir, renewalLogName))
	if err != nil {
		return nil
	}
	var out []renewalEntry
	_ = json.Unmarshal(b, &out)
	return out
}

func logRenewal(pkiDir string, e renewalEntry) {
	e.At = time.Now().UTC().Format(time.RFC3339)
	log := append(readRenewalLog(pkiDir), e)
	b, err := json.MarshalIndent(log, "", "  ")
	if err == nil {
		err = secretfile.Write(filepath.Join(pkiDir, renewalLogName), b, 0o600)
	}
	if err != nil {
		slog.Warn("could not update the renewal log", "error", err)
	}
}

// resignedRejoin returns the host's audit admission record re-signed for
// nextSerial, or nil when there is none to carry over. Only a record that
// verifies against the cluster CA and is bound to the certificate being
// replaced is carried: re-signing anything else would launder it.
func resignedRejoin(r remotePKI, pkiDir, hostName string, prevPEM []byte, prevSerial, nextSerial string) (*installFile, error) {
	path := filepath.Join(remotePKIDir, corrosion.AuditRejoinFileName)
	data, ok, err := r.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s on %s: %w", path, hostName, err)
	}
	if !ok {
		return nil, nil
	}
	var rj corrosion.AuditRejoin
	if err := json.Unmarshal(data, &rj); err != nil || !strings.EqualFold(rj.CertSerial, prevSerial) {
		// Unparseable, or written for an earlier certificate: the daemon
		// already ignores it, and so does the renewal.
		return nil, nil
	}
	tmp, err := os.MkdirTemp("", "litevirt-rejoin-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	for name, b := range map[string][]byte{"ca.crt": caPEM, "host.crt": prevPEM, corrosion.AuditRejoinFileName: data} {
		if err := os.WriteFile(filepath.Join(tmp, name), b, 0o600); err != nil {
			return nil, err
		}
	}
	if _, ok, err := corrosion.LoadAuditRejoin(tmp, hostName); err != nil || !ok {
		return nil, fmt.Errorf("%s on %s does not verify against the cluster CA (%v); refusing to re-sign it. "+
			"Move it aside if it is not genuine, then retry", path, hostName, err)
	}
	resigned, err := corrosion.SignAuditRejoin(pkiDir, hostName, nextSerial, rj.Seq, rj.Hash)
	if err != nil {
		return nil, fmt.Errorf("re-sign %s for the renewed certificate: %w", corrosion.AuditRejoinFileName, err)
	}
	out, err := json.Marshal(resigned)
	if err != nil {
		return nil, err
	}
	return &installFile{path: path, data: out, mode: 0o644}, nil
}

// waitServedSerial polls probe until it presents want. It returns the last
// serial seen and whether any probe answered at all — a host that answered
// with another serial is evidence; a probe that only failed is not.
func waitServedSerial(ctx context.Context, probe servedCertProbe, want string, wait time.Duration) (string, bool, error) {
	deadline := time.Now().Add(wait)
	last, saw := "", false
	var lastErr error
	for {
		c, err := probe(ctx)
		if err == nil && c != nil {
			last, saw, lastErr = strings.ToLower(c.SerialNumber.Text(16)), true, nil
			if last == want {
				return last, true, nil
			}
		} else if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return last, saw, fmt.Errorf("probe failed: %w", lastErr)
			}
			return last, saw, fmt.Errorf("still presenting %s after %s", last, wait)
		}
		select {
		case <-ctx.Done():
			return last, saw, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func waitRecordedSerial(ctx context.Context, c pb.LiteVirtClient, hostName, want string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if got, err := hostCertSerial(ctx, c, hostName); err == nil && strings.EqualFold(got, want) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
}

// sshTargetForHost resolves the SSH target a credential command uses for the
// cluster host hostName, recorded at addr. With no --ssh target the default is
// root@<hostName>, and an ssh config alias of that name decides where it goes;
// one whose HostName resolves anywhere but addr (stale, or another machine)
// would carry the host's key material there, so it is refused. An explicit
// target is the operator's choice and is used as given.
func sshTargetForHost(hostName, sshTarget, addr string) (*ssh.Target, error) {
	explicit := sshTarget != ""
	if !explicit {
		sshTarget = "root@" + hostName
	}
	rt, err := ssh.Resolve(sshTarget)
	if err != nil {
		return nil, err
	}
	if !explicit && rt.Host() != hostName {
		if ip, err := resolveHost(rt.Host()); err != nil || ip != addr {
			return nil, fmt.Errorf("your ssh config sends %s to %s, but the cluster records %s at %s; "+
				"refusing to carry its credentials there. Fix the ssh config's HostName, or name the "+
				"target with --ssh", hostName, rt.Host(), hostName, addr)
		}
	}
	return rt, nil
}

func hostAddress(ctx context.Context, c pb.LiteVirtClient, hostName string) (string, error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return "", err
	}
	for _, h := range resp.Hosts {
		if h.Name == hostName {
			if h.Address == "" {
				return "", fmt.Errorf("host %s has no recorded address", hostName)
			}
			return h.Address, nil
		}
	}
	return "", fmt.Errorf("host %s is not in the cluster", hostName)
}

// dialServedCert completes a TLS handshake with addr, verifying it against the
// cluster CA, and returns the leaf it presented.
func dialServedCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	cfg, err := pki.ClientTLSConfig(PKIDir())
	if err != nil {
		return nil, err
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, errors.New("no certificate presented")
	}
	return st.PeerCertificates[0], nil
}

// requireCAKey fails early, before anything on a host is touched, when this
// machine cannot sign.
func requireCAKey(pkiDir, what string) error {
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caKeyPath); err != nil {
		return fmt.Errorf("no cluster CA private key at %s: %s must be run from the machine that ran "+
			"`lv host init`, because it signs with the CA private key", caKeyPath, what)
	}
	return nil
}

func orNotFound(err error) error {
	if err == nil {
		return os.ErrNotExist
	}
	return err
}

// sshRemotePKI is remotePKI over SSH. The host side of the identity operations
// is `litevirt host-pki` on the host itself.
type sshRemotePKI struct{ sc *ssh.Client }

const hostPKICmd = "/usr/local/bin/litevirt host-pki"

func (t *sshRemotePKI) ReadFile(path string) ([]byte, bool, error) {
	q := ssh.ShellQuote(path)
	// One command, two answers: a marker for absence, so an empty file and a
	// missing one are not confused, and a read error is still an error.
	out, err := t.sc.RunOutput(fmt.Sprintf("if [ -e %s ]; then head -c 1048576 -- %s; else printf '%s'; fi", q, q, absentMarker))
	if err != nil {
		return nil, false, err
	}
	if string(out) == absentMarker {
		return nil, false, nil
	}
	return out, true, nil
}

const absentMarker = "__litevirt_file_absent__"

func (t *sshRemotePKI) GenCSR(hostName string) (string, []byte, string, error) {
	out, err := t.sc.RunOutput(hostPKICmd + " gen-csr --name " + ssh.ShellQuote(hostName))
	if err != nil {
		return "", nil, "", err
	}
	var v struct {
		Staging    string
		CSR        string
		OutsideKey string `json:"outside_key"`
	}
	if err := json.Unmarshal(out, &v); err != nil || v.Staging == "" {
		return "", nil, "", fmt.Errorf("unexpected answer from host-pki gen-csr: %q", strings.TrimSpace(string(out)))
	}
	return v.Staging, []byte(v.CSR), v.OutsideKey, nil
}

func (t *sshRemotePKI) DiscardIdentity(serial string) error {
	return t.sc.Run(hostPKICmd + " discard --serial " + ssh.ShellQuote(serial))
}

func (t *sshRemotePKI) InstallIdentity(staging string, certPEM []byte) error {
	return t.sc.RunWithInput(hostPKICmd+" install --staging "+ssh.ShellQuote(staging), certPEM)
}

func (t *sshRemotePKI) AbandonStaging(staging string) error {
	return t.sc.Run(hostPKICmd + " abandon --staging " + ssh.ShellQuote(staging))
}

func (t *sshRemotePKI) RollbackIdentity(serial string) error {
	return t.sc.Run(hostPKICmd + " rollback --to " + ssh.ShellQuote(serial))
}

func (t *sshRemotePKI) CommitIdentity() error { return t.sc.Run(hostPKICmd + " commit") }

const preRenewSuffix = ".pre-renew"

func (t *sshRemotePKI) InstallFiles(files []installFile) error {
	// Stage everything first: a dropped connection mid-transfer must leave the
	// installed files untouched.
	for _, f := range files {
		if err := t.sc.WriteFile(stagedPath(f.path), f.data, f.mode); err != nil {
			return fmt.Errorf("stage %s: %w", filepath.Base(f.path), err)
		}
	}
	var cmd strings.Builder
	cmd.WriteString("set -e; ")
	for _, f := range files {
		q := ssh.ShellQuote(f.path)
		// cp -p keeps a key's 0600 on its backup.
		fmt.Fprintf(&cmd, "if [ -e %s ]; then cp -p -- %s %s; fi; ", q, q, ssh.ShellQuote(f.path+preRenewSuffix))
	}
	for _, f := range files {
		fmt.Fprintf(&cmd, "mv -fT -- %s %s; ", ssh.ShellQuote(stagedPath(f.path)), ssh.ShellQuote(f.path))
	}
	return t.sc.Run(cmd.String())
}

func (t *sshRemotePKI) RollbackFiles(files []installFile) error {
	var cmd strings.Builder
	for _, f := range files {
		b := ssh.ShellQuote(f.path + preRenewSuffix)
		fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s; fi; rm -f -- %s; ", b, b, ssh.ShellQuote(f.path),
			ssh.ShellQuote(stagedPath(f.path)))
	}
	return t.sc.Run(cmd.String())
}

func (t *sshRemotePKI) CommitFiles(files []installFile) error {
	var cmd strings.Builder
	cmd.WriteString("rm -f --")
	for _, f := range files {
		cmd.WriteString(" " + ssh.ShellQuote(f.path+preRenewSuffix))
	}
	return t.sc.Run(cmd.String())
}

func (t *sshRemotePKI) ReloadLibvirtTLS() error {
	// The monolithic daemon first, then the modular proxy daemon that owns the
	// TLS socket on newer distributions.
	return t.sc.Run("virt-admin server-update-tls libvirtd >/dev/null 2>&1 || " +
		"virt-admin -c virtproxyd:///system server-update-tls virtproxyd >/dev/null 2>&1")
}

func (t *sshRemotePKI) Remove(paths []string) error {
	var cmd strings.Builder
	cmd.WriteString("set -e; ")
	for _, p := range paths {
		fmt.Fprintf(&cmd, "rm -f -- %s; ", ssh.ShellQuote(p))
	}
	return t.sc.Run(cmd.String())
}

func stagedPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".renew")
}

// LocalRemotePKI is remotePKI over a directory this process can reach — the
// pki directory of the node it runs on, or a test's — running the host side
// in-process. Paths under /etc/litevirt/pki map into Dir.
type LocalRemotePKI struct {
	Dir string
	// FailInstallAfterSwitch makes InstallIdentity report an error after the
	// switch (a dropped connection, for tests).
	FailInstallAfterSwitch bool
	reloaded               bool
}

func (d *LocalRemotePKI) local(path string) string {
	return filepath.Join(d.Dir, strings.TrimPrefix(path, remotePKIDir+"/"))
}

func (d *LocalRemotePKI) ReadFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(d.local(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (d *LocalRemotePKI) GenCSR(hostName string) (string, []byte, string, error) {
	outside := pki.LegacyKeyOutside(d.Dir)
	id, csr, err := pki.GenerateRenewalCSR(d.Dir, hostName)
	return id, csr, outside, err
}

func (d *LocalRemotePKI) DiscardIdentity(serial string) error {
	return pki.DiscardIdentity(d.Dir, serial)
}

func (d *LocalRemotePKI) InstallIdentity(staging string, certPEM []byte) error {
	if _, _, err := pki.InstallRenewal(d.Dir, staging, certPEM); err != nil {
		return err
	}
	if d.FailInstallAfterSwitch {
		return errors.New("connection lost")
	}
	return nil
}

func (d *LocalRemotePKI) AbandonStaging(staging string) error {
	return pki.AbandonStaging(d.Dir, staging)
}

func (d *LocalRemotePKI) RollbackIdentity(serial string) error {
	return pki.RollbackRenewal(d.Dir, serial)
}

func (d *LocalRemotePKI) CommitIdentity() error { return pki.CommitRenewal(d.Dir) }

func (d *LocalRemotePKI) InstallFiles(files []installFile) error {
	for _, f := range files {
		if b, err := os.ReadFile(d.local(f.path)); err == nil {
			if err := secretfile.Write(d.local(f.path+preRenewSuffix), b, 0o600); err != nil {
				return err
			}
		}
	}
	for _, f := range files {
		if err := secretfile.Write(d.local(f.path), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func (d *LocalRemotePKI) RollbackFiles(files []installFile) error {
	for _, f := range files {
		b := d.local(f.path + preRenewSuffix)
		if _, err := os.Stat(b); err == nil {
			if err := os.Rename(b, d.local(f.path)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *LocalRemotePKI) CommitFiles(files []installFile) error {
	for _, f := range files {
		os.Remove(d.local(f.path + preRenewSuffix))
	}
	return nil
}

func (d *LocalRemotePKI) ReloadLibvirtTLS() error { d.reloaded = true; return nil }

func (d *LocalRemotePKI) Remove(paths []string) error {
	for _, p := range paths {
		if err := os.Remove(d.local(p)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
