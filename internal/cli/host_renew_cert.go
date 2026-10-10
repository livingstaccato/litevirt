package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// HostRenewCert replaces a running host's cluster (mTLS) certificate with a
// successor from the same CA, without restarting it, partitioning it, or
// giving any peer a reason to fence it.
//
// Why each step is where it is:
//
//   - The successor names the installed certificate as its predecessor
//     (pki.RenewHostCert). Peers pin each host's serial, and that pin is what
//     keeps a re-admitted name's old certificate out — so it cannot just be
//     relaxed. A peer whose record still names the predecessor accepts the
//     successor at once, which is what makes the swap invisible to the cluster.
//     The command refuses if the cluster's record and the installed
//     certificate disagree: a successor of a certificate nobody recorded would
//     be refused by every peer until replication caught up.
//   - The daemon serves its identity from disk at handshake time and re-records
//     its own serial within a minute (pki.KeyPairSource, daemon certWatch), so
//     installing the files is the whole hand-over. The command then CHECKS that
//     the host presents the new certificate before going further, and puts the
//     old pair back if it does not.
//   - Only then is the old certificate revoked. Revocation is what makes a
//     renewal retire a key rather than add one: without it the old certificate
//     stays a valid client credential for the rest of its five years. It comes
//     last because a host still presenting a revoked certificate is refused by
//     every peer — the one outcome this command must never produce.
//   - An audit admission record (audit-rejoin.json) is bound to the host
//     certificate's serial and ignored for any other. A re-added host renewed
//     before its audit history caught up would lose its hold on the next
//     start, so the record is re-signed for the new serial in the same swap.
//
// libvirt's TLS listener (qemu+tls:// migration) reads the same files through
// symlinks but only when told to; the command asks it to reload, and says so if
// it cannot. libvirt does not consult the cluster CRL, so a listener still on
// the old certificate keeps working until its next restart.
//
// Migration-TLS certificates (pki_dir/migration, a separate CA) are not
// touched; they are rotated with the migration CA.
type RenewCertOptions struct {
	// SSHTarget reaches the host; default root@<host>.
	SSHTarget string
	// GRPCPort is the host's gRPC port, dialled to confirm the certificate it
	// presents. Default 7443.
	GRPCPort int
	// KeepOld leaves the replaced certificate unrevoked.
	KeepOld bool
	// Wait bounds each confirmation (served certificate, re-recorded serial).
	Wait time.Duration
}

const remotePKIDir = "/etc/litevirt/pki"

// renewTarget is what renewal needs from the host's machine. The SSH form is
// sshRenewTarget; tests use a directory.
type renewTarget interface {
	// ReadFile returns path's contents, or ok=false when it does not exist.
	ReadFile(path string) (data []byte, ok bool, err error)
	// Install puts each file in place, keeping the files it replaces so
	// Rollback can restore them. Every file lands by rename; the private key
	// is never readable beyond its mode.
	Install(files []installFile) error
	// Rollback restores what the last Install replaced.
	Rollback(files []installFile) error
	// Commit drops the copies Install kept.
	Commit(files []installFile) error
	// ReloadLibvirtTLS asks libvirt's TLS listener to re-read its certificate.
	ReloadLibvirtTLS() error
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
	if opts.SSHTarget == "" {
		opts.SSHTarget = "root@" + hostName
	}
	if opts.GRPCPort == 0 {
		opts.GRPCPort = 7443
	}
	if opts.Wait == 0 {
		opts.Wait = 90 * time.Second
	}
	addr, err := hostAddress(ctx, c, hostName)
	if err != nil {
		return err
	}
	sc, err := ssh.NewClient(opts.SSHTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()
	probe := func(ctx context.Context) (*x509.Certificate, error) {
		return dialServedCert(ctx, net.JoinHostPort(addr, strconv.Itoa(opts.GRPCPort)))
	}
	return renewHostCert(ctx, c, &sshRenewTarget{sc: sc}, probe, hostName, opts)
}

// renewHostCert is HostRenewCert past the connections, so it can be driven
// against a directory and a fake cluster.
func renewHostCert(ctx context.Context, c pb.LiteVirtClient, r renewTarget, probe servedCertProbe,
	hostName string, opts RenewCertOptions) error {
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

	recorded, err := hostCertSerial(ctx, c, hostName)
	if err != nil {
		return fmt.Errorf("read %s's recorded certificate serial: %w", hostName, err)
	}
	if !strings.EqualFold(recorded, prevSerial) {
		return fmt.Errorf("the cluster records certificate %s for %s, but the host holds %s. A successor "+
			"of a certificate the cluster does not record would be refused by every peer until "+
			"replication catches up. The daemon re-records its own serial within a minute of starting "+
			"(or of adopting a renewal) — wait for `lv host inspect %s` to show %s, then retry",
			recorded, hostName, prevSerial, hostName, prevSerial)
	}

	certPEM, keyPEM, err := pki.RenewHostCert(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"), prev, hostName)
	if err != nil {
		return fmt.Errorf("mint the renewed certificate: %w", err)
	}
	next, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return err
	}
	nextSerial := strings.ToLower(next.SerialNumber.Text(16))

	// Key first, certificate second: the daemon adopts a pair only once both
	// match, so the order does not matter to it — but a reader of host.crt
	// alone (the serial the daemon records at boot) should only ever see a
	// certificate whose key is already in place.
	files := []installFile{
		{path: filepath.Join(remotePKIDir, "host.key"), data: keyPEM, mode: 0o600},
		{path: certPath, data: certPEM, mode: 0o644},
	}
	rejoin, err := resignedRejoin(r, pkiDir, hostName, prevPEM, prevSerial, nextSerial)
	if err != nil {
		return err
	}
	if rejoin != nil {
		files = append(files, *rejoin)
	}

	slog.Info("installing renewed host certificate", "host", hostName, "serial", nextSerial, "replaces", prevSerial)
	if err := r.Install(files); err != nil {
		if rbErr := r.Rollback(files); rbErr != nil {
			return fmt.Errorf("install the renewed certificate on %s: %w (and restoring the previous one "+
				"failed: %v — check %s by hand)", hostName, err, rbErr, remotePKIDir)
		}
		return fmt.Errorf("install the renewed certificate on %s: %w (the previous one was restored)", hostName, err)
	}

	served, err := waitServedSerial(ctx, probe, nextSerial, opts.Wait)
	if err != nil {
		rbErr := r.Rollback(files)
		if rbErr != nil {
			return fmt.Errorf("%s did not start presenting the renewed certificate (%v), and restoring the "+
				"previous pair failed: %v — check %s by hand. Nothing was revoked", hostName, err, rbErr, remotePKIDir)
		}
		return fmt.Errorf("%s did not start presenting the renewed certificate (%v, last presented %s); "+
			"the previous pair was restored and nothing was revoked. Check `journalctl -u litevirt` on %s",
			hostName, err, served, hostName)
	}
	if err := r.Commit(files); err != nil {
		fmt.Printf("  NOTE: could not remove the previous pair's backup in %s: %v\n", remotePKIDir, err)
	}

	fmt.Printf("Host certificate renewed for %s\n", hostName)
	fmt.Printf("  serial %s replaces %s; valid until %s\n", nextSerial, prevSerial, next.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("  %s presents it now — no restart; peers accept it as the recorded certificate's successor\n", hostName)
	if rejoin != nil {
		fmt.Println("  the host's audit admission record was re-signed for the new serial")
	}
	if err := r.ReloadLibvirtTLS(); err != nil {
		fmt.Printf("  NOTE: libvirt's TLS listener did not reload (%v); it keeps serving the previous\n", err)
		fmt.Println("  certificate for qemu+tls:// migration until it restarts. libvirt does not read the")
		fmt.Println("  cluster CRL, so migrations keep working meanwhile")
	} else {
		fmt.Println("  libvirt's TLS listener reloaded the renewed certificate")
	}

	if waitRecordedSerial(ctx, c, hostName, nextSerial, opts.Wait) {
		fmt.Println("  the cluster now records the renewed serial")
	} else {
		fmt.Printf("  NOTE: the cluster does not record %s yet; peers accept it as the recorded\n", nextSerial)
		fmt.Println("  certificate's successor meanwhile, and the daemon keeps re-recording it")
	}

	if opts.KeepOld {
		fmt.Printf("  the previous certificate %s was NOT revoked (--keep-old): peers no longer accept it as\n", prevSerial)
		fmt.Printf("  %s once the new serial is recorded, but it stays a CA-valid credential until %s\n",
			hostName, prev.NotAfter.UTC().Format("2006-01-02"))
		return nil
	}
	if err := revokeHostCert(pkiDir, hostName, prevSerial); err != nil {
		return fmt.Errorf("the renewal is complete, but revoking the previous certificate %s failed: %w. "+
			"It stays a valid credential until revoked", prevSerial, err)
	}
	version, err := publishClusterCRL(ctx, c, pkiDir)
	if err != nil {
		return fmt.Errorf("the renewal is complete and %s is revoked in %s, but publishing the CRL failed: %w. "+
			"Retry with `lv host publish-crl`", prevSerial, filepath.Join(pkiDir, "crl.pem"), err)
	}
	fmt.Printf("  revoked the previous certificate %s in CRL %d\n", prevSerial, version)
	return nil
}

// resignedRejoin returns the host's audit admission record re-signed for
// nextSerial, or nil when there is none to carry over. Only a record that
// verifies against the cluster CA and is bound to the certificate being
// replaced is carried: re-signing anything else would launder it.
func resignedRejoin(r renewTarget, pkiDir, hostName string, prevPEM []byte, prevSerial, nextSerial string) (*installFile, error) {
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
	// Verify it the way the daemon does, against a scratch pki dir holding
	// exactly what the host holds.
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

func waitServedSerial(ctx context.Context, probe servedCertProbe, want string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	last := "nothing"
	for {
		c, err := probe(ctx)
		if err == nil && c != nil {
			last = strings.ToLower(c.SerialNumber.Text(16))
			if last == want {
				return last, nil
			}
		} else if err != nil {
			last = "an error: " + err.Error()
		}
		if time.Now().After(deadline) {
			return last, fmt.Errorf("still presenting %s after %s", last, wait)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
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
// machine cannot sign: there is no CSR flow.
func requireCAKey(pkiDir, what string) error {
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caKeyPath); err != nil {
		return fmt.Errorf("no cluster CA private key at %s: %s must be run from the machine that ran "+
			"`lv host init`, because it signs with the CA private key and litevirt has no CSR flow", caKeyPath, what)
	}
	return nil
}

func orNotFound(err error) error {
	if err == nil {
		return os.ErrNotExist
	}
	return err
}

// sshRenewTarget is renewTarget over SSH.
type sshRenewTarget struct{ sc *ssh.Client }

func (t *sshRenewTarget) ReadFile(path string) ([]byte, bool, error) {
	q := ssh.ShellQuote(path)
	// One command, two answers: a marker for absence, so an empty file and a
	// missing one are not confused, and a read error is still an error.
	out, err := t.sc.RunOutput(fmt.Sprintf("if [ -e %s ]; then cat -- %s; else printf '%s'; fi", q, q, absentMarker))
	if err != nil {
		return nil, false, err
	}
	if string(out) == absentMarker {
		return nil, false, nil
	}
	return out, true, nil
}

const absentMarker = "__litevirt_file_absent__"

const preRenewSuffix = ".pre-renew"

func (t *sshRenewTarget) Install(files []installFile) error {
	// Stage everything first: a dropped connection mid-transfer must leave the
	// installed pair untouched.
	for _, f := range files {
		if err := t.sc.WriteFile(stagedPath(f.path), f.data, f.mode); err != nil {
			return fmt.Errorf("stage %s: %w", filepath.Base(f.path), err)
		}
	}
	var cmd strings.Builder
	cmd.WriteString("set -e; ")
	for _, f := range files {
		q := ssh.ShellQuote(f.path)
		// cp -p keeps the key's 0600 on its backup.
		fmt.Fprintf(&cmd, "if [ -e %s ]; then cp -p -- %s %s; fi; ", q, q, ssh.ShellQuote(f.path+preRenewSuffix))
	}
	for _, f := range files {
		fmt.Fprintf(&cmd, "mv -fT -- %s %s; ", ssh.ShellQuote(stagedPath(f.path)), ssh.ShellQuote(f.path))
	}
	return t.sc.Run(cmd.String())
}

func (t *sshRenewTarget) Rollback(files []installFile) error {
	var cmd strings.Builder
	for _, f := range files {
		b := ssh.ShellQuote(f.path + preRenewSuffix)
		fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s; fi; rm -f -- %s; ", b, b, ssh.ShellQuote(f.path),
			ssh.ShellQuote(stagedPath(f.path)))
	}
	return t.sc.Run(cmd.String())
}

func (t *sshRenewTarget) Commit(files []installFile) error {
	var cmd strings.Builder
	cmd.WriteString("rm -f --")
	for _, f := range files {
		cmd.WriteString(" " + ssh.ShellQuote(f.path+preRenewSuffix))
	}
	return t.sc.Run(cmd.String())
}

func (t *sshRenewTarget) ReloadLibvirtTLS() error {
	// The monolithic daemon first, then the modular proxy daemon that owns the
	// TLS socket on newer distributions.
	return t.sc.Run("virt-admin server-update-tls libvirtd >/dev/null 2>&1 || " +
		"virt-admin -c virtproxyd:///system server-update-tls virtproxyd >/dev/null 2>&1")
}

func stagedPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".renew")
}
