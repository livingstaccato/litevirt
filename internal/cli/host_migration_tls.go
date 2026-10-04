package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// Migration TLS credentials: a separate migration CA, kept beside the cluster CA
// on the machine that runs `lv host init`, and one certificate per host, issued
// for the address peers dial. The daemon installs a host's set into QEMU's TLS
// directory (internal/pki InstallQemuMigrationTLS), so storage migrations
// between two provisioned hosts are encrypted.

// remoteMigrationDir is a host's migration-credential directory.
var remoteMigrationDir = pki.MigrationDir("/etc/litevirt/pki")

// migrationCredentialHolder names an existing cluster host that already holds
// migration credentials, or "" when none does. It is asked only when this
// machine has no migration CA and is about to mint one. A nil one means there
// is nobody to ask: `lv host init` founding a cluster.
type migrationCredentialHolder func() (holder string, err error)

// ensureLocalMigrationCA returns the migration CA beside the cluster CA in
// pkiDir, minting it the first time.
//
// It refuses to mint while a cluster host already holds migration credentials
// (existing names one): those came from a CA on another machine, and a second
// CA issues certificates they cannot verify. The new host would advertise
// migration TLS ready and every storage migration with it would then fail the
// QEMU TLS handshake. `lv host install-migration-tls` refuses the same way.
func ensureLocalMigrationCA(pkiDir string, existing migrationCredentialHolder) (certPath, keyPath string, minted bool, err error) {
	certPath = filepath.Join(pkiDir, pki.MigrationCACertName)
	keyPath = filepath.Join(pkiDir, pki.MigrationCAKeyName)
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, false, nil
	} else if !os.IsNotExist(err) {
		return "", "", false, err
	}
	if existing != nil {
		holder, err := existing()
		if err != nil {
			return "", "", false, fmt.Errorf("%s has no migration CA, and whether the cluster "+
				"already has one could not be checked: %w. Minting a second one would break storage "+
				"migrations with every host provisioned from the first; copy %s and %s here (the key "+
				"mode 0600) from the machine that holds them, or retry once a cluster host is reachable",
				pkiDir, err, pki.MigrationCACertName, pki.MigrationCAKeyName)
		}
		if holder != "" {
			return "", "", false, secondMigrationCAError(pkiDir, holder)
		}
	}
	if err := pki.GenerateMigrationCA(certPath, keyPath); err != nil {
		return "", "", false, fmt.Errorf("generate migration CA: %w", err)
	}
	slog.Info("generated the cluster's migration CA", "path", certPath)
	return certPath, keyPath, true, nil
}

// secondMigrationCAError is the refusal to mint a migration CA while holder
// already has credentials from the cluster's existing one.
func secondMigrationCAError(pkiDir, holder string) error {
	return fmt.Errorf("%s has no migration CA, but %s already holds migration credentials, "+
		"so this cluster has one elsewhere. Run this from the machine that ran `lv host init`, "+
		"or copy its %s and %s here (the key mode 0600)",
		pkiDir, holder, pki.MigrationCACertName, pki.MigrationCAKeyName)
}

// peerMigrationHolder asks the join peers, over SSH as sshUser, whether any
// already holds migration credentials. The first that does is the answer. A
// peer that cannot be reached is skipped, but when none can be, absence is
// not proven and that is an error.
func peerMigrationHolder(sshUser string, joinPeers []string) migrationCredentialHolder {
	return func() (string, error) {
		var why []string
		answered := 0
		for _, p := range joinPeers {
			target := sshTargetForPeer(sshUser, p)
			held, err := peerHoldsMigrationCredentials(target)
			if err != nil {
				why = append(why, fmt.Sprintf("%s: %v", target, err))
				continue
			}
			if held {
				return target, nil
			}
			answered++
		}
		if answered == 0 {
			return "", fmt.Errorf("no cluster host could be asked (%s)", strings.Join(why, "; "))
		}
		return "", nil
	}
}

// migrationCredsProbe is the remote command that answers "yes" when a host
// already holds migration credentials and "no" when it does not.
func migrationCredsProbe() string {
	path := filepath.Join(remoteMigrationDir, pki.MigrationHostCertName)
	return fmt.Sprintf("if [ -e %s ]; then echo yes; else echo no; fi", ssh.ShellQuote(path))
}

// peerHoldsMigrationCredentials reports over SSH whether a cluster host
// already holds migration credentials. A seam so the add path can be tested
// without a node to SSH into.
var peerHoldsMigrationCredentials = func(sshTarget string) (bool, error) {
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return false, fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()
	out, err := sc.RunOutput(migrationCredsProbe())
	if err != nil {
		return false, err
	}
	return string(out) == "yes\n", nil
}

// migrationFile is one file of a host's migration-credential set.
type migrationFile struct {
	local, remote string
	mode          os.FileMode
}

// migrationIssuingCA is the CA host certificates are issued from right now and
// the trust bundle each host's ca.crt gets. Mid-rotation that is the NEW CA,
// so a host added during a rotation is never left on the old one.
func migrationIssuingCA(pkiDir string) (caCert, caKey, trustBundle string, err error) {
	cur := filepath.Join(pkiDir, pki.MigrationCACertName)
	r, err := loadMigrationRotation(pkiDir)
	if err != nil {
		return "", "", "", err
	}
	if !r.inProgress() {
		return cur, filepath.Join(pkiDir, pki.MigrationCAKeyName), cur, nil
	}
	next, nextKey := filepath.Join(pkiDir, nextCACertName), filepath.Join(pkiDir, nextCAKeyName)
	if _, err := os.Stat(next); errors.Is(err, fs.ErrNotExist) {
		// Finalize already made the new CA current; only "done" is unsaved.
		return cur, filepath.Join(pkiDir, pki.MigrationCAKeyName), cur, nil
	}
	switch r.Phase {
	case phaseTrustBoth, phaseReissue:
		return next, nextKey, filepath.Join(pkiDir, bundleCACertName), nil
	default: // drop-old, cutover
		return next, nextKey, next, nil
	}
}

// issueMigrationCredentials mints the migration CA if needed (and existing
// allows; see ensureLocalMigrationCA) and issues hostName's migration
// certificate for ip. It returns the three files to put in the host's
// migration directory: the trust bundle (ca.crt), the certificate, and the
// key (0600). Mid-rotation the certificate is issued from the rotation's new
// CA and the trust bundle reflects the rotation's phase (migrationIssuingCA).
func issueMigrationCredentials(pkiDir, hostName string, ip net.IP, existing migrationCredentialHolder) ([]migrationFile, error) {
	if _, _, _, err := ensureLocalMigrationCA(pkiDir, existing); err != nil {
		return nil, err
	}
	caCert, caKey, trust, err := migrationIssuingCA(pkiDir)
	if err != nil {
		return nil, err
	}
	cert := filepath.Join(pkiDir, hostName+"-migration.crt")
	key := filepath.Join(pkiDir, hostName+"-migration.key")
	if err := pki.GenerateHostCert(caCert, caKey, cert, key, hostName, ip); err != nil {
		return nil, fmt.Errorf("issue %s's migration certificate: %w", hostName, err)
	}
	return []migrationFile{
		{trust, filepath.Join(remoteMigrationDir, pki.MigrationCAName), 0o644},
		{cert, filepath.Join(remoteMigrationDir, pki.MigrationHostCertName), 0o644},
		// 0600 and root's: the daemon copies it to QEMU's TLS directory owned by
		// the QEMU user. Nothing else on the host needs to read it.
		{key, filepath.Join(remoteMigrationDir, pki.MigrationHostKeyName), 0o600},
	}, nil
}

// pushMigrationCredentials puts a host's migration-credential set in place
// over SSH.
func pushMigrationCredentials(sc *ssh.Client, files []migrationFile) error {
	if err := sc.Run("mkdir -p -m 0700 " + ssh.ShellQuote(remoteMigrationDir)); err != nil {
		return fmt.Errorf("create %s: %w", remoteMigrationDir, err)
	}
	for _, f := range files {
		if err := sc.CopyFileMode(f.local, f.remote, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(f.remote), err)
		}
	}
	return nil
}

// MigrationTLSHost is one host `lv host install-migration-tls` provisions.
type MigrationTLSHost interface {
	Name() string
	Address() string
	// Provisioned reports whether the host already holds migration credentials.
	Provisioned(ctx context.Context) (bool, error)
	// Push installs a migration-credential set on the host.
	Push(ctx context.Context, files []migrationFile) error
}

// InstallMigrationTLS issues and pushes migration credentials to every host
// that has none (all of them with reissue). A host's daemon installs them for
// QEMU before its next storage migration; no restart is needed.
//
// It refuses to mint a NEW migration CA while a host already holds credentials:
// those came from another machine's CA, and certificates from a second CA would
// not verify against them.
func InstallMigrationTLS(ctx context.Context, pkiDir string, hosts []MigrationTLSHost, reissue bool, out io.Writer) error {
	if MigrationRotationInProgress(pkiDir) {
		return fmt.Errorf("a migration-CA rotation is in progress (%s); finish it with "+
			"`lv host rotate-migration-ca` before reissuing", filepath.Join(pkiDir, rotationFileName)) // ci:skip-cmd: rotate-migration-ca ships in a later task
	}
	provisioned := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		p, err := h.Provisioned(ctx)
		if err != nil {
			return fmt.Errorf("check %s: %w", h.Name(), err)
		}
		provisioned[h.Name()] = p
	}
	if _, err := os.Stat(filepath.Join(pkiDir, pki.MigrationCACertName)); os.IsNotExist(err) {
		for _, h := range hosts {
			if provisioned[h.Name()] {
				return secondMigrationCAError(pkiDir, h.Name())
			}
		}
	} else if err != nil {
		return err
	}

	done := 0
	for _, h := range hosts {
		if provisioned[h.Name()] && !reissue {
			fmt.Fprintf(out, "%s: already has migration credentials (pass --reissue to replace them)\n", h.Name())
			continue
		}
		ip := net.ParseIP(h.Address())
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("%s's recorded address %q is not an IPv4 address; its migration "+
				"certificate is issued for the address peers dial", h.Name(), h.Address())
		}
		// nil: every host was asked above, before anything was issued.
		files, err := issueMigrationCredentials(pkiDir, h.Name(), ip, nil)
		if err != nil {
			return err
		}
		if err := h.Push(ctx, files); err != nil {
			return fmt.Errorf("%s: %w", h.Name(), err)
		}
		fmt.Fprintf(out, "%s: migration credentials installed\n", h.Name())
		done++
	}
	fmt.Fprintf(out, "%d host(s) provisioned. Storage migrations between provisioned hosts are now encrypted.\n", done)
	return nil
}

// sshMigrationTLSHost is a MigrationTLSHost reached over SSH.
type sshMigrationTLSHost struct {
	name, address string
	sc            *ssh.Client
}

func (h *sshMigrationTLSHost) Name() string    { return h.name }
func (h *sshMigrationTLSHost) Address() string { return h.address }

func (h *sshMigrationTLSHost) Provisioned(ctx context.Context) (bool, error) {
	out, err := h.sc.RunOutput(migrationCredsProbe())
	if err != nil {
		return false, err
	}
	return string(out) == "yes\n", nil
}

func (h *sshMigrationTLSHost) Push(ctx context.Context, files []migrationFile) error {
	return pushMigrationCredentials(h.sc, files)
}

// MigrationRotationInProgress reports whether pkiDir holds an unfinished
// `lv host rotate-migration-ca`. An unreadable state file counts as in // ci:skip-cmd: rotate-migration-ca ships in a later task
// progress: guessing "no" would let a reissue mint from the wrong CA.
func MigrationRotationInProgress(pkiDir string) bool {
	r, err := loadMigrationRotation(pkiDir)
	return err != nil || r.inProgress()
}

// SSHMigrationTLSHosts connects to every host in the cluster as sshUser.
func SSHMigrationTLSHosts(ctx context.Context, c pb.LiteVirtClient, sshUser string) ([]MigrationTLSHost, func(), error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("list hosts: %w", err)
	}
	if sshUser == "" {
		sshUser = "root"
	}
	var hosts []MigrationTLSHost
	var conns []*ssh.Client
	closeAll := func() {
		for _, sc := range conns {
			sc.Close()
		}
	}
	for _, h := range resp.Hosts {
		if h.Address == "" {
			closeAll()
			return nil, nil, fmt.Errorf("host %s has no recorded address to reach it on", h.Name)
		}
		sc, err := ssh.NewClient(sshUser + "@" + h.Address)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("SSH to %s (%s): %w", h.Name, h.Address, err)
		}
		conns = append(conns, sc)
		hosts = append(hosts, &sshMigrationTLSHost{name: h.Name, address: h.Address, sc: sc})
	}
	return hosts, closeAll, nil
}

// unreachableMigrationHost is a cluster host SSH could not reach. Its Push
// returns the connect error, so the rotation stops on it, or skips it under
// --force, instead of refusing to start.
type unreachableMigrationHost struct {
	name, address string
	err           error
}

func (h *unreachableMigrationHost) Name() string                              { return h.name }
func (h *unreachableMigrationHost) Address() string                           { return h.address }
func (h *unreachableMigrationHost) Provisioned(context.Context) (bool, error) { return false, h.err }
func (h *unreachableMigrationHost) Push(context.Context, []migrationFile) error {
	return fmt.Errorf("SSH to %s: %w", h.address, h.err)
}

// SSHMigrationTLSHostsLenient is SSHMigrationTLSHosts for the rotation: a host
// SSH cannot reach is returned as unreachable rather than failing the list.
func SSHMigrationTLSHostsLenient(ctx context.Context, c pb.LiteVirtClient, sshUser string) ([]MigrationTLSHost, func(), error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("list hosts: %w", err)
	}
	if sshUser == "" {
		sshUser = "root"
	}
	var hosts []MigrationTLSHost
	var conns []*ssh.Client
	closeAll := func() {
		for _, sc := range conns {
			sc.Close()
		}
	}
	for _, h := range resp.Hosts {
		if h.Address == "" {
			hosts = append(hosts, &unreachableMigrationHost{h.Name, "", errors.New("no recorded address")})
			continue
		}
		sc, err := ssh.NewClient(sshUser + "@" + h.Address)
		if err != nil {
			hosts = append(hosts, &unreachableMigrationHost{h.Name, h.Address, err})
			continue
		}
		conns = append(conns, sc)
		hosts = append(hosts, &sshMigrationTLSHost{name: h.Name, address: h.Address, sc: sc})
	}
	return hosts, closeAll, nil
}
