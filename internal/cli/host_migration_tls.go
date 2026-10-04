package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"

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

// ensureLocalMigrationCA returns the migration CA beside the cluster CA in
// pkiDir, minting it the first time.
func ensureLocalMigrationCA(pkiDir string) (certPath, keyPath string, minted bool, err error) {
	certPath = filepath.Join(pkiDir, pki.MigrationCACertName)
	keyPath = filepath.Join(pkiDir, pki.MigrationCAKeyName)
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, false, nil
	} else if !os.IsNotExist(err) {
		return "", "", false, err
	}
	if err := pki.GenerateMigrationCA(certPath, keyPath); err != nil {
		return "", "", false, fmt.Errorf("generate migration CA: %w", err)
	}
	slog.Info("generated the cluster's migration CA", "path", certPath)
	return certPath, keyPath, true, nil
}

// migrationFile is one file of a host's migration-credential set.
type migrationFile struct {
	local, remote string
	mode          os.FileMode
}

// issueMigrationCredentials mints the migration CA if needed and issues
// hostName's migration certificate for ip. It returns the three files to put in
// the host's migration directory: the CA, the certificate, and the key (0600).
func issueMigrationCredentials(pkiDir, hostName string, ip net.IP) ([]migrationFile, error) {
	caCert, caKey, _, err := ensureLocalMigrationCA(pkiDir)
	if err != nil {
		return nil, err
	}
	cert := filepath.Join(pkiDir, hostName+"-migration.crt")
	key := filepath.Join(pkiDir, hostName+"-migration.key")
	if err := pki.GenerateHostCert(caCert, caKey, cert, key, hostName, ip); err != nil {
		return nil, fmt.Errorf("issue %s's migration certificate: %w", hostName, err)
	}
	return []migrationFile{
		{caCert, filepath.Join(remoteMigrationDir, pki.MigrationCAName), 0o644},
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
				return fmt.Errorf("%s has no migration CA, but %s already holds migration credentials, "+
					"so this cluster has one elsewhere. Run this from the machine that ran `lv host init`, "+
					"or copy its %s and %s here (the key mode 0600)",
					pkiDir, h.Name(), pki.MigrationCACertName, pki.MigrationCAKeyName)
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
		files, err := issueMigrationCredentials(pkiDir, h.Name(), ip)
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
	path := filepath.Join(remoteMigrationDir, pki.MigrationHostCertName)
	out, err := h.sc.RunOutput(fmt.Sprintf("if [ -e %s ]; then echo yes; else echo no; fi", ssh.ShellQuote(path)))
	if err != nil {
		return false, err
	}
	return string(out) == "yes\n", nil
}

func (h *sshMigrationTLSHost) Push(ctx context.Context, files []migrationFile) error {
	return pushMigrationCredentials(h.sc, files)
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
