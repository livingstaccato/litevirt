package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// UICertOptions configures `lv host ui-cert set|clear`.
type UICertOptions struct {
	// SSHTarget reaches the host; default root@<host>.
	SSHTarget string
	// CertPath / KeyPath are local files: the chain (leaf first) and its key.
	CertPath, KeyPath string
	// Names the UI is reached by; every one must be covered by the
	// certificate. Empty: it must cover the host's litevirt name or address.
	Names []string
}

// HostUICertSet installs an operator-supplied certificate for the web UI
// (corporate PKI) on one host.
//
// The chain and key are validated HERE, before anything is sent (pki.
// ValidateServingChain: key matches, chain in order, nothing expired, a server
// certificate, and SANs covering the names), so a mistake is reported with
// the reason rather than discovered as a browser warning. The daemon re-checks
// the same properties before it serves the pair. The key goes over SSH into
// pki_dir/ui.key at 0600 — the same handling as the host's own key — and is
// never printed or logged; the local copy is the operator's to keep or delete.
//
// The daemon serves it from the next handshake and, if the UI was plain HTTP,
// switches the listener to HTTPS within seconds. `lv host ui-cert clear` is the
// way back to ACME or the cluster certificate.
func HostUICertSet(ctx context.Context, c pb.LiteVirtClient, hostName string, opts UICertOptions) error {
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
	return hostUICertSet(&sshRemotePKI{sc: sc}, hostName, addr, opts)
}

func hostUICertSet(r remotePKI, hostName, addr string, opts UICertOptions) error {
	if opts.CertPath == "" || opts.KeyPath == "" {
		return fmt.Errorf("--cert and --key are both required")
	}
	chainPEM, err := os.ReadFile(opts.CertPath)
	if err != nil {
		return fmt.Errorf("read --cert: %w", err)
	}
	keyPEM, err := os.ReadFile(opts.KeyPath)
	if err != nil {
		return fmt.Errorf("read --key: %w", err)
	}
	leaf, err := pki.ValidateServingChain(chainPEM, keyPEM, pki.ServingCertCheck{
		AnyOf: []string{hostName, addr},
		AllOf: opts.Names,
	})
	if err != nil {
		return fmt.Errorf("refusing to install %s: %w", opts.CertPath, err)
	}
	files := []installFile{
		{path: filepath.Join(remotePKIDir, pki.UIKeyName), data: keyPEM, mode: 0o600},
		{path: filepath.Join(remotePKIDir, pki.UICertName), data: chainPEM, mode: 0o644},
	}
	if err := r.InstallFiles(files); err != nil {
		if rbErr := r.RollbackFiles(files); rbErr != nil {
			return fmt.Errorf("install the UI certificate on %s: %w (restoring the previous one failed: %v)", hostName, err, rbErr)
		}
		return fmt.Errorf("install the UI certificate on %s: %w (the previous one, if any, was restored)", hostName, err)
	}
	if err := r.CommitFiles(files); err != nil {
		fmt.Printf("  NOTE: could not remove the previous certificate's backup in %s: %v\n", remotePKIDir, err)
	}
	fmt.Printf("UI certificate installed on %s\n", hostName)
	fmt.Printf("  subject %s, issued by %s\n", leaf.Subject, leaf.Issuer)
	fmt.Printf("  names: %s\n", certNames(leaf))
	fmt.Printf("  valid until %s (%d days)\n", leaf.NotAfter.UTC().Format(time.RFC3339), int(time.Until(leaf.NotAfter).Hours()/24))
	fmt.Println("  served from the next TLS handshake; a UI serving plain HTTP switches to HTTPS within seconds")
	fmt.Println("  the daemon warns (certificate.expiring) from 30 days before it expires")
	fmt.Printf("  check it with `lv acme status %s`; undo with `lv host ui-cert clear %s`\n", addr, hostName)
	return nil
}

// certNames lists a certificate's DNS and IP SANs.
func certNames(c *x509.Certificate) string {
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	return strings.Join(names, ", ")
}

// HostUICertClear removes a host's custom UI certificate. The daemon then
// serves ACME's certificate when acme: is configured, else the cluster
// certificate — or plain HTTP, when ui_tls is auto and ACME is not configured,
// which is where a UI without a certificate of its own has always been.
func HostUICertClear(ctx context.Context, hostName string, opts UICertOptions) error {
	if opts.SSHTarget == "" {
		opts.SSHTarget = "root@" + hostName
	}
	sc, err := ssh.NewClient(opts.SSHTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()
	return hostUICertClear(&sshRemotePKI{sc: sc}, hostName)
}

func hostUICertClear(r remotePKI, hostName string) error {
	// Certificate first: the daemon only serves a custom pair while BOTH
	// files are present, so the key is never left as the only half.
	if err := r.Remove([]string{
		filepath.Join(remotePKIDir, pki.UICertName),
		filepath.Join(remotePKIDir, pki.UIKeyName),
	}); err != nil {
		return fmt.Errorf("remove the UI certificate on %s: %w", hostName, err)
	}
	fmt.Printf("Custom UI certificate removed from %s\n", hostName)
	fmt.Println("  the UI now serves ACME's certificate if acme: is configured, else the cluster")
	fmt.Println("  certificate under ui_tls: on, else plain HTTP (ui_tls: auto, the default)")
	return nil
}
