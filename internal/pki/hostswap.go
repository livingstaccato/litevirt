package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Crash-safe host identity swaps (`lv host renew-cert`).
//
// host.crt and host.key are two files, and no sequence of renames of two
// files is atomic: a crash between them leaves a key that does not match its
// certificate, and a daemon that starts on that pair has no listener. So a
// renewed identity is installed as ONE unit:
//
//	pki_dir/host.crt           -> host.d/current/host.crt   (symlink)
//	pki_dir/host.key           -> host.d/current/host.key   (symlink)
//	pki_dir/host.d/current     -> <serial>                  (symlink)
//	pki_dir/host.d/<serial>/   host.crt + host.key, a matched pair
//
// and the switch is a single rename of the `current` symlink. Every path a
// reader takes — the daemon, libvirt's symlinks, `lv host init` — resolves
// through `current`, so at any instant it names one complete pair.
//
// The new key is generated HERE, on the host (GenerateRenewalCSR): the CA side
// sees only a certificate signing request and returns only a certificate, so
// the private key never leaves the machine that uses it.
//
// The first renewal of a node converts the legacy layout (two regular files)
// into this one. Each conversion step replaces one path with a symlink to a
// copy of identical content, so a crash anywhere in it still leaves a matched
// pair; RecoverHostIdentity finishes or repairs whatever a crash left.

const (
	hostDirName     = "host.d"
	currentLinkName = "current"
	stagingPrefix   = ".staging-"
)

// swapCrashHook lets tests stop InstallRenewal after a named step, as a crash
// would. Nil in production.
var swapCrashHook func(step string) error

func crashPoint(step string) error {
	if swapCrashHook != nil {
		return swapCrashHook(step)
	}
	return nil
}

func hostDir(pkiDir string) string { return filepath.Join(pkiDir, hostDirName) }

// GenerateRenewalCSR creates a fresh P-256 key for cn in a new staging
// directory under pki_dir/host.d (key 0600, never leaves the host) and returns
// the staging id and a PEM certificate signing request for it.
func GenerateRenewalCSR(pkiDir, cn string) (string, []byte, error) {
	if cn == "" {
		return "", nil, errors.New("host name required")
	}
	if err := os.MkdirAll(hostDir(pkiDir), 0o700); err != nil {
		return "", nil, err
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(buf)
	dir := filepath.Join(hostDir(pkiDir), stagingPrefix+id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", nil, err
	}
	if err := secretfile.Write(filepath.Join(dir, "host.key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return "", nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{Organization: []string{"litevirt"}, CommonName: cn},
	}, key)
	if err != nil {
		return "", nil, err
	}
	return id, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

// InstallRenewal adopts certPEM as this host's identity: it must match the
// staged key, chain to the cluster CA as a host certificate, and name the same
// host as the installed one. It returns the serials (lower-case hex) of the
// identity it replaced and of the new one.
func InstallRenewal(pkiDir, stagingID string, certPEM []byte) (prevSerial, newSerial string, err error) {
	if stagingID == "" || strings.ContainsAny(stagingID, "/.") {
		return "", "", fmt.Errorf("invalid staging id %q", stagingID)
	}
	staging := filepath.Join(hostDir(pkiDir), stagingPrefix+stagingID)
	// A renewed key is written by this build (GenerateRenewalCSR), so it is
	// held to the strict rules — unlike the identity main installed.
	if err := checkKeyFile(filepath.Join(staging, "host.key")); err != nil {
		return "", "", fmt.Errorf("the staged key: %w", err)
	}
	keyPEM, err := readBounded(filepath.Join(staging, "host.key"))
	if err != nil {
		return "", "", fmt.Errorf("read the staged key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", "", fmt.Errorf("the certificate does not match the key staged on this host: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", err
	}
	cur, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, "host.crt"), filepath.Join(pkiDir, "host.key"))
	if err != nil {
		return "", "", fmt.Errorf("the installed identity does not load; repair it before renewing: %w", err)
	}
	curLeaf, err := x509.ParseCertificate(cur.Certificate[0])
	if err != nil {
		return "", "", err
	}
	if err := checkSameIdentity(pkiDir, curLeaf.Subject.CommonName, leaf,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}); err != nil {
		return "", "", err
	}
	prevSerial = strings.ToLower(curLeaf.SerialNumber.Text(16))
	newSerial = strings.ToLower(leaf.SerialNumber.Text(16))
	if prevSerial == newSerial {
		return "", "", errors.New("the certificate is the one already installed")
	}

	if err := secretfile.Write(filepath.Join(staging, "host.crt"), certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := crashPoint("staged"); err != nil {
		return "", "", err
	}
	final := filepath.Join(hostDir(pkiDir), newSerial)
	if err := os.Rename(staging, final); err != nil {
		return "", "", fmt.Errorf("place the new identity: %w", err)
	}
	if err := crashPoint("placed"); err != nil {
		return "", "", err
	}
	if err := ensureLinkedLayout(pkiDir, prevSerial); err != nil {
		return "", "", err
	}
	if err := switchCurrent(pkiDir, newSerial); err != nil {
		return "", "", err
	}
	if err := crashPoint("switched"); err != nil {
		return "", "", err
	}
	return prevSerial, newSerial, nil
}

// ensureLinkedLayout converts the legacy two-file layout into the linked one
// (see the package comment above), one consistent step at a time. Idempotent.
func ensureLinkedLayout(pkiDir, curSerial string) error {
	cur := filepath.Join(hostDir(pkiDir), currentLinkName)
	if _, err := os.Lstat(cur); errors.Is(err, os.ErrNotExist) {
		dir := filepath.Join(hostDir(pkiDir), curSerial)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		for _, f := range []struct {
			name string
			mode os.FileMode
		}{{"host.key", 0o600}, {"host.crt", 0o644}} {
			b, err := readBounded(filepath.Join(pkiDir, f.name))
			if err != nil {
				return err
			}
			if err := secretfile.Write(filepath.Join(dir, f.name), b, f.mode); err != nil {
				return err
			}
		}
		if err := crashPoint("copied-legacy"); err != nil {
			return err
		}
		if err := atomicSymlink(curSerial, cur); err != nil {
			return err
		}
		if err := crashPoint("current-created"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// Key first, then certificate — both now point at the pair `current`
	// names, which until the switch is the very pair the regular files held.
	for _, name := range []string{"host.key", "host.crt"} {
		p := filepath.Join(pkiDir, name)
		want := filepath.Join(hostDirName, currentLinkName, name)
		if dst, err := os.Readlink(p); err == nil && dst == want {
			continue
		}
		if err := atomicSymlink(want, p); err != nil {
			return err
		}
		if err := crashPoint("linked-" + name); err != nil {
			return err
		}
	}
	return nil
}

// atomicSymlink points path at target with one rename.
func atomicSymlink(target, path string) error {
	tmp := path + ".tmp-link"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func switchCurrent(pkiDir, serial string) error {
	if _, err := os.Stat(filepath.Join(hostDir(pkiDir), serial, "host.crt")); err != nil {
		return fmt.Errorf("no identity %s on this host: %w", serial, err)
	}
	return atomicSymlink(serial, filepath.Join(hostDir(pkiDir), currentLinkName))
}

// RollbackRenewal points the identity back at serial (one rename). An
// identity that is already serial — the switch never happened — is left alone.
func RollbackRenewal(pkiDir, serial string) error {
	serial = strings.ToLower(serial)
	if s, err := CertSerial(filepath.Join(pkiDir, "host.crt")); err == nil && strings.EqualFold(s, serial) {
		return nil
	}
	return switchCurrent(pkiDir, serial)
}

// CommitRenewal deletes every identity under host.d except the current one —
// including the replaced key, so it no longer exists anywhere — and any
// staging directory.
func CommitRenewal(pkiDir string) error {
	cur, err := os.Readlink(filepath.Join(hostDir(pkiDir), currentLinkName))
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(hostDir(pkiDir))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == currentLinkName || e.Name() == cur || !e.IsDir() {
			continue
		}
		if err := os.RemoveAll(filepath.Join(hostDir(pkiDir), e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// AbandonStaging removes one staging directory (a renewal that will not be
// installed).
func AbandonStaging(pkiDir, stagingID string) error {
	if stagingID == "" || strings.ContainsAny(stagingID, "/.") {
		return fmt.Errorf("invalid staging id %q", stagingID)
	}
	return os.RemoveAll(filepath.Join(hostDir(pkiDir), stagingPrefix+stagingID))
}

// RecoverHostIdentity runs before the daemon loads its identity. When
// host.crt/host.key load as a matched pair it changes nothing. When they do
// not — a crash, a hand edit, a dangling `current` — it points `current` at
// the newest complete identity under host.d that chains to the cluster CA and
// names hostName, and says so. Staging directories older than an hour (a
// renewal that died before installing) are removed.
func RecoverHostIdentity(pkiDir, hostName string) (bool, error) {
	if entries, err := os.ReadDir(hostDir(pkiDir)); err == nil {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), stagingPrefix) {
				continue
			}
			if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > time.Hour {
				_ = os.RemoveAll(filepath.Join(hostDir(pkiDir), e.Name()))
			}
		}
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, "host.crt"), filepath.Join(pkiDir, "host.key")); err == nil {
		return false, nil
	}
	entries, err := os.ReadDir(hostDir(pkiDir))
	if err != nil {
		return false, fmt.Errorf("the host identity does not load and there is no %s to recover from", hostDirName)
	}
	type cand struct {
		serial string
		nb     time.Time
	}
	var cands []cand
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(hostDir(pkiDir), e.Name())
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"))
		if err != nil {
			continue
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || checkSameIdentity(pkiDir, hostName, leaf,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) != nil {
			continue
		}
		cands = append(cands, cand{e.Name(), leaf.NotBefore})
	}
	if len(cands) == 0 {
		return false, fmt.Errorf("the host identity does not load and no complete identity under %s names %s",
			hostDir(pkiDir), hostName)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].nb.After(cands[j].nb) })
	if err := switchCurrent(pkiDir, cands[0].serial); err != nil {
		return false, err
	}
	if err := ensureLinkedLayout(pkiDir, cands[0].serial); err != nil {
		return false, err
	}
	slog.Warn("the host identity did not load (an interrupted renewal?); recovered the newest complete one",
		"serial", cands[0].serial, "dir", hostDir(pkiDir))
	return true, nil
}

// RenewLocal renews the identity in pkiDir on a machine that holds the CA key
// itself: request, signature and install all happen here, so the new key still
// never leaves the host. It returns the replaced and the new serial. The
// replaced identity is kept under host.d until CommitRenewal.
func RenewLocal(caCertPath, caKeyPath, pkiDir, hostName string) (prevSerial, newSerial string, err error) {
	prev, err := ServedHostCertificate(pkiDir)
	if err != nil {
		return "", "", err
	}
	id, csr, err := GenerateRenewalCSR(pkiDir, hostName)
	if err != nil {
		return "", "", err
	}
	certPEM, err := SignRenewal(caCertPath, caKeyPath, prev, hostName, csr)
	if err != nil {
		_ = AbandonStaging(pkiDir, id)
		return "", "", err
	}
	return InstallRenewal(pkiDir, id, certPEM)
}
