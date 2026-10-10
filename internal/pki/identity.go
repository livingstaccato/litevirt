package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Hot-reloadable TLS identities.
//
// The host's TLS identity (host.crt / host.key) used to be read once: the gRPC
// listener's config was built at boot, the health checker cached the client
// config it dials peers with, and the UI's loopback connection did the same. So
// replacing the files on a running node changed nothing until a restart, and
// renewing a certificate meant bouncing the daemon.
//
// A KeyPairSource serves the pair from disk instead, re-reading it when either
// file changes (mtime, size or inode — an atomic rename always gives a new inode,
// so a same-second, same-size replacement is still seen). Every TLS config this
// package builds asks it for the certificate at handshake time, so a renewed
// pair is in use from the next handshake on. Established connections keep the
// certificate they negotiated.
//
// A CHANGED pair is adopted only if it passes the source's check; anything else
// is logged and the pair being served stays. Two cases make that the right
// direction:
//
//   - a torn replacement. cert and key are two files, so a reader can see the new
//     certificate beside the old key. LoadX509KeyPair refuses the mismatch, the
//     stamps are recorded, and the second rename changes them again — the next
//     handshake then loads the matching pair.
//   - a wrong certificate. A host identity that no longer chains to the cluster
//     CA, or names another host, would cut this node off from every peer. Keeping
//     the old identity keeps the node in the cluster, and the log says why the
//     new one was not taken.
type KeyPairSource struct {
	certPath, keyPath string
	// check vets a changed pair before it replaces the served one. nil accepts
	// any pair LoadX509KeyPair can load.
	check func(leaf *x509.Certificate) error
	// pairCheck vets EVERY pair, the first included, and may set pair.Leaf.
	pairCheck func(pair *tls.Certificate) error
	// strictKeyFile refuses a key file that fails checkKeyFile. Only for keys
	// this build introduced (the custom UI certificate): a key file main
	// served — the host's and client's identity — is never newly refused, only
	// reported (KeyFileProblems) and served.
	strictKeyFile bool
	warnedKey     string

	mu         sync.Mutex
	cur        *tls.Certificate
	certStamp  fileStamp
	keyStamp   fileStamp
	loadErr    error
	everLoaded bool
}

// fileStamp identifies one version of a file on disk.
type fileStamp struct {
	mod  time.Time
	size int64
	ino  uint64
}

func stampOf(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	s := fileStamp{mod: fi.ModTime(), size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.ino = uint64(st.Ino) //nolint:unconvert // Ino is uint32 on some platforms
	}
	return s, nil
}

// NewKeyPairSource returns a source for certPath/keyPath. check, when non-nil,
// is applied to every pair after the first; see KeyPairSource.
func NewKeyPairSource(certPath, keyPath string, check func(*x509.Certificate) error) *KeyPairSource {
	return &KeyPairSource{certPath: certPath, keyPath: keyPath, check: check}
}

// withPairCheck sets a check applied to every pair loaded, the first included.
func (s *KeyPairSource) withPairCheck(fn func(*tls.Certificate) error) *KeyPairSource {
	s.pairCheck = fn
	return s
}

// Get returns the pair to serve, re-reading the files if they changed. It errs
// only while no pair has ever loaded.
func (s *KeyPairSource) Get() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, cerr := stampOf(s.certPath)
	ks, kerr := stampOf(s.keyPath)
	switch {
	case cerr != nil || kerr != nil:
		// A file that vanished keeps the pair already loaded: deleting the
		// identity of a running node must not take it off the network mid-RPC.
		if s.cur == nil {
			if cerr != nil {
				return nil, fmt.Errorf("load %s: %w", filepath.Base(s.certPath), cerr)
			}
			return nil, fmt.Errorf("load %s: %w", filepath.Base(s.keyPath), kerr)
		}
	case !s.everLoaded || cs != s.certStamp || ks != s.keyStamp:
		s.certStamp, s.keyStamp = cs, ks
		s.reloadLocked()
	}
	if s.cur == nil {
		return nil, s.loadErr
	}
	return s.cur, nil
}

// reloadLocked loads the pair the stamps now describe and adopts it if it passes.
func (s *KeyPairSource) reloadLocked() {
	first := !s.everLoaded
	s.everLoaded = true
	var pair tls.Certificate
	var err error
	if s.strictKeyFile {
		pair, err = loadPairChecked(s.certPath, s.keyPath)
	} else {
		pair, err = s.loadPairLenient()
	}
	if err == nil && pair.Leaf == nil && len(pair.Certificate) > 0 {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	}
	if err == nil && s.pairCheck != nil {
		err = s.pairCheck(&pair)
	}
	if err == nil && !first && s.check != nil {
		err = s.check(pair.Leaf)
	}
	if err != nil {
		s.loadErr = fmt.Errorf("load %s/%s: %w", filepath.Base(s.certPath), filepath.Base(s.keyPath), err)
		if s.cur != nil {
			// The key is never part of this message: LoadX509KeyPair's errors
			// describe the mismatch, not the material.
			slog.Warn("a replaced certificate was not adopted; still serving the previous one "+
				"(a half-written pair is retried when the second file lands)",
				"cert", s.certPath, "serving_serial", s.cur.Leaf.SerialNumber.Text(16), "error", err)
		}
		return
	}
	if s.cur != nil && !first {
		slog.Info("certificate reloaded from disk",
			"cert", s.certPath,
			"previous_serial", s.cur.Leaf.SerialNumber.Text(16),
			"serial", pair.Leaf.SerialNumber.Text(16),
			"not_after", pair.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	s.cur, s.loadErr = &pair, nil
}

// loadPairChecked is tls.LoadX509KeyPair with the checks a served identity
// needs on every load, not only at boot: both files regular and bounded in
// size, and the key resolving inside its own directory, owned by this process's
// user, and readable by nobody else (tightened to 0600 if it is not).
func loadPairChecked(certPath, keyPath string) (tls.Certificate, error) {
	if err := checkKeyFile(keyPath); err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := readBounded(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readBounded(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// loadPairLenient loads a pair the way main did — whatever the key file's
// owner, location or size — after tightening a loose mode, and warns once per
// problem set; the daemon raises the same problems as a degraded condition.
func (s *KeyPairSource) loadPairLenient() (tls.Certificate, error) {
	if probs := KeyFileProblems(s.keyPath); len(probs) > 0 {
		if key := strings.Join(probs, "; "); key != s.warnedKey {
			s.warnedKey = key
			slog.Warn("a private key file is not held the way it should be; still serving it",
				"key", s.keyPath, "problems", key)
		}
	} else {
		s.warnedKey = ""
	}
	// Bounded and regular-file-only, as on the strict path: neither ever
	// refuses a real PEM pair, and both keep a planted FIFO or huge file from
	// costing a read per handshake.
	certPEM, err := readBounded(s.certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readBounded(s.keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// KeyFileProblems lists what is wrong with how keyPath is held, each with its
// fix, after tightening a mode readable by others (a repair, never a refusal).
// Empty when the key is a regular file inside its own directory, owned by this
// process's user, readable by nobody else.
func KeyFileProblems(keyPath string) []string {
	var out []string
	real, err := filepath.EvalSymlinks(keyPath)
	if err != nil {
		return []string{fmt.Sprintf("%s cannot be resolved: %v", keyPath, err)}
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(keyPath)); err == nil {
		if rel, err := filepath.Rel(dir, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			out = append(out, fmt.Sprintf("%s resolves outside %s (to %s): move the key into %s", keyPath, dir, real, dir))
		}
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return append(out, fmt.Sprintf("%s cannot be read: %v", real, err))
	}
	if !fi.Mode().IsRegular() {
		out = append(out, fmt.Sprintf("%s is not a regular file: replace it with one", real))
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		out = append(out, fmt.Sprintf("%s is owned by uid %d: chown %d %s", real, st.Uid, os.Geteuid(), real))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := TightenKeyMode(real); err != nil {
			out = append(out, fmt.Sprintf("%s is mode %04o: chmod 600 %s", real, fi.Mode().Perm(), real))
		}
	}
	return out
}

// readBounded reads a regular file of at most maxServingChainBytes.
func readBounded(path string) ([]byte, error) { return readBoundedN(path, maxServingChainBytes) }

// readBoundedN reads a regular file of at most limit bytes.
func readBoundedN(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// checkKeyFile refuses a private key that resolves outside its own directory
// or belongs to another user, and tightens one readable by group or others.
func checkKeyFile(keyPath string) error {
	real, err := filepath.EvalSymlinks(keyPath)
	if err != nil {
		return err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(keyPath))
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(dir, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("private key %s resolves outside %s", keyPath, dir)
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("private key %s is not a regular file", keyPath)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("private key %s is owned by uid %d, not this process's user", keyPath, st.Uid)
	}
	return TightenKeyMode(real)
}

// Leaf returns the certificate being served, or an error while none has loaded.
func (s *KeyPairSource) Leaf() (*x509.Certificate, error) {
	pair, err := s.Get()
	if err != nil {
		return nil, err
	}
	return pair.Leaf, nil
}

var (
	sourcesMu sync.Mutex
	sources   = map[string]*KeyPairSource{}
)

// hostIdentitySource is the process-wide source for pkiDir's host identity,
// shared by every TLS config built for that directory, so a renewal is adopted
// once and seen everywhere.
func hostIdentitySource(pkiDir string) *KeyPairSource {
	return sharedSource(pkiDir, "host", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
}

// sharedSource returns the process-wide source for pkiDir/<name>.crt|.key. A
// changed pair must chain to pkiDir/ca.crt for every usage in usages and keep
// the Common Name of the pair first loaded — renewal replaces a certificate; it
// never changes whose it is.
func sharedSource(pkiDir, name string, usages ...x509.ExtKeyUsage) *KeyPairSource {
	certPath := filepath.Join(pkiDir, name+".crt")
	keyPath := filepath.Join(pkiDir, name+".key")
	key := certPath + "\x00" + keyPath
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	if s, ok := sources[key]; ok {
		return s
	}
	s := NewKeyPairSource(certPath, keyPath, nil)
	s.check = func(leaf *x509.Certificate) error {
		return checkSameIdentity(pkiDir, s.firstCN(), leaf, usages)
	}
	sources[key] = s
	return s
}

// firstCN is the Common Name of the pair currently served. Called from check,
// which runs with s.mu held.
func (s *KeyPairSource) firstCN() string {
	if s.cur == nil || s.cur.Leaf == nil {
		return ""
	}
	return s.cur.Leaf.Subject.CommonName
}

// checkSameIdentity accepts leaf as a replacement for an identity named cn: it
// must chain to the cluster CA for each usage and carry the same Common Name.
func checkSameIdentity(pkiDir, cn string, leaf *x509.Certificate, usages []x509.ExtKeyUsage) error {
	if leaf == nil {
		return errors.New("no certificate")
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("failed to parse CA cert")
	}
	for _, u := range usages {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{u}}); err != nil {
			return fmt.Errorf("the new certificate does not verify against the cluster CA: %w", err)
		}
	}
	if cn != "" && leaf.Subject.CommonName != cn {
		return fmt.Errorf("the new certificate names %q, but this identity is %q", leaf.Subject.CommonName, cn)
	}
	return nil
}

// ServedHostCertificate is the host certificate this process presents for
// pkiDir right now — the one peers see, which after a renewal on disk is not
// necessarily what a fresh read of host.crt would say if that file was refused.
func ServedHostCertificate(pkiDir string) (*x509.Certificate, error) {
	return hostIdentitySource(pkiDir).Leaf()
}

// ServedHostKeyPair is ServedHostCertificate with its private key, for signers
// that must sign as the identity peers verify (recovery-claim votes).
func ServedHostKeyPair(pkiDir string) (*tls.Certificate, error) {
	return hostIdentitySource(pkiDir).Get()
}
