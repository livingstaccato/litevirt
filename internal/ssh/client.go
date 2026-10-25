package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Client wraps an SSH connection for remote operations.
type Client struct {
	conn *ssh.Client
	addr string
}

// NewClient connects to a remote host via SSH.
// target format: "user@host" or "user@host:port"
func NewClient(target string) (*Client, error) { return newClient(target, 0, false) }

// NewClientTimeout is NewClient with the connect and the handshake bounded
// by timeout together, for a best-effort connection to a host that may be
// dead or silent.
func NewClientTimeout(target string, timeout time.Duration) (*Client, error) {
	return newClient(target, timeout, false)
}

// NewClientDeadline is NewClientTimeout with the bound left on the whole
// session: the commands run over it fail once timeout has passed since the
// dial began, for a short best-effort job on a host that may stall.
func NewClientDeadline(target string, timeout time.Duration) (*Client, error) {
	return newClient(target, timeout, true)
}

func newClient(target string, timeout time.Duration, keepDeadline bool) (*Client, error) {
	start := time.Now()
	// The ssh -G run counts against the caller's bound, not before it.
	t, err := resolveTarget(target, timeout)
	if err != nil {
		return nil, err
	}
	return dialTarget(t, start, timeout, keepDeadline)
}

// NewClientResolved connects to a target already resolved with Resolve.
func NewClientResolved(t *Target) (*Client, error) {
	return dialTarget(t, time.Now(), 0, false)
}

func dialTarget(t *Target, start time.Time, timeout time.Duration, keepDeadline bool) (*Client, error) {
	cfg, sshUser, host, port := t.cfg, t.user, t.host, t.port
	dialHost := cfg.Hostname

	auth, err := authMethodsFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH auth: %w", err)
	}

	// The host-key policy is for the address actually dialled -- the config's
	// HostName and Port, never the alias the operator typed -- because that is
	// the string ssh.Dial hands the callback.
	addr := net.JoinHostPort(dialHost, port)
	config, err := clientConfig(sshUser, auth, cfg, addr)
	if err != nil {
		return nil, fmt.Errorf("host key check for %s: %w", host, err)
	}
	var conn *ssh.Client
	if timeout > 0 {
		remaining := timeout - time.Since(start)
		if remaining <= 0 {
			return nil, fmt.Errorf("SSH dial %s: %w", addr, context.DeadlineExceeded)
		}
		conn, err = dialTimeout(addr, config, remaining, keepDeadline)
	} else {
		conn, err = ssh.Dial("tcp", addr, config)
	}
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}

	return &Client{conn: conn, addr: addr}, nil
}

// clientConfig is the ClientConfig every litevirt SSH dial uses: the given
// auth, and the host-key policy cfg sets for addr (host:port as dialled).
//
// The verifying callback and the HostKeyAlgorithms offer come from one read of
// the same known_hosts files, so the key types asked for are exactly the ones
// the verification will accept. HostKeyAlgorithms is never taken from the ssh
// config: a config could re-add SHA-1 ssh-rsa, or ask for a type known_hosts
// does not record and so turn a known host into a refused one.
func clientConfig(sshUser string, auth []ssh.AuthMethod, cfg *resolved, addr string) (*ssh.ClientConfig, error) {
	// Options with which ssh would refuse keys litevirt cannot otherwise see: a
	// pin source litevirt does not run refuses outright; a revocation list litevirt
	// cannot read refuses too. Neither is ever skipped.
	if cfg != nil && cfg.KnownHostsCommand != "" {
		return nil, fmt.Errorf("your ssh config sets KnownHostsCommand (%s); litevirt does not run it, "+
			"so the host keys it would supply cannot be checked -- refusing. Put the host's key in a "+
			"known_hosts file (UserKnownHostsFile or GlobalKnownHostsFile) instead", cfg.KnownHostsCommand)
	}
	var revoked map[string]bool
	if cfg != nil && cfg.RevokedHostKeys != "" {
		var err error
		if revoked, err = loadRevokedHostKeys(cfg.RevokedHostKeys); err != nil {
			return nil, err
		}
	}
	hostKeyCallback, hostKeyAlgos, err := hostKeyPolicyFor(cfg, addr)
	if err != nil {
		// Only the ABSENCE of any known_hosts reaches the first-contact
		// fallback. A store that exists but cannot be read or parsed fails
		// closed: accepting any key there would let a corrupt file (or one
		// named by the config) switch off the check for a changed key.
		if !errors.Is(err, errNoKnownHosts) || (cfg != nil && cfg.StrictYes) {
			return nil, err
		}
		host, _, serr := net.SplitHostPort(addr)
		if serr != nil {
			host = addr
		}
		// No known_hosts at all (no HOME, no file). Accept-new still
		// applies -- there is nothing to compare against, and refusing here
		// would make provisioning impossible on a fresh workstation -- but say
		// so, because this connection carries the cluster CA-signed host key
		// and nothing is pinning the far end.
		fmt.Fprintf(os.Stderr,
			"warning: no usable known_hosts (%v); %s's host key cannot be checked "+
				"against a previous one. This connection carries the cluster CA-signed "+
				"host key.\n", err, host)
		hostKeyCallback = firstContactOnlyCallback(host)
		hostKeyAlgos = slices.Clone(firstContactHostKeyAlgorithms)
	}

	return &ssh.ClientConfig{
		User:              sshUser,
		Auth:              auth,
		HostKeyCallback:   refuseRevokedAndSHA1CA(hostKeyCallback, revoked, revokedFile(cfg)),
		HostKeyAlgorithms: hostKeyAlgos,
	}, nil
}

func revokedFile(cfg *resolved) string {
	if cfg == nil {
		return ""
	}
	return cfg.RevokedHostKeys
}

// refuseRevokedAndSHA1CA runs before next, on every path including first
// contact: a key RevokedHostKeys lists -- presented plainly, as the key inside
// a certificate, or as the CA that signed one -- is refused, and so is a host
// certificate whose CA signed it with SHA-1 ssh-rsa (or DSA), which OpenSSH's
// default CASignatureAlgorithms refuses.
func refuseRevokedAndSHA1CA(next ssh.HostKeyCallback, revoked map[string]bool, file string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		isRevoked := func(k ssh.PublicKey) bool { return k != nil && revoked[string(k.Marshal())] }
		cert, isCert := key.(*ssh.Certificate)
		if isRevoked(key) || (isCert && (isRevoked(cert.Key) || isRevoked(cert.SignatureKey))) {
			return fmt.Errorf("host key for %s is revoked (RevokedHostKeys %s) -- refusing", hostname, file)
		}
		if isCert && cert.Signature != nil {
			switch cert.Signature.Format {
			case ssh.KeyAlgoRSA, ssh.KeyAlgoDSA: //nolint:staticcheck // naming them to refuse them
				return fmt.Errorf("host certificate for %s is signed by its CA with SHA-1 (%s) -- refusing, "+
					"as OpenSSH does by default; re-sign it with rsa-sha2-512", hostname, cert.Signature.Format)
			}
		}
		return next(hostname, remote, key)
	}
}

// loadRevokedHostKeys reads a RevokedHostKeys file that is a plain list of
// public keys (blank lines and # comments allowed). ssh also accepts a binary
// KRL, which x/crypto cannot parse; that, a line that is not a public key, or
// a file that cannot be read (absent included -- ssh refuses then too) is an
// error, never an empty list.
func loadRevokedHostKeys(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("RevokedHostKeys %s cannot be read: %w", path, err)
	}
	if bytes.HasPrefix(data, []byte("SSHKRL\n\x00")) {
		return nil, fmt.Errorf("RevokedHostKeys %s is a binary KRL, which litevirt cannot read -- "+
			"refusing rather than skip the revocations; list the revoked public keys instead", path)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("RevokedHostKeys %s:%d is not a public key: %w", path, i+1, err)
		}
		out[string(k.Marshal())] = true
	}
	return out, nil
}

// hostKeyAlgorithmPreference is the order known host-key types are asked for
// in, strongest first. An RSA key is asked for with SHA-2 signatures only.
var hostKeyAlgorithmPreference = []struct {
	keyType string
	algos   []string
}{
	{ssh.KeyAlgoED25519, []string{ssh.KeyAlgoED25519}},
	{ssh.KeyAlgoECDSA256, []string{ssh.KeyAlgoECDSA256}},
	{ssh.KeyAlgoECDSA384, []string{ssh.KeyAlgoECDSA384}},
	{ssh.KeyAlgoECDSA521, []string{ssh.KeyAlgoECDSA521}},
	{ssh.KeyAlgoRSA, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}},
}

// sha2CertAlgorithms are the host-certificate algorithms asked for when a
// @cert-authority line covers the host. They follow the HOST key's type, which
// need not be the CA's (an ed25519 CA can sign an ecdsa host key), so every
// supported type is listed. No SHA-1 ssh-rsa or DSA certificates.
var sha2CertAlgorithms = []string{
	ssh.CertAlgoED25519v01,
	ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01,
	ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01,
	ssh.CertAlgoRSASHA256v01,
}

// firstContactHostKeyAlgorithms is the offer to a host known_hosts does not
// know: every plain type, SHA-2 only, and no certificates. A certificate from
// a CA nothing trusts would be refused outright, so asking for one would turn
// first contact with a cert-bearing host into a refusal; its plain key is
// taken under accept-new like any other new host's.
var firstContactHostKeyAlgorithms = func() []string {
	var algos []string
	for _, p := range hostKeyAlgorithmPreference {
		algos = append(algos, p.algos...)
	}
	return algos
}()

// knownHostKeyAlgorithms returns the host-key algorithms to ask addr for:
// certificates first when a @cert-authority line covers it, then the plain key
// types its plain known_hosts entries record; for a host known_hosts does not
// know, firstContactHostKeyAlgorithms.
//
// Without this the server presents whichever of its keys x/crypto prefers --
// ECDSA before ED25519 -- while OpenSSH records the ED25519 one. knownhosts
// then finds an entry for the host holding a different key, and a node whose
// key never changed is refused as CHANGED. OpenSSH avoids the same trap the
// same way (it orders HostKeyAlgorithms by what known_hosts holds).
//
// Narrowing the offer is not a weakening: the presented key must still match a
// recorded one exactly (or be a certificate the recorded CA signed), and a
// server that holds no key of a recorded type fails the negotiation instead of
// being treated as unknown.
//
// raw is the unwrapped knownhosts callback; addr is host:port as dialled. The
// probe key is fresh, so it can match no entry, and the KeyError lists every
// entry -- plain AND @cert-authority, which KnownKey does not tell apart --
// recorded for addr. isHostAuthority sorts them. The same in-memory database
// then verifies the real key, so the two answers cannot disagree about the file.
func knownHostKeyAlgorithms(raw ssh.HostKeyCallback, addr string) []string {
	probe, want := knownHostEntries(raw, addr)
	if len(want) == 0 {
		return slices.Clone(firstContactHostKeyAlgorithms)
	}
	keyErr := &knownhosts.KeyError{Want: want}
	authority := false
	recorded := map[string]bool{}
	for _, k := range keyErr.Want {
		if isHostAuthority(raw, addr, probe, k.Key) {
			authority = true
		} else {
			recorded[k.Key.Type()] = true
		}
	}
	var algos []string
	if authority {
		algos = append(algos, sha2CertAlgorithms...)
	}
	for _, p := range hostKeyAlgorithmPreference {
		if recorded[p.keyType] {
			algos = append(algos, p.algos...)
		}
	}
	if len(algos) == 0 {
		// Recorded only under types this client cannot negotiate (sk-*, dss):
		// whatever the host presents fails hostKeyVerdictFor, which says so.
		return slices.Clone(firstContactHostKeyAlgorithms)
	}
	return algos
}

// knownHostEntries asks raw for addr with a fresh key, which can match no
// entry, and returns that key and every entry recorded for addr (none for a
// host known_hosts does not know).
func knownHostEntries(raw ssh.HostKeyCallback, addr string) (ssh.PublicKey, []knownhosts.KnownKey) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil
	}
	probe, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(raw(addr, &net.TCPAddr{IP: net.IPv4zero}, probe), &keyErr) {
		return probe, nil
	}
	return probe, keyErr.Want
}

// sourceHasCA reports whether raw holds a @cert-authority line covering addr.
func sourceHasCA(raw ssh.HostKeyCallback, addr string) bool {
	probe, want := knownHostEntries(raw, addr)
	for _, k := range want {
		if isHostAuthority(raw, addr, probe, k.Key) {
			return true
		}
	}
	return false
}

// commonHostKeyAlgorithms keeps, in union's order, the algorithms every
// per-source offer lists. When a CA line is in one file and plain entries in
// another it is empty, and the union (certificates first) is right: a plain
// source then checks the key inside the certificate.
func commonHostKeyAlgorithms(union []string, per [][]string) []string {
	var out []string
	for _, a := range union {
		ok := true
		for _, p := range per {
			if !slices.Contains(p, a) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, a)
		}
	}
	return out
}

// wildcardPortPattern is a known_hosts host pattern with a wildcard in its
// port ("[10.0.0.*]:*"). x/crypto matches ports exactly, so it never matches
// one, while OpenSSH does: a pin written that way would be silently ignored.
type wildcardPortPattern struct {
	file, pattern, host string
	line                int
}

// mayMatch reports whether the pattern's host part could match host. A
// pattern path.Match cannot read counts as a match (fail closed).
func (w wildcardPortPattern) mayMatch(host string) bool {
	ok, err := path.Match(strings.ToLower(w.host), strings.ToLower(host))
	return ok || err != nil
}

// wildcardPortPatterns lists the wildcard-port host patterns in a known_hosts
// file. @revoked lines are skipped: their host field is not consulted.
func wildcardPortPatterns(file string) ([]wildcardPortPattern, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []wildcardPortPattern
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if f[0] == "@revoked" {
			continue
		}
		if strings.HasPrefix(f[0], "@") {
			f = f[1:]
			if len(f) == 0 {
				continue
			}
		}
		for _, p := range strings.Split(f[0], ",") {
			p = strings.TrimPrefix(p, "!")
			if !strings.HasPrefix(p, "[") {
				continue
			}
			end := strings.LastIndex(p, "]:")
			if end < 0 || !strings.ContainsAny(p[end+2:], "*?") {
				continue
			}
			out = append(out, wildcardPortPattern{file: file, pattern: p, host: p[1:end], line: i + 1})
		}
	}
	return out, nil
}

// hostIsKnown reports whether known_hosts holds any entry -- plain or
// @cert-authority -- for addr.
func hostIsKnown(raw ssh.HostKeyCallback, addr string) bool {
	_, want := knownHostEntries(raw, addr)
	return len(want) > 0
}

// isHostAuthority reports whether key is a @cert-authority entry for addr
// rather than a plain one. knownhosts does not export that, so it asks the
// callback with an unsigned, expired host certificate "signed" by key: the
// callback refuses it either way, but only with "no authorities for hostname"
// when key is not a CA for addr. Misreading the string fails closed (a CA host
// is asked for plain keys and refused; TestHostKeyCA_CAOnlyHostWithCert).
func isHostAuthority(raw ssh.HostKeyCallback, addr string, probe, key ssh.PublicKey) (authority bool) {
	defer func() {
		if recover() != nil {
			authority = false
		}
	}()
	cert := &ssh.Certificate{
		Key:          probe,
		CertType:     ssh.HostCert,
		SignatureKey: key,
		Signature:    &ssh.Signature{Format: key.Type()},
		// ValidBefore 0: expired, so no path reaches signature verification.
	}
	err := raw(addr, &net.TCPAddr{IP: net.IPv4zero}, cert)
	return err != nil && !strings.Contains(err.Error(), "no authorities for hostname")
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Run executes a command on the remote host.
func (c *Client) Run(cmd string) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	return session.Run(cmd)
}

// RunWithInput runs a command with data on its stdin.
//
// This is how a provisioning script should reach a remote host: `bash -s` with
// the script on stdin never creates a file, so there is no path for a local
// user on the target to pre-create, no window between writing and executing,
// and nothing to clean up if the process dies in between.
func (c *Client) RunWithInput(cmd string, input []byte) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytesReader(input)
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	return session.Run(cmd)
}

// RunOutput executes a command and returns stdout.
func (c *Client) RunOutput(cmd string) ([]byte, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	return session.Output(cmd)
}

// RunOutputContext is RunOutput, bounded by ctx: when ctx ends before the
// command does, the command and every process it started on the remote are
// killed, and ctx's error is returned with no output.
//
// Closing the session alone would not stop them: a command run without a PTY
// is not signalled when its channel closes, so a hung child would run on
// until it ended by itself. The command therefore runs in a session (and
// process group) of its own under killOnStdinEOF, and the end of ctx is sent
// as EOF on its stdin, which kills that group. The command reads /dev/null,
// not the session's stdin.
func (c *Client) RunOutputContext(ctx context.Context, cmd string) ([]byte, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("SSH session: %w", err)
	}
	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Start(killOnStdinEOF(cmd)); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		return out.Bytes(), err
	case <-ctx.Done():
	}
	// EOF on stdin: the remote kills the command's session. Wait a little for
	// it to report, so a machine that answers has stopped it before this
	// returns; one that does not answer is not waited for.
	_ = stdin.Close()
	t := time.NewTimer(remoteKillGrace)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	return nil, ctx.Err()
}

// remoteKillGrace is how long RunOutputContext waits, once its context has
// ended, for the remote to report the killed command's exit.
var remoteKillGrace = 2 * time.Second

// killOnStdinEOF wraps cmd for RunOutputContext. A watcher reading the
// session's stdin kills cmd's whole session when stdin reaches EOF:
//
//   - with setsid, cmd runs in a session of its own, so the session's id is
//     its pid;
//   - without it, cmd stays in the session sshd gave the wrapper (sshd makes
//     the command it runs a session leader, so $$ names it), and that whole
//     session is killed: wrapper, watcher and cmd's tree. Where $$ leads no
//     session (an unusual launcher), the kill finds none, and only cmd's
//     shell is killed.
//
// The session, not the process group: a child may move to a group of its
// own (coreutils timeout without --foreground calls setpgid(0, 0)), but it
// cannot leave the session without setsid.
//
// The wrapper exits with cmd's status and stops the watcher first (a
// watcher still reading stdin; one that is killing finishes, and is waited
// for), so a command that ended by itself is never followed by a kill. A background job
// reads /dev/null unless told otherwise, so stdin reaches the watcher as fd 3.
func killOnStdinEOF(cmd string) string {
	q := ShellQuote(cmd)
	return `exec 3<&0; ` +
		`if command -v setsid >/dev/null 2>&1; then setsid sh -c ` + q + ` 3<&- </dev/null & p=$!; s=$p; f=; ` +
		`else sh -c ` + q + ` 3<&- </dev/null & p=$!; s=$$; f=$p; fi; ` +
		`sh -c ` + ShellQuote(sessionKillWatcher) + ` sh "$s" "$f" <&3 >/dev/null 2>&1 & w=$!; ` +
		`exec 3<&-; wait $p; rc=$?; kill $w 2>/dev/null; wait $w; exit $rc`
}

// sessionKillWatcher is the watcher killOnStdinEOF starts with the session's
// id ($1) and, without setsid, cmd's pid ($2). Once stdin reaches EOF it
// SIGKILLs every process in session $1: with setsid, cmd's group first (the
// watcher is outside it), then the session by pkill -s, twice, so a child
// forked during the first pass is caught by the second. Where there is no
// pkill it reads /proc once instead, skipping itself. Without setsid the
// watcher is in the session too, and is killed with the rest, wrapper
// included. From EOF on it ignores SIGTERM: the wrapper, once cmd has died,
// stops the watcher with one and waits for it, which must not cut the kill
// short.
const sessionKillWatcher = `cat >/dev/null
trap '' TERM
s=$1; f=$2
[ -z "$f" ] && kill -s KILL -- -$s
if command -v pkill >/dev/null 2>&1; then
  pkill -KILL -s "$s"; pkill -KILL -s "$s"
else
  for x in /proc/[0-9]*/stat; do
    read -r l < "$x" || continue
    i=${l%% *}
    [ "$i" = "$$" ] && continue
    set -- ${l##*") "}
    [ "$4" = "$s" ] && kill -s KILL "$i"
  done
fi
[ -n "$f" ] && kill -s KILL "$f"
exit 0`

// CopyFileMode copies a local file to the remote host with an explicit mode.
//
// The mode is explicit because a 0644 default was wrong for private keys, and
// nothing about the call site made that visible: `lv host init root@<host>` —
// the form the docs tell you to use for anything multi-node — pushed
// /etc/litevirt/pki/host.key world-readable on every node it provisioned. That
// key is the host's whole cluster identity: any local user who can read it can
// impersonate the host over peer mTLS and sign audit rows in its name. Callers
// pushing key material MUST pass 0600.
func (c *Client) CopyFileMode(localPath, remotePath string, mode os.FileMode) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file: %w", err)
	}
	return c.WriteFile(remotePath, data, mode)
}

// ShellQuote renders s as a single-quoted POSIX shell word.
//
// Exported because every caller that builds a remote command line from data
// needs it, not only this package: an SSH exec request is run by the login
// shell, so anything interpolated into one is shell input.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeFileCmd builds the remote shell command that materialises a file.
//
// The content is staged in a mktemp file beside the destination, chmod'd there,
// and only then moved into place. The obvious `cat > path && chmod mode path`
// leaves the file complete and world-readable at the remote umask for the whole
// transfer — and permanently if the connection drops between the two commands.
// The payload here is host.key.
//
// Staging also fixes the case a leading chmod would not: redirecting into an
// EXISTING file truncates it but keeps its old mode, so re-provisioning over a
// loose file would write the new key at the old permissions. mv replaces the
// destination wholesale, mode included, and does so atomically.
//
// mktemp in the destination's own directory keeps the rename on one filesystem.
// The staged file is synced before the move and the directory after it, so a
// power loss cannot leave the destination renamed over but empty. A failed
// sync fails the write before the move (coreutils 8.24 or later syncs one
// file; there is no fallback to a global sync, which reports success
// whatever happened and blocks on a hung mount).
//
// -T is load-bearing, not tidiness. Without it, `mv src dest` where dest is a
// DIRECTORY moves src INSIDE it — so a local user who can see the destination
// path (process command lines are world-readable on a default Linux) can
// mkdir it first, let the staged file land inside, then rename their directory
// away and leave their own file at the path root is about to read. -T makes
// that case an error instead. -- stops a path that begins with "-" being read
// as options.
func writeFileCmd(remotePath string, mode os.FileMode) string {
	q := ShellQuote(remotePath)
	return fmt.Sprintf(
		"set -e; d=$(dirname %s); t=$(mktemp \"$d/.litevirt.XXXXXX\"); "+
			"trap 'rm -f \"$t\"' EXIT; cat > \"$t\"; chmod %o \"$t\"; "+
			"sync -- \"$t\"; "+
			"mv -fT -- \"$t\" %s; trap - EXIT; sync -- \"$d\"",
		q, mode.Perm(), q)
}

// WriteFile writes data to a remote file.
func (c *Client) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytesReader(data)
	return session.Run(writeFileCmd(remotePath, mode))
}

// Conn returns the underlying SSH client connection (used for tunneling).
func (c *Client) Conn() *ssh.Client {
	return c.conn
}

func parseTarget(target string) (user, host, port string) {
	user, host, port, _, _ = parseTargetExplicit(target)
	return
}

// parseTargetExplicit is parseTarget that also says whether the target named
// the user and the port, so a config value is used only where it did not.
func parseTargetExplicit(target string) (user, host, port string, userSet, portSet bool) {
	user = "root"
	host = target
	port = "22"

	for i, c := range target {
		if c == '@' {
			user = target[:i]
			host = target[i+1:]
			userSet = true
			break
		}
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
		portSet = true
	}

	return
}

func authMethods() ([]ssh.AuthMethod, error) { return authMethodsFor(nil) }

// authMethodsFor is authMethods under cfg: its IdentityFile entries tried
// before the default key files, IdentitiesOnly, and IdentityAgent. A nil cfg
// is the defaults (SSH_AUTH_SOCK, the default key files).
func authMethodsFor(cfg *resolved) ([]ssh.AuthMethod, error) {
	var (
		extraKeys      []string
		identitiesOnly bool
		onlyConfigured bool
	)
	sock, sockFrom := os.Getenv("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK not set"
	if cfg != nil {
		extraKeys, identitiesOnly = cfg.IdentityFiles, cfg.IdentitiesOnly
		// IdentitiesOnly with an IdentityFile litevirt had to skip offers
		// nothing in its place: ssh would offer that key, never the defaults.
		onlyConfigured = identitiesOnly && (len(extraKeys) > 0 || cfg.IdentitySkipped)
		if cfg.AgentSet {
			sock, sockFrom = cfg.AgentSock, "disabled by IdentityAgent in the ssh config"
		}
	}
	var tried []string
	// agentSigners is nil without a usable agent.
	var agentSigners func() ([]ssh.Signer, error)

	// Try SSH agent first
	home, _ := os.UserHomeDir()
	defaults := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
	identities := append(append([]string(nil), extraKeys...), defaults...)
	if onlyConfigured {
		identities = extraKeys // ssh offers only the configured identities
	}
	if sock == "" {
		tried = append(tried, "agent: "+sockFrom)
	} else {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			tried = append(tried, fmt.Sprintf("agent: dial %s: %v", sock, err))
		} else {
			ac := agent.NewClient(conn)
			// Verify agent actually has keys before adding
			keys, err := ac.List()
			if err != nil {
				conn.Close()
				tried = append(tried, fmt.Sprintf("agent: list keys: %v", err))
			} else if len(keys) == 0 {
				conn.Close()
				tried = append(tried, "agent: connected but no keys loaded")
			} else {
				tried = append(tried, fmt.Sprintf("agent: %d key(s) available", len(keys)))
				if identitiesOnly {
					// As OpenSSH does: keep the agent, offer only its keys
					// that match the identities (by public key, so a .pub
					// IdentityFile whose private half lives in the agent works).
					want := identityPublicKeys(identities)
					tried = append(tried, fmt.Sprintf("agent: IdentitiesOnly yes, %d identity public key(s) to match", len(want)))
					agentSigners = func() ([]ssh.Signer, error) {
						all, err := ac.Signers()
						if err != nil {
							return nil, err
						}
						var keep []ssh.Signer
						for _, sg := range all {
							if want[string(sg.PublicKey().Marshal())] {
								keep = append(keep, sg)
							}
						}
						return keep, nil
					}
				} else {
					agentSigners = ac.Signers
				}
			}
		}
	}

	// Try default key files
	keyFiles := identities
	if !identitiesOnly {
		keyFiles = append(append([]string(nil), extraKeys...), defaults...)
	}
	var fileSigners []ssh.Signer
	for _, kf := range keyFiles {
		key, err := loadPrivateKey(kf)
		if err != nil {
			if os.IsNotExist(err) {
				tried = append(tried, fmt.Sprintf("key %s: not found", kf))
			} else {
				tried = append(tried, fmt.Sprintf("key %s: %v", kf, err))
			}
			continue
		}
		tried = append(tried, fmt.Sprintf("key %s: loaded", kf))
		fileSigners = append(fileSigners, key)
	}

	// The configured identities' public keys, in config order. They come from
	// the key files' public halves (a .pub sibling, a public-key file, the
	// clear half of an OpenSSH private key) as well as from loading the
	// private key: a passphrase-protected key, or one whose private half lives
	// only in the agent or on a hardware token, is still the key the operator
	// named, and its agent copy must still be offered first.
	var configuredPubs []string
	seenPub := map[string]bool{}
	addPub := func(k string) {
		if !seenPub[k] {
			seenPub[k] = true
			configuredPubs = append(configuredPubs, k)
		}
	}
	for _, kf := range extraKeys {
		if sg, err := loadPrivateKey(kf); err == nil {
			addPub(string(sg.PublicKey().Marshal()))
			continue
		}
		for k := range identityPublicKeys([]string{kf}) {
			addPub(k)
		}
	}

	if agentSigners == nil && len(fileSigners) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available:\n  %s", joinLines(tried))
	}

	// ONE publickey method: the client tries each method name once, so an
	// agent whose keys all fail would otherwise use up "publickey" and the key
	// files after it would never be offered. Order, as OpenSSH does: the
	// configured IdentityFile keys first (the agent's copy of one when it has
	// it), then the agent's other keys, then the remaining key files, never
	// repeating a key -- so unrelated agent keys cannot use up MaxAuthTries
	// before the key the operator named.
	return []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		var agentAll []ssh.Signer
		if agentSigners != nil {
			as, err := agentSigners()
			if err != nil && len(fileSigners) == 0 {
				return nil, err
			}
			agentAll = as
		}
		byPub := map[string]ssh.Signer{}
		for _, sg := range fileSigners {
			byPub[string(sg.PublicKey().Marshal())] = sg
		}
		for _, sg := range agentAll { // the agent's copy wins
			byPub[string(sg.PublicKey().Marshal())] = sg
		}
		var all []ssh.Signer
		seen := map[string]bool{}
		add := func(sg ssh.Signer) {
			if k := string(sg.PublicKey().Marshal()); !seen[k] {
				seen[k] = true
				all = append(all, sg)
			}
		}
		for _, k := range configuredPubs {
			if sg, ok := byPub[k]; ok {
				add(sg)
			}
		}
		for _, sg := range agentAll {
			add(sg)
		}
		for _, sg := range fileSigners {
			add(sg)
		}
		return all, nil
	})}, nil
}

// identityPublicKeys returns the marshalled public keys of the identity files,
// read from <file>.pub, from the file itself when it holds a public key, or
// from the cleartext public half of an OpenSSH private key (so a passphrase
// protected key held by the agent still matches).
func identityPublicKeys(paths []string) map[string]bool {
	out := map[string]bool{}
	for _, p := range paths {
		for _, f := range []string{p + ".pub", p} {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if k, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
				out[string(k.Marshal())] = true
				break
			}
			if k := openSSHPrivatePublic(data); k != nil {
				out[string(k.Marshal())] = true
				break
			}
		}
	}
	return out
}

// openSSHPrivatePublic extracts the public key stored in the clear in an
// "openssh-key-v1" private key file, or nil.
func openSSHPrivatePublic(data []byte) ssh.PublicKey {
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "OPENSSH PRIVATE KEY" {
		return nil
	}
	b := blk.Bytes
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return nil
	}
	b = b[len(magic):]
	readString := func() []byte {
		if len(b) < 4 {
			return nil
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(n) > uint64(len(b)-4) {
			return nil
		}
		v := b[4 : 4+n]
		b = b[4+n:]
		return v
	}
	for i := 0; i < 3; i++ { // cipher, kdf, kdf options
		if readString() == nil && len(b) < 4 {
			return nil
		}
	}
	if len(b) < 4 || binary.BigEndian.Uint32(b) < 1 {
		return nil
	}
	b = b[4:]
	k, err := ssh.ParsePublicKey(readString())
	if err != nil {
		return nil
	}
	return k
}

func joinLines(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += "\n  "
		}
		result += s
	}
	return result
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// hostKeyVerdict decides what to do with the knownhosts callback's answer.
//
// The old policy accepted unknown hosts AND key mismatches, on the stated
// grounds that "litevirt manages its own trust via mTLS -- SSH is just a
// transport for setup/upgrade operations". That is exactly backwards for the
// operation it is used by: `lv host init` and `lv host add` use SSH to carry
// the cluster CA-signed HOST PRIVATE KEY to a machine that has no mTLS
// identity yet. There is no other anchor at that moment, so accepting a
// changed key hands that key to whoever answered.
//
// knownhosts.KeyError distinguishes the two cases by Want:
//
//   - empty  -- the host is UNKNOWN. Unavoidable: provisioning a new machine
//     is always first contact. Accepted (the documented
//     StrictHostKeyChecking=accept-new behaviour).
//   - non-empty -- the host is KNOWN and the key CHANGED. Refused. Nothing
//     about provisioning requires this, and it is the whole MITM.
func hostKeyVerdict(hostname string, err error) error {
	return hostKeyVerdictFor(hostname, nil, err)
}

// hostKeyVerdictFor is hostKeyVerdict knowing the presented key, so a refusal
// can say when the key is of a type known_hosts holds no entry of. That is
// still refused -- it cannot be verified, and taking it as first contact would
// let an impostor dodge the pin by presenting another type -- but it is not
// evidence the recorded key changed.
func hostKeyVerdictFor(hostname string, key ssh.PublicKey, err error) error {
	if keyErr := (*knownhosts.KeyError)(nil); errors.As(err, &keyErr) {
		if len(keyErr.Want) == 0 {
			return nil // unknown host: accept-new
		}
		if key != nil && !recordsType(keyErr.Want, key.Type()) {
			var types []string
			for _, w := range keyErr.Want {
				types = append(types, w.Key.Type())
			}
			return fmt.Errorf("host key for %s cannot be verified -- refusing: it presented a %s "+
				"key, and known_hosts records only %s for it (%s:%d). This connection would "+
				"carry the cluster CA-signed host key",
				hostname, key.Type(), strings.Join(types, ", "), keyErr.Want[0].Filename, keyErr.Want[0].Line)
		}
		return fmt.Errorf("host key for %s CHANGED (known key at %s:%d) -- refusing: "+
			"this connection would carry the cluster CA-signed host key, and a changed "+
			"key means something other than the host we trusted is answering. If the "+
			"host was genuinely rebuilt, remove its known_hosts entry first",
			hostname, keyErr.Want[0].Filename, keyErr.Want[0].Line)
	}
	return err
}

func recordsType(want []knownhosts.KnownKey, keyType string) bool {
	for _, w := range want {
		if w.Key != nil && w.Key.Type() == keyType {
			return true
		}
	}
	return false
}

// firstContactOnlyCallback is used when no known_hosts is usable at all.
//
// It accepts, because with no store there is no previous key to contradict and
// refusing would make `lv host init` impossible on a fresh workstation. It is a
// named function rather than ssh.InsecureIgnoreHostKey so the two cases cannot
// be confused: this one has been reported to the operator, and it is reached
// only when the store itself is missing -- never to paper over a MISMATCH,
// which hostKeyVerdict refuses even here.
func firstContactOnlyCallback(host string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		slog.Warn("ssh: host key not verified (no known_hosts store)",
			"host", host, "remote", remote.String(), "key_type", key.Type())
		return nil
	}
}

// errNoKnownHosts marks the one condition under which first contact may be
// accepted unchecked: there is no known_hosts store at all.
var errNoKnownHosts = errors.New("no known_hosts")

func defaultHostKeyCallback() (ssh.HostKeyCallback, error) {
	cb, _, err := hostKeyPolicyFor(nil, "")
	return cb, err
}

// openSSHGlobalKnownHosts is OpenSSH's built-in GlobalKnownHostsFile.
var openSSHGlobalKnownHosts = []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}

// defaultGlobalKnownHosts is the global known_hosts files used when the
// config names OpenSSH's default (or ssh -G gives no answer). Always
// openSSHGlobalKnownHosts outside tests, which point it at files of their own
// so they never read this machine's /etc/ssh.
var defaultGlobalKnownHosts = slices.Clone(openSSHGlobalKnownHosts)

// knownHostsFiles lists the known_hosts files that verify a host under cfg
// (nil: the defaults): ~/.ssh/known_hosts{,2} always -- a configured
// UserKnownHostsFile adds to them and never replaces them, so a key they hold
// cannot be bypassed with /dev/null -- then the configured UserKnownHostsFile
// entries, then the GlobalKnownHostsFile ones (by default
// /etc/ssh/ssh_known_hosts{,2}, where config management often distributes a
// fleet's host keys). All are only ever read.
//
// An absent file is skipped, as ssh skips it. One that exists but cannot be
// read or parsed is an error naming it, never skipped: it could hold the key
// that contradicts the others. errNoKnownHosts means there is no file at all.
func knownHostsFiles(cfg *resolved) ([]string, error) {
	var files []string
	use := func(kind, f string) error {
		if _, err := os.Stat(f); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if _, err := knownhosts.New(f); err != nil {
			return fmt.Errorf("%s %s is unusable: %w", kind, f, err)
		}
		files = append(files, f)
		return nil
	}
	def := "~/.ssh/known_hosts"
	if home, err := os.UserHomeDir(); err == nil {
		def = filepath.Join(home, ".ssh", "known_hosts")
		for _, f := range []string{def, def + "2"} {
			if err := use("known_hosts", f); err != nil {
				return nil, err
			}
		}
	}
	global := defaultGlobalKnownHosts
	if cfg != nil {
		for _, f := range cfg.KnownHosts {
			if err := use("UserKnownHostsFile", f); err != nil {
				return nil, err
			}
		}
		global = cfg.GlobalKnownHosts
	}
	for _, f := range global {
		if err := use("GlobalKnownHostsFile", f); err != nil {
			return nil, err
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: %s does not exist", errNoKnownHosts, def)
	}
	return files, nil
}

// hostKeyPolicyFor reads the known_hosts files cfg names once and returns the
// verifying callback and, for a non-empty addr (host:port as dialled), the
// host-key algorithms to ask it for. The two come from the same in-memory
// database, so they cannot disagree.
//
// Nothing in the ssh config makes it accept more than the defaults do:
//   - UserKnownHostsFile and GlobalKnownHostsFile only add files to check;
//   - StrictHostKeyChecking yes refuses an unknown host too, and no or
//     accept-new are not read at all -- a CHANGED key is always refused;
//   - HostKeyAlias makes the alias the name a key is looked up under, as ssh
//     does (certificate principals included), so a key pinned under it is
//     enforced. When known_hosts has no entry for the alias, the dialled
//     address is checked instead of taking the host as new, so a key pinned
//     under the address is not bypassed either -- except under
//     StrictHostKeyChecking yes, where an unknown alias is refused as ssh
//     refuses it;
//   - HostKeyAlgorithms is not read (see clientConfig).
func hostKeyPolicyFor(cfg *resolved, addr string) (ssh.HostKeyCallback, []string, error) {
	files, err := knownHostsFiles(cfg)
	if err != nil {
		return nil, nil, err
	}
	raw, err := knownhosts.New(files...)
	if err != nil {
		return nil, nil, err
	}
	// Each file is also a source of its own: the merged database accepts as
	// soon as ANY line for the host matches, so a stale or planted entry in
	// one file would override a pin in another. Every source that has entries
	// for the host must accept the key.
	type source struct {
		file string
		cb   ssh.HostKeyCallback
	}
	var sources []source
	var wildcards []wildcardPortPattern
	for _, f := range files {
		cb, err := knownhosts.New(f)
		if err != nil {
			return nil, nil, err
		}
		sources = append(sources, source{f, cb})
		w, err := wildcardPortPatterns(f)
		if err != nil {
			return nil, nil, err
		}
		wildcards = append(wildcards, w...)
	}
	// knownSources are the sources with an entry (plain or CA) for name.
	knownSources := func(name string) []source {
		var out []source
		for _, src := range sources {
			if hostIsKnown(src.cb, name) {
				out = append(out, src)
			}
		}
		return out
	}
	var alias string
	var strict bool
	if cfg != nil {
		alias, strict = cfg.HostKeyAlias, cfg.StrictYes
	}
	// lookup is the name hostname's key is looked up under. The offer and
	// the verification both use it, so they agree on which entries apply.
	lookup := func(hostname string) string {
		if alias == "" {
			return hostname
		}
		// ssh looks the alias up with no port; for knownhosts that is 22,
		// which a bare "alias" line matches.
		a := net.JoinHostPort(alias, "22")
		if strict || hostIsKnown(raw, a) {
			return a
		}
		return hostname
	}
	var algos []string
	if addr != "" {
		name := lookup(addr)
		algos = knownHostKeyAlgorithms(raw, name)
		// Ask for what EVERY source that knows the host can vouch for: with
		// the union, a host all files record under RSA would be asked for an
		// ed25519 key one file holds, and the others would refuse it. An
		// empty intersection keeps the union, which then refuses.
		var per [][]string
		for _, src := range knownSources(name) {
			per = append(per, knownHostKeyAlgorithms(src.cb, name))
		}
		if common := commonHostKeyAlgorithms(algos, per); len(common) > 0 {
			algos = common
		}
	}
	// accept-new, not accept-anything: see hostKeyVerdict for why a CHANGED
	// key is refused even though an unknown one is not. Strict wraps the raw
	// answer, so the verdict's refusals stay reachable under it.
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		name, label := lookup(hostname), hostname
		if name != hostname {
			label = fmt.Sprintf("%s (HostKeyAlias %s)", hostname, alias)
		}
		// A pattern x/crypto cannot evaluate (a wildcard port) could be the
		// pin for this host; it would silently never match.
		if h, _, err := net.SplitHostPort(name); err == nil {
			for _, w := range wildcards {
				if w.mayMatch(h) {
					return fmt.Errorf("%s:%d: known_hosts pattern %q has a wildcard port, which litevirt "+
						"cannot evaluate, and could pin %s -- refusing. List the port explicitly",
						w.file, w.line, w.pattern, label)
				}
			}
		}
		err := raw(name, remote, key)
		if strict && err != nil {
			if keyErr := (*knownhosts.KeyError)(nil); errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
				return fmt.Errorf("host key for %s is not in known_hosts and StrictHostKeyChecking is yes: %w", label, err)
			}
		}
		if err != nil {
			// No source matches (or the key is revoked, or a certificate
			// fails): the merged answer already decides -- CHANGED, or first
			// contact when no source has any entry.
			return hostKeyVerdictFor(label, key, err)
		}
		// Some source matched. Every other source that records the host must
		// match too; one that records a different key (or another type, or
		// no CA for a presented certificate) refuses.
		for _, src := range knownSources(name) {
			checked := key
			if cert, ok := key.(*ssh.Certificate); ok && !sourceHasCA(src.cb, name) {
				// A source with only plain entries vouches for the key inside
				// the certificate: the same key agrees, a different one refuses.
				checked = cert.Key
			}
			if serr := src.cb(name, remote, checked); serr != nil {
				if v := hostKeyVerdictFor(label, checked, serr); v != nil {
					return fmt.Errorf("%w (known_hosts sources disagree: each file that records the "+
						"host must hold the presented key; %s does not)", v, src.file)
				}
				return fmt.Errorf("host key for %s does not match %s -- refusing", label, src.file)
			}
		}
		return nil
	}, algos, nil
}

type bytesReaderWrapper struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReaderWrapper {
	return &bytesReaderWrapper{data: data}
}

func (r *bytesReaderWrapper) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return
}

// dialTimeout is ssh.Dial with one bound on the TCP connect and the SSH
// handshake together: ssh.Dial bounds neither the handshake nor, without
// ClientConfig.Timeout, the connect.
//
// The deadline is fixed before the dial, so the connect and the handshake
// share timeout rather than each getting its own. With keepDeadline it stays
// on the connection, bounding the whole session to timeout.
var dialTimeout = func(addr string, config *ssh.ClientConfig, timeout time.Duration, keepDeadline bool) (*ssh.Client, error) {
	deadline := time.Now().Add(timeout)
	conn, err := dialConn(addr, deadline)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !keepDeadline {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			c.Close()
			return nil, err
		}
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// dialConn is the TCP connect of dialTimeout, given up at deadline.
var dialConn = func(addr string, deadline time.Time) (net.Conn, error) {
	d := net.Dialer{Deadline: deadline}
	return d.Dial("tcp", addr)
}
