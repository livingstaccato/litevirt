package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
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
	sshUser, host, port := parseTarget(target)

	auth, err := authMethods()
	if err != nil {
		return nil, fmt.Errorf("SSH auth: %w", err)
	}

	addr := net.JoinHostPort(host, port)
	config := clientConfig(sshUser, auth, host, addr)
	var conn *ssh.Client
	if timeout > 0 {
		conn, err = dialTimeout(addr, config, timeout, keepDeadline)
	} else {
		conn, err = ssh.Dial("tcp", addr, config)
	}
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}

	return &Client{conn: conn, addr: addr}, nil
}

// clientConfig is the ClientConfig every litevirt SSH dial uses: the given
// auth, and the host-key policy for addr.
func clientConfig(sshUser string, auth []ssh.AuthMethod, host, addr string) *ssh.ClientConfig {
	hostKeyCallback, hostKeyAlgos, err := defaultHostKeyPolicy(addr)
	if err != nil {
		// No usable known_hosts (no HOME, unreadable file). Accept-new still
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
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgos,
	}
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
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(raw(addr, &net.TCPAddr{IP: net.IPv4zero}, probe), &keyErr) || len(keyErr.Want) == 0 {
		return slices.Clone(firstContactHostKeyAlgorithms)
	}
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

// CopyFile copies a local file to a remote path using SCP-like semantics.
func (c *Client) CopyFile(localPath, remotePath string) error {
	return c.CopyFileMode(localPath, remotePath, 0644)
}

// CopyFileMode copies a local file to the remote host with an explicit mode.
//
// It exists because CopyFile's 0644 default is wrong for private keys, and
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

// Interactive runs a command on the remote host with a PTY attached,
// connecting local stdin/stdout/stderr. Used for lv console.
func (c *Client) Interactive(cmd string) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("make raw terminal: %w", err)
	}
	defer term.Restore(fd, oldState)

	w, h, _ := term.GetSize(fd)
	if err := session.RequestPty("xterm-256color", h, w, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request PTY: %w", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Forward SIGWINCH (terminal resize) to remote session.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			w, h, _ := term.GetSize(fd)
			session.WindowChange(h, w)
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("start command: %w", err)
	}
	return session.Wait()
}

// Conn returns the underlying SSH client connection (used for tunneling).
func (c *Client) Conn() *ssh.Client {
	return c.conn
}

func parseTarget(target string) (user, host, port string) {
	user = "root"
	host = target
	port = "22"

	for i, c := range target {
		if c == '@' {
			user = target[:i]
			host = target[i+1:]
			break
		}
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	return
}

func authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	var tried []string

	// Try SSH agent first
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		tried = append(tried, "agent: SSH_AUTH_SOCK not set")
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
				methods = append(methods, ssh.PublicKeysCallback(ac.Signers))
			}
		}
	}

	// Try default key files
	home, _ := os.UserHomeDir()
	keyFiles := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
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
		methods = append(methods, ssh.PublicKeys(key))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available:\n  %s", joinLines(tried))
	}

	return methods, nil
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

func defaultHostKeyCallback() (ssh.HostKeyCallback, error) {
	cb, _, err := defaultHostKeyPolicy("")
	return cb, err
}

// defaultHostKeyPolicy reads ~/.ssh/known_hosts once and returns the verifying
// callback and, for a non-empty addr, the host-key algorithms to ask it for.
func defaultHostKeyPolicy(addr string) (ssh.HostKeyCallback, []string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")
	raw, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, nil, err
	}
	var algos []string
	if addr != "" {
		algos = knownHostKeyAlgorithms(raw, addr)
	}
	// accept-new, not accept-anything: see hostKeyVerdict for why a CHANGED
	// key is refused even though an unknown one is not.
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return hostKeyVerdictFor(hostname, key, raw(hostname, remote, key))
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
