package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
	"github.com/litevirt/litevirt/internal/ssh"
)

// HostAdd adds a new host to an existing cluster.
func HostAdd(ctx context.Context, c pb.LiteVirtClient, sshTarget string, hostName string, joinPeers []string) error {
	// Before anything is generated or pushed, because a failure here must leave the
	// target untouched.
	//
	// The peer list is gathered best-effort by the caller: it asks the local daemon
	// for the current hosts and carries on if that fails. Carrying on means writing
	// `join_peers: []` onto the new node — certificates, binary and a running daemon,
	// and no way to find the cluster — and then reporting success. `add` always has
	// at least one host to join by definition; if it did not, this would be `init`.
	if len(joinPeers) == 0 {
		return fmt.Errorf("no gossip peers to join: could not read the existing cluster's "+
			"hosts, so %s would be provisioned with an empty join_peers and never reach the "+
			"cluster. Check that a daemon is reachable from here (lv host ls), or that this "+
			"is not the first host — the first one is `lv host init`", hostName)
	}
	pkiDir := PKIDir()

	// Verify CA exists
	caPath := filepath.Join(pkiDir, "ca.crt")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		return fmt.Errorf("no cluster CA found — run 'lv host init' first")
	}

	parsedHost, sshUser, err := parseSSHTarget(sshTarget)
	if err != nil {
		return err
	}
	hostAddr, err := resolveHost(parsedHost)
	if err != nil {
		return err
	}

	// Format join_peers as YAML array, e.g. ["10.0.50.10:7946","10.0.50.11:7946"]
	peersYAML := "["
	for i, p := range joinPeers {
		if i > 0 {
			peersYAML += ","
		}
		peersYAML += fmt.Sprintf("%q", p)
	}
	peersYAML += "]"

	// Decided before anything is minted or pushed, like the peer list: a refusal
	// here must leave the target untouched.
	enforcement, err := addSetupEnforcement(sshUser, joinPeers)
	if err != nil {
		return err
	}
	// The gossip key goes with ca.crt. A keyed cluster with no key here is a
	// refusal now, before anything is minted or pushed.
	gossipKeyPath, pushGossipKey, err := gossipKeyToPush(pkiDir, enforcement)
	if err != nil {
		return err
	}
	if !pushGossipKey {
		gossipKeyPath = ""
	}
	// The migration CA, likewise decided before anything is pushed: minted here
	// only when no join peer already holds credentials from one elsewhere.
	migHolder := peerMigrationHolder(sshUser, joinPeers)
	if _, _, _, err := ensureLocalMigrationCA(pkiDir, migHolder); err != nil {
		return err
	}

	// Generate CLI client certificate if it doesn't exist
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	clientCertPath := filepath.Join(pkiDir, "client.crt")
	clientKeyPath := filepath.Join(pkiDir, "client.key")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("generating CLI client certificate")
		if err := pki.GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}

	binPath, err := findDaemonBinary()
	if err != nil {
		return fmt.Errorf("find litevirtd binary: %w", err)
	}
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}

	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	return hostAddTo(ctx, c, &sshAddRemote{sshRemotePKI{sc: sc}}, hostAddPlan{
		pkiDir: pkiDir, hostName: hostName, hostAddr: hostAddr, peersYAML: peersYAML,
		enforcement: enforcement, gossipKeyPath: gossipKeyPath, migHolder: migHolder,
		binPath: binPath, setupScript: setupScript,
		rerun: fmt.Sprintf("lv host add --name %s %s", hostName, sshTarget),
	})
}

// hostAddPlan is what HostAdd decided before it reached the new machine.
type hostAddPlan struct {
	pkiDir, hostName, hostAddr, peersYAML, enforcement string
	// gossipKeyPath is this machine's gossip key, "" when none is pushed.
	gossipKeyPath string
	migHolder     migrationCredentialHolder
	binPath       string
	setupScript   string
	// rerun is the command that finishes an add that failed after admission.
	rerun string
}

// addRemote is what `lv host add` does on the new machine. sshAddRemote runs
// it over SSH; LocalAddTarget on a directory.
type addRemote interface {
	// ReadFile returns path's contents, or ok=false when it does not exist.
	ReadFile(path string) (data []byte, ok bool, err error)
	Run(cmd string) error
	RunWithInput(cmd string, input []byte) error
	// WriteFile puts data at path by rename, so a running executable at path
	// is replaced, not written into.
	WriteFile(path string, data []byte, mode os.FileMode) error
	// Exists reports which of paths exist.
	Exists(paths []string) (map[string]bool, error)
	// InstallKeeping puts each file in place by rename, after copying each
	// file it replaces to its path plus suffix.
	InstallKeeping(files []installFile, suffix string) error
	// Restore undoes InstallKeeping: a file that existed (existed[path]) gets
	// its copy back, and one that did not is removed.
	Restore(files []installFile, existed map[string]bool, suffix string) error
}

// hostAddTo is HostAdd once the new machine is reachable through r.
func hostAddTo(ctx context.Context, c pb.LiteVirtClient, r addRemote, p hostAddPlan) error {
	caPath := filepath.Join(p.pkiDir, "ca.crt")
	caKeyPath := filepath.Join(p.pkiDir, "ca.key")
	hostCertPath := filepath.Join(p.pkiDir, p.hostName+".crt")
	hostKeyPath := filepath.Join(p.pkiDir, p.hostName+".key")
	ip := net.ParseIP(p.hostAddr)

	hosts, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list the cluster's hosts before adding %s: %w", p.hostName, err)
	}
	// The certificate of an earlier `lv host add` of this machine that was
	// admitted and did not finish is used again: the daemon admits it again,
	// where a new one is refused while the name is live.
	serial, reused := unfinishedAdd(hosts.GetHosts(), p, hostCertPath, hostKeyPath)
	if !reused {
		// Minted beside the operator's copy and moved over it only once
		// admitted: a refused add leaves a live host's copy alone.
		stagedCert := filepath.Join(p.pkiDir, "."+p.hostName+".crt.add")
		stagedKey := filepath.Join(p.pkiDir, "."+p.hostName+".key.add")
		defer os.Remove(stagedCert)
		defer os.Remove(stagedKey)
		if err := pki.GenerateHostCert(caPath, caKeyPath, stagedCert, stagedKey, p.hostName, ip); err != nil {
			return fmt.Errorf("generate host cert: %w", err)
		}
		if serial, err = pki.CertSerial(stagedCert); err != nil {
			return fmt.Errorf("read generated host certificate serial: %w", err)
		}
		hostCertPath, hostKeyPath = stagedCert, stagedKey
	}
	if err := refuseLiveMember(r, hosts.GetHosts(), p.hostName, serial); err != nil {
		return err
	}

	// Every check the daemon makes runs here, before anything reaches the
	// machine: pushing first replaced the key of a machine whose add was then
	// refused, and a live host's daemon serves its identity from disk.
	//
	// The header is this command's claim that it installs its own build,
	// which keeps a host incarnation; the daemon cannot check which binary
	// findDaemonBinary pushes (docs/upgrades.md).
	admitCtx := metadata.AppendToOutgoingContext(ctx, apimeta.AdmitInstallsReleaseHeader, capabilities.ReleaseToken)
	admitted, err := c.AdmitHost(admitCtx, &pb.AdmitHostRequest{
		Name: p.hostName, Address: p.hostAddr, CertSerial: serial,
	})
	if err != nil {
		return fmt.Errorf("admit host identity to the cluster (nothing was pushed to the host): %w", err)
	}
	if why := admitted.GetIncarnationNotIssued(); why != "" {
		fmt.Printf("  re-admitted %s without a host incarnation: %s\n", p.hostName, why)
	}
	failed := func(err error) error {
		return fmt.Errorf("%w\n%s is admitted to the cluster (joining) with certificate %s; "+
			"run `%s` to finish the add", err, p.hostName, serial, p.rerun)
	}
	if !reused {
		final := filepath.Join(p.pkiDir, p.hostName)
		if err := os.Rename(hostKeyPath, final+".key"); err != nil {
			return failed(fmt.Errorf("keep the admitted host key: %w", err))
		}
		if err := os.Rename(hostCertPath, final+".crt"); err != nil {
			return failed(fmt.Errorf("keep the admitted host certificate: %w", err))
		}
		hostCertPath, hostKeyPath = final+".crt", final+".key"
	}
	migFiles, err := issueMigrationCredentials(p.pkiDir, p.hostName, ip, p.migHolder)
	if err != nil {
		return failed(err)
	}
	files, err := addIdentityFiles(p, hostCertPath, hostKeyPath, migFiles)
	if err != nil {
		return failed(err)
	}
	if err := r.Run("mkdir -p " + ssh.ShellQuote(remotePKIDir) + " && mkdir -p -m 0700 " + ssh.ShellQuote(remoteMigrationDir)); err != nil {
		return failed(fmt.Errorf("create remote PKI dir: %w", err))
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.path
	}
	existed, err := r.Exists(paths)
	if err != nil {
		return failed(fmt.Errorf("check which identity files the host already has: %w", err))
	}
	// Nothing the machine holds is overwritten without a copy, and the copies
	// go back if the add does not finish.
	suffix := ".pre-add-" + time.Now().UTC().Format("20060102T150405Z")
	restore := func(err error) error {
		if rerr := r.Restore(files, existed, suffix); rerr != nil {
			return failed(fmt.Errorf("%w\nputting back the files it replaced failed too (%v): each one it "+
				"replaced is kept beside it as <file>%s", err, rerr, suffix))
		}
		return failed(fmt.Errorf("%w\nthe host's previous identity files were put back", err))
	}
	if err := r.InstallKeeping(files, suffix); err != nil {
		return restore(fmt.Errorf("push the host identity: %w", err))
	}
	if err := pushAddBinary(r, p.binPath); err != nil {
		return restore(err)
	}
	if err := finishAdd(r, p, serial, admitted); err != nil {
		return restore(err)
	}
	for _, f := range files {
		if existed[f.path] {
			fmt.Printf("  kept the %s it replaced as %s\n", f.path, f.path+suffix)
		}
	}
	return addedLocally(p)
}

// unfinishedAdd returns the serial of this machine's copy of hostName's pair
// when it is the certificate the cluster admitted for an add of this address
// that has not finished: the row is joining and names it.
func unfinishedAdd(hosts []*pb.Host, p hostAddPlan, certPath, keyPath string) (string, bool) {
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return "", false
	}
	serial, err := pki.CertSerial(certPath)
	if err != nil {
		return "", false
	}
	for _, h := range hosts {
		if h.GetName() == p.hostName && h.GetState() == pb.HostState_HOST_JOINING &&
			h.GetAddress() == p.hostAddr && strings.EqualFold(h.GetCertSerial(), serial) {
			return serial, true
		}
	}
	return "", false
}

// refuseLiveMember refuses a machine that serves a live member's current
// certificate: adding it would replace that member's identity, whatever name
// it is added under. The certificate of this add's own unfinished admission
// (serial, under hostName) is not another member.
func refuseLiveMember(r addRemote, hosts []*pb.Host, hostName, serial string) error {
	b, ok, err := r.ReadFile(filepath.Join(remotePKIDir, "host.crt"))
	if err != nil {
		return fmt.Errorf("read the host's installed certificate before adding it: %w", err)
	}
	installed := installedSerial(b)
	if !ok || installed == "" {
		return nil
	}
	for _, h := range hosts {
		if !strings.EqualFold(h.GetCertSerial(), installed) {
			continue
		}
		if h.GetName() == hostName && strings.EqualFold(installed, serial) {
			return nil
		}
		return fmt.Errorf("the host serves %s's current certificate (serial %s): it is a live member of the "+
			"cluster, and adding it would replace %s's identity on disk. Nothing was pushed. To add this "+
			"machine again, remove it first (`lv host rm %s`)", h.GetName(), installed, h.GetName(), h.GetName())
	}
	return nil
}

// addIdentityFiles is the key material an add installs: the cluster CA, the
// host's pair, the gossip key, and its migration credentials.
func addIdentityFiles(p hostAddPlan, hostCertPath, hostKeyPath string, migFiles []migrationFile) ([]installFile, error) {
	// The host KEY is 0600. It is the node's entire cluster identity: peer mTLS
	// authenticates with it and audit rows are signed with it, so a local user
	// who can read it can both impersonate the host to every peer and forge its
	// audit history.
	src := []migrationFile{
		{filepath.Join(p.pkiDir, "ca.crt"), filepath.Join(remotePKIDir, "ca.crt"), 0o644},
		{hostCertPath, filepath.Join(remotePKIDir, "host.crt"), 0o644},
		{hostKeyPath, filepath.Join(remotePKIDir, "host.key"), 0o600},
	}
	if p.gossipKeyPath != "" {
		// 0600 for the same reason as host.key: whoever reads it speaks gossip.
		src = append(src, migrationFile{p.gossipKeyPath, filepath.Join(remotePKIDir, pki.GossipKeyName), 0o600})
	}
	src = append(src, migFiles...)
	files := make([]installFile, 0, len(src))
	for _, f := range src {
		b, err := os.ReadFile(f.local)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.local, err)
		}
		files = append(files, installFile{path: f.remote, data: b, mode: f.mode})
	}
	return files, nil
}

// pushAddBinary installs the litevirt binary and the `lv` symlink. The write
// is a rename, so a daemon running from the old binary does not stop it.
func pushAddBinary(r addRemote, binPath string) error {
	slog.Info("pushing litevirt binary", "path", binPath)
	b, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("push litevirt binary: %w", err)
	}
	if err := r.WriteFile("/usr/local/bin/litevirt", b, 0o755); err != nil {
		return fmt.Errorf("push litevirt binary: %w", err)
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := r.Run("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv"); err != nil {
		return fmt.Errorf("symlink lv: %w", err)
	}
	return nil
}

// finishAdd writes the audit admission record and runs setup, which starts
// the daemon.
func finishAdd(r addRemote, p hostAddPlan, serial string, admitted *pb.AdmitHostResponse) error {
	// The name's audit chain position, signed with the CA, so the new machine's
	// daemon holds its own audit rows until that history has reached it instead
	// of starting a second chain under an old name. Before setup, which starts
	// the daemon. A name with no history gets no record — and loses any a
	// previous machine under the name left behind.
	rejoin, remove, err := AuditRejoinFile(p.pkiDir, p.hostName, serial, admitted)
	if err != nil {
		return fmt.Errorf("sign %s's audit admission record: %w", p.hostName, err)
	}
	rejoinPath := filepath.Join(remotePKIDir, corrosion.AuditRejoinFileName)
	if rejoin != nil {
		if err := r.WriteFile(rejoinPath, rejoin, 0644); err != nil {
			return fmt.Errorf("push %s: %w", corrosion.AuditRejoinFileName, err)
		}
	} else if remove {
		if err := r.Run("rm -f " + ssh.ShellQuote(rejoinPath)); err != nil {
			return fmt.Errorf("remove a stale %s: %w", corrosion.AuditRejoinFileName, err)
		}
	}
	// hostAddr is the address this command just put in the certificate SAN and the
	// address peers were told to dial, so it is also the address the node must
	// advertise. Leaving the daemon to auto-detect meant it registered with its
	// default-route source IP — a different interface on a multi-homed host — and
	// that value was then copied into the join_peers of every host added after it.
	//
	// Admission must replicate before setup starts the daemon. A re-added node's
	// local database still contains its tombstone; starting it first lets its boot
	// state update put a fresh timestamp on that tombstone and race the admission
	// back out to the cluster.
	if err := r.RunWithInput(remoteAddSetupCommand(p.hostName, p.hostAddr, p.peersYAML, p.enforcement), []byte(p.setupScript)); err != nil {
		return fmt.Errorf("run setup script after admitting the host identity: %w", err)
	}
	return nil
}

// addedLocally back-fills the new host into THIS machine's gossip seed list.
// The daemon needs a restart to pick it up, and memberlist may discover the
// peer through existing members anyway — but the seed list is now load-bearing
// for more than gossip, so only one failure here is benign.
//
// Running `lv` from a workstation is supported, and a workstation has no
// daemon config to update. That is errNotALocalNode, and it is fine.
//
// Anything else means this machine IS a cluster node whose join_peers could
// not be updated, and a slog.Warn is not enough: an empty join_peers is what
// makes a node look like a FOUNDER, so leaving it wrong sets up a later
// state.db rebuild to mint a fresh admin credential over the cluster's.
func addedLocally(p hostAddPlan) error {
	if err := ensureLocalPeer(daemonConfigPath, p.hostAddr, 7946); err != nil {
		if errors.Is(err, errNotALocalNode) {
			slog.Info("this machine is not a cluster node, so it has no join_peers to back-fill",
				"config", daemonConfigPath)
		} else {
			return fmt.Errorf("host %s WAS added to the cluster, but this machine's own "+
				"join_peers in %s could not be updated (%w) — add %s to it by hand before "+
				"restarting the daemon, or this node still looks like a founder",
				p.hostName, daemonConfigPath, err, net.JoinHostPort(p.hostAddr, strconv.Itoa(7946)))
		}
	}
	fmt.Printf("Host %s added to cluster at %s\n", p.hostName, p.hostAddr)
	return nil
}

// installedSerial is the serial of a PEM certificate, lower-case hex, or ""
// when b holds none.
func installedSerial(b []byte) string {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	return strings.ToLower(cert.SerialNumber.Text(16))
}

// sshAddRemote is addRemote over SSH.
type sshAddRemote struct{ sshRemotePKI }

func (r *sshAddRemote) Run(cmd string) error { return r.sc.Run(cmd) }

func (r *sshAddRemote) RunWithInput(cmd string, input []byte) error {
	return r.sc.RunWithInput(cmd, input)
}

func (r *sshAddRemote) WriteFile(path string, data []byte, mode os.FileMode) error {
	return r.sc.WriteFile(path, data, mode)
}

func (r *sshAddRemote) Exists(paths []string) (map[string]bool, error) {
	out, err := r.sc.RunOutput(existsCmd(paths))
	if err != nil {
		return nil, err
	}
	got := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		if l != "" {
			got[l] = true
		}
	}
	return got, nil
}

// existsCmd prints each of paths that exists, one per line.
func existsCmd(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		q := ssh.ShellQuote(p)
		fmt.Fprintf(&b, "if [ -e %s ]; then printf '%%s\\n' %s; fi; ", q, q)
	}
	return b.String()
}

func (r *sshAddRemote) InstallKeeping(files []installFile, suffix string) error {
	// Stage everything first: a dropped connection mid-transfer leaves the
	// installed files untouched.
	for _, f := range files {
		if err := r.sc.WriteFile(addStagedPath(f.path), f.data, f.mode); err != nil {
			return fmt.Errorf("stage %s: %w", filepath.Base(f.path), err)
		}
	}
	return r.sc.Run(installKeepingCmd(files, suffix))
}

// installKeepingCmd copies every file it replaces (cp -p keeps a key's 0600)
// before it moves any staged file into place.
func installKeepingCmd(files []installFile, suffix string) string {
	var cmd strings.Builder
	cmd.WriteString("set -e; ")
	for _, f := range files {
		q := ssh.ShellQuote(f.path)
		fmt.Fprintf(&cmd, "if [ -e %s ]; then cp -pP -- %s %s; fi; ", q, q, ssh.ShellQuote(f.path+suffix))
	}
	for _, f := range files {
		fmt.Fprintf(&cmd, "mv -fT -- %s %s; ", ssh.ShellQuote(addStagedPath(f.path)), ssh.ShellQuote(f.path))
	}
	return cmd.String()
}

func (r *sshAddRemote) Restore(files []installFile, existed map[string]bool, suffix string) error {
	return r.sc.Run(restoreCmd(files, existed, suffix))
}

// restoreCmd puts back each file that existed from its copy, and removes each
// one that did not. A file whose copy is missing was never replaced.
func restoreCmd(files []installFile, existed map[string]bool, suffix string) string {
	var cmd strings.Builder
	for _, f := range files {
		q := ssh.ShellQuote(f.path)
		if existed[f.path] {
			b := ssh.ShellQuote(f.path + suffix)
			fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s; fi; ", b, b, q)
		} else {
			fmt.Fprintf(&cmd, "rm -f -- %s; ", q)
		}
		fmt.Fprintf(&cmd, "rm -f -- %s; ", ssh.ShellQuote(addStagedPath(f.path)))
	}
	return cmd.String()
}

func addStagedPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".add")
}

// LocalAddTarget is addRemote over a directory tree this process can reach (a
// test's): /etc/litevirt/pki maps to PKIDir and every other absolute path
// under Root. Commands are recorded, not run.
type LocalAddTarget struct {
	Root, PKIDir string
	// Binary is the file pushed as the litevirt binary.
	Binary string
	// FailSetup is what running setup returns.
	FailSetup error
	// Commands are the commands run, in order; Wrote the paths written,
	// moved or removed.
	Commands []string
	Wrote    []string
}

func (d *LocalAddTarget) local(path string) string {
	if path == remotePKIDir || strings.HasPrefix(path, remotePKIDir+"/") {
		return filepath.Join(d.PKIDir, strings.TrimPrefix(path, remotePKIDir))
	}
	return filepath.Join(d.Root, path)
}

func (d *LocalAddTarget) ReadFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(d.local(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (d *LocalAddTarget) Run(cmd string) error {
	d.Commands = append(d.Commands, cmd)
	return nil
}

func (d *LocalAddTarget) RunWithInput(cmd string, _ []byte) error {
	d.Commands = append(d.Commands, cmd)
	if strings.HasSuffix(cmd, "bash -s") {
		return d.FailSetup
	}
	return nil
}

func (d *LocalAddTarget) WriteFile(path string, data []byte, mode os.FileMode) error {
	d.Wrote = append(d.Wrote, path)
	if err := os.MkdirAll(filepath.Dir(d.local(path)), 0o700); err != nil {
		return err
	}
	return secretfile.Write(d.local(path), data, mode)
}

func (d *LocalAddTarget) Exists(paths []string) (map[string]bool, error) {
	got := map[string]bool{}
	for _, p := range paths {
		if _, err := os.Lstat(d.local(p)); err == nil {
			got[p] = true
		}
	}
	return got, nil
}

func (d *LocalAddTarget) InstallKeeping(files []installFile, suffix string) error {
	for _, f := range files {
		if b, err := os.ReadFile(d.local(f.path)); err == nil {
			st, _ := os.Stat(d.local(f.path))
			if err := secretfile.Write(d.local(f.path+suffix), b, st.Mode().Perm()); err != nil {
				return err
			}
		}
	}
	for _, f := range files {
		if err := d.WriteFile(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func (d *LocalAddTarget) Restore(files []installFile, existed map[string]bool, suffix string) error {
	for _, f := range files {
		d.Wrote = append(d.Wrote, f.path)
		if existed[f.path] {
			b := d.local(f.path + suffix)
			if _, err := os.Stat(b); err == nil {
				if err := os.Rename(b, d.local(f.path)); err != nil {
					return err
				}
			}
			continue
		}
		if err := os.Remove(d.local(f.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// HostAddOn adds hostName at hostAddr to the cluster c reaches, on the
// machine t stands for, as `lv host add` does once it has reached it. The
// cluster runs no gossip key, and the migration CA in this machine's pki
// directory is used (minted when there is none).
func HostAddOn(ctx context.Context, c pb.LiteVirtClient, t *LocalAddTarget, hostName, hostAddr string) error {
	return hostAddTo(ctx, c, t, hostAddPlan{
		pkiDir: PKIDir(), hostName: hostName, hostAddr: hostAddr, peersYAML: "[]",
		binPath: t.Binary, rerun: "lv host add --name " + hostName + " root@" + hostAddr,
	})
}
