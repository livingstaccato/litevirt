package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	"gopkg.in/yaml.v3"
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
	// configInstalled says the add installs the host's merged config.yaml,
	// which setup then leaves alone.
	configInstalled bool
}

// addRemote is what `lv host add` does on the new machine. sshAddRemote runs
// it over SSH; LocalAddTarget on a directory.
type addRemote interface {
	// ReadFile returns path's contents, or ok=false when it does not exist.
	ReadFile(path string) (data []byte, ok bool, err error)
	Run(cmd string) error
	RunWithInput(cmd string, input []byte) error
	// WriteFile puts data at path by a synced rename.
	WriteFile(path string, data []byte, mode os.FileMode) error
	// Path is how the file commands below must name path; Unpath maps a
	// path they print back.
	Path(path string) string
	Unpath(path string) string
	// Shell runs one of the file commands (installCmd, restoreCmd, ...);
	// kind names it.
	Shell(kind, cmd string) ([]byte, error)
}

const remoteBinary = "/usr/local/bin/litevirt"

// addFile is one file an add installs, from local bytes.
type addFile struct {
	path string
	data []byte
	mode os.FileMode
}

// hostAddTo is HostAdd once the new machine is reachable through r.
//
// Nothing live on the machine is written until the cluster has admitted the
// host: every file is uploaded to a staged path beside its destination
// first, and only moved into place after AdmitHost. A refused add, or one
// that fails before the admission, removes what it staged and leaves no row.
func hostAddTo(ctx context.Context, c pb.LiteVirtClient, r addRemote, p hostAddPlan) error {
	ip := net.ParseIP(p.hostAddr)
	hostCrt, hostKey := filepath.Join(remotePKIDir, "host.crt"), filepath.Join(remotePKIDir, "host.key")

	hostsResp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list the cluster's hosts before adding %s: %w", p.hostName, err)
	}
	hosts := hostsResp.GetHosts()
	installed, err := remoteSerial(r, hostCrt)
	if err != nil {
		return err
	}
	staged, err := remoteSerial(r, addStagedPath(hostCrt))
	if err != nil {
		return err
	}
	if err := refuseAnotherMember(hosts, p, installed); err != nil {
		return err
	}

	// An earlier add of this machine under this name: finish it with the
	// certificate it was admitted with, which the machine holds installed
	// or staged, or say that it already finished.
	serial, pairOnMachine := "", false
	if row := liveHost(hosts, p.hostName); row != nil && row.GetAddress() == p.hostAddr {
		admittedSerial := strings.ToLower(row.GetCertSerial())
		joining := row.GetState() == pb.HostState_HOST_JOINING
		switch {
		case installed == admittedSerial && !joining:
			fmt.Printf("Host %s is already a member at %s and serves the certificate it was admitted with; nothing to do\n",
				p.hostName, p.hostAddr)
			return addedLocally(p)
		case joining && (installed == admittedSerial || staged == admittedSerial):
			serial, pairOnMachine = admittedSerial, true
		case joining:
			return fmt.Errorf("%s is admitted (joining) with certificate %s, which the host holds neither installed "+
				"nor staged. Undo the admission with `lv host rm %s`, then run `%s` again",
				p.hostName, admittedSerial, p.hostName, p.rerun)
		}
	}

	var files []addFile
	var local []string // minted here, moved into place once admitted
	if !pairOnMachine {
		pair, s, err := mintStaged(p.pkiDir, p.hostName, ip, &local)
		if err != nil {
			removeAll(local)
			return err
		}
		serial = s
		files = append(files, addFile{hostCrt, pair[0], 0o644}, addFile{hostKey, pair[1], 0o600})
	} else if installed != serial {
		// The admitted pair waits at its staged paths from the earlier add.
		files = append(files, addFile{path: hostCrt}, addFile{path: hostKey})
	}
	rest, err := addOtherFiles(p, ip, &local)
	if err != nil {
		removeAll(local)
		return err
	}
	files = append(files, rest...)
	// A machine that already has a config (a re-added one) keeps it: the
	// keys the add must set are edited in, and setup leaves the file alone.
	cfg, err := hostConfig(r, p)
	if err != nil {
		removeAll(local)
		return err
	}
	if cfg != nil {
		files = append(files, *cfg)
		p.configInstalled = true
	}
	bin, err := os.ReadFile(p.binPath)
	if err != nil {
		removeAll(local)
		return fmt.Errorf("read the litevirt binary: %w", err)
	}

	// Upload everything to its staged path. Nothing it replaces yet.
	var wrote []string
	unstage := func() {
		if _, err := r.Shell("unstage", removeCmd(r, stagedPaths(wrote))); err != nil {
			slog.Warn("could not remove the files staged on the host", "error", err)
		}
		removeAll(local)
	}
	if err := r.Run("mkdir -p " + ssh.ShellQuote(remotePKIDir) + " && mkdir -p -m 0700 " + ssh.ShellQuote(remoteMigrationDir)); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}
	for _, f := range append(files, addFile{remoteBinary, bin, 0o755}) {
		if f.data == nil {
			continue
		}
		wrote = append(wrote, f.path)
		if err := r.WriteFile(addStagedPath(f.path), f.data, f.mode); err != nil {
			unstage()
			return fmt.Errorf("upload %s (nothing was admitted or installed): %w", filepath.Base(f.path), err)
		}
	}

	// Every check the daemon makes runs here. A refusal leaves the host as
	// it was: pushing first replaced the key of a live host whose add was
	// then refused.
	//
	// The header is this command's claim that it installs its own build,
	// which keeps a host incarnation; the daemon cannot check which binary
	// findDaemonBinary pushes (docs/upgrades.md).
	admitCtx := metadata.AppendToOutgoingContext(ctx, apimeta.AdmitInstallsReleaseHeader, capabilities.ReleaseToken)
	admitted, err := c.AdmitHost(admitCtx, &pb.AdmitHostRequest{
		Name: p.hostName, Address: p.hostAddr, CertSerial: serial,
	})
	if err != nil {
		unstage()
		return fmt.Errorf("admit host identity to the cluster (nothing was installed on the host): %w", err)
	}
	if why := admitted.GetIncarnationNotIssued(); why != "" {
		fmt.Printf("  re-admitted %s without a host incarnation: %s\n", p.hostName, why)
	}
	keepLocal(local)
	failed := func(err error) error {
		return fmt.Errorf("%w\n%s is admitted to the cluster (joining) with certificate %s and counts as a voter "+
			"until it starts. Run `%s` to finish the add, or `lv host rm %s` to undo the admission",
			err, p.hostName, serial, p.rerun, p.hostName)
	}

	// A machine re-added while its old daemon still runs would serve the
	// admitted identity from that stale process until setup restarts it.
	if err := r.Run("systemctl stop litevirt 2>/dev/null || true"); err != nil {
		return failed(fmt.Errorf("stop the host's daemon before installing: %w", err))
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.path
	}
	existedOut, err := r.Shell("exists", existsCmd(r, paths))
	if err != nil {
		return failed(fmt.Errorf("check which identity files the host already has: %w", err))
	}
	existed := existsSet(r, paths, existedOut)
	// Nothing the machine holds is overwritten without a copy, and the copies
	// go back if the add does not finish.
	suffix := ".pre-add-" + time.Now().UTC().Format("20060102T150405Z")
	restore := func(err error) error {
		if _, rerr := r.Shell("restore", restoreCmd(r, paths, existed, suffix)); rerr != nil {
			return failed(fmt.Errorf("%w\nputting back the files it replaced failed too (%v): each one it "+
				"replaced is kept beside it as <file>%s", err, rerr, suffix))
		}
		return failed(fmt.Errorf("%w\nthe host's previous identity files were put back; the admitted ones are "+
			"staged beside them for the rerun", err))
	}
	if _, err := r.Shell("install", installCmd(r, paths, suffix)); err != nil {
		return restore(fmt.Errorf("install the host identity: %w", err))
	}
	if _, err := r.Shell("binary", installCmd(r, []string{remoteBinary}, "")); err != nil {
		return restore(fmt.Errorf("install the litevirt binary: %w", err))
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := r.Run("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv"); err != nil {
		return restore(fmt.Errorf("symlink lv: %w", err))
	}
	if err := finishAdd(r, p, serial, admitted); err != nil {
		return restore(err)
	}
	// The copies of replaced keys go; the operator's config is kept as it was.
	var discard []string
	for _, path := range paths {
		if cfg != nil && path == cfg.path {
			fmt.Printf("  kept the config it edited, as it was, in %s (0600)\n", path+suffix)
			continue
		}
		discard = append(discard, path)
	}
	if _, err := r.Shell("discard", removeCmd(r, suffixed(discard, suffix))); err != nil {
		slog.Warn("could not remove the copies of the replaced identity files", "suffix", suffix, "error", err)
	}
	return addedLocally(p)
}

// remoteSerial is the serial of the certificate at path on the machine, ""
// when there is none.
func remoteSerial(r addRemote, path string) (string, error) {
	b, ok, err := r.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the host's %s before adding it: %w", filepath.Base(path), err)
	}
	if !ok {
		return "", nil
	}
	return installedSerial(b), nil
}

// liveHost is the listed (live) row of name, or nil.
func liveHost(hosts []*pb.Host, name string) *pb.Host {
	for _, h := range hosts {
		if h.GetName() == name {
			return h
		}
	}
	return nil
}

// refuseAnotherMember refuses a machine that is another live member: one
// that serves another host's current certificate, or whose address another
// host has. Adding it would replace that member's identity on disk. Removed
// hosts are not listed, so a re-add after `lv host rm` passes.
func refuseAnotherMember(hosts []*pb.Host, p hostAddPlan, installed string) error {
	for _, h := range hosts {
		if h.GetName() == p.hostName {
			continue
		}
		var why string
		switch {
		case installed != "" && strings.EqualFold(h.GetCertSerial(), installed):
			why = fmt.Sprintf("the host serves %s's current certificate (serial %s)", h.GetName(), installed)
		case h.GetAddress() == p.hostAddr:
			why = fmt.Sprintf("%s is a live member at that address", h.GetName())
		default:
			continue
		}
		return fmt.Errorf("refusing to add %s at %s: %s, and adding it would replace %s's identity on disk. "+
			"Nothing was pushed. To add this machine under another name, remove it first (`lv host rm %s`)",
			p.hostName, p.hostAddr, why, h.GetName(), h.GetName())
	}
	return nil
}

// mintStaged mints hostName's pair beside this machine's copy and returns
// its contents and serial. The paths are appended to local.
func mintStaged(pkiDir, hostName string, ip net.IP, local *[]string) ([2][]byte, string, error) {
	crt := filepath.Join(pkiDir, "."+hostName+".crt.add")
	key := filepath.Join(pkiDir, "."+hostName+".key.add")
	*local = append(*local, crt, key)
	var pair [2][]byte
	if err := pki.GenerateHostCert(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"), crt, key, hostName, ip); err != nil {
		return pair, "", fmt.Errorf("generate host cert: %w", err)
	}
	serial, err := pki.CertSerial(crt)
	if err != nil {
		return pair, "", fmt.Errorf("read generated host certificate serial: %w", err)
	}
	for i, f := range []string{crt, key} {
		if pair[i], err = os.ReadFile(f); err != nil {
			return pair, "", err
		}
	}
	return pair, strings.ToLower(serial), nil
}

// addOtherFiles is the rest of the key material an add installs: the cluster
// CA, the gossip key and the host's migration credentials (minted beside this
// machine's copy; paths appended to local).
func addOtherFiles(p hostAddPlan, ip net.IP, local *[]string) ([]addFile, error) {
	crt := filepath.Join(p.pkiDir, "."+p.hostName+"-migration.crt.add")
	key := filepath.Join(p.pkiDir, "."+p.hostName+"-migration.key.add")
	*local = append(*local, crt, key)
	mig, err := issueMigrationCredentialsAt(p.pkiDir, crt, key, p.hostName, net.ParseIP(p.hostAddr), p.migHolder)
	if err != nil {
		return nil, err
	}
	src := []migrationFile{{filepath.Join(p.pkiDir, "ca.crt"), filepath.Join(remotePKIDir, "ca.crt"), 0o644}}
	if p.gossipKeyPath != "" {
		// 0600 like host.key: whoever reads it speaks gossip.
		src = append(src, migrationFile{p.gossipKeyPath, filepath.Join(remotePKIDir, pki.GossipKeyName), 0o600})
	}
	src = append(src, mig...)
	files := make([]addFile, 0, len(src))
	for _, f := range src {
		b, err := os.ReadFile(f.local)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.local, err)
		}
		files = append(files, addFile{f.remote, b, f.mode})
	}
	return files, nil
}

func removeAll(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// keepLocal moves this machine's minted copies (".<name>.add") into place
// once admitted. A failure leaves the staged copy where it is: the admitted
// pair is also staged on the host, and the rerun takes it from there.
func keepLocal(local []string) {
	for _, s := range local {
		dir, base := filepath.Split(s)
		final := filepath.Join(dir, strings.TrimSuffix(strings.TrimPrefix(base, "."), ".add"))
		if err := os.Rename(s, final); err != nil {
			slog.Warn("could not keep this machine's copy of the admitted credentials", "path", s, "error", err)
		}
	}
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
	if err := r.RunWithInput(remoteAddSetupCommand(p.hostName, p.hostAddr, p.peersYAML, p.enforcement, p.configInstalled), []byte(p.setupScript)); err != nil {
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

func addStagedPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".add")
}

func stagedPaths(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = addStagedPath(p)
	}
	return out
}

func suffixed(paths []string, suffix string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = p + suffix
	}
	return out
}

// syncCmd flushes q (a file or directory) to disk. Its failure fails the
// command (set -e): there is no fallback to a global sync.
func syncCmd(q string) string { return fmt.Sprintf("sync -- %s; ", q) }

// existsCmd prints each of paths that exists, one per line.
func existsCmd(r addRemote, paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		q := ssh.ShellQuote(r.Path(p))
		fmt.Fprintf(&b, "if [ -e %s ]; then printf '%%s\\n' %s; fi; ", q, q)
	}
	return b.String()
}

// existsSet reads existsCmd's output back into paths.
func existsSet(r addRemote, paths []string, out []byte) map[string]bool {
	listed := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		listed[l] = true
	}
	got := map[string]bool{}
	for _, p := range paths {
		if listed[r.Path(p)] {
			got[p] = true
		}
	}
	return got
}

// installCmd moves each path's staged file into place, synced before and
// after the rename. With a suffix, every file it replaces is first copied to
// path+suffix: its content (a symlinked key is followed) at 0600.
func installCmd(r addRemote, paths []string, suffix string) string {
	var cmd strings.Builder
	cmd.WriteString("set -e; umask 077; ")
	if suffix != "" {
		for _, p := range paths {
			q, b := ssh.ShellQuote(r.Path(p)), ssh.ShellQuote(r.Path(p)+suffix)
			fmt.Fprintf(&cmd, "if [ -e %s ]; then rm -f -- %s; cp -L -- %s %s; chmod 600 %s; fi; ", q, b, q, b, b)
		}
	}
	dirs := map[string]bool{}
	for _, p := range paths {
		q, s := ssh.ShellQuote(r.Path(p)), ssh.ShellQuote(r.Path(addStagedPath(p)))
		cmd.WriteString(syncCmd(s))
		fmt.Fprintf(&cmd, "mv -fT -- %s %s; ", s, q)
		dirs[filepath.Dir(r.Path(p))] = true
	}
	for _, p := range paths {
		if d := filepath.Dir(r.Path(p)); dirs[d] {
			cmd.WriteString(syncCmd(ssh.ShellQuote(d)))
			delete(dirs, d)
		}
	}
	return cmd.String()
}

// restoreCmd undoes installCmd. A path whose staged file is still there was
// never replaced. Any other goes back to its staged path, so the admitted
// file stays on the host for a rerun, and its copy back into place; one with
// no copy did not exist.
func restoreCmd(r addRemote, paths []string, existed map[string]bool, suffix string) string {
	var cmd strings.Builder
	cmd.WriteString("rc=0; ")
	for _, p := range paths {
		q := ssh.ShellQuote(r.Path(p))
		s, b := ssh.ShellQuote(r.Path(addStagedPath(p))), ssh.ShellQuote(r.Path(p)+suffix)
		fmt.Fprintf(&cmd, "if [ -e %s ]; then rm -f -- %s || rc=1; else ", s, b)
		fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s || rc=1; fi; ", q, q, s)
		if existed[p] {
			fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s || rc=1; fi; ", b, b, q)
		}
		cmd.WriteString("fi; ")
	}
	cmd.WriteString("exit $rc")
	return cmd.String()
}

// removeCmd removes each of paths.
func removeCmd(r addRemote, paths []string) string {
	var cmd strings.Builder
	cmd.WriteString("rc=0; ")
	for _, p := range paths {
		fmt.Fprintf(&cmd, "rm -f -- %s || rc=1; ", ssh.ShellQuote(r.Path(p)))
	}
	cmd.WriteString("exit $rc")
	return cmd.String()
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

func (r *sshAddRemote) Path(path string) string { return path }

func (r *sshAddRemote) Unpath(path string) string { return path }

func (r *sshAddRemote) Shell(_, cmd string) ([]byte, error) { return r.sc.RunOutput(cmd) }

// LocalAddTarget is addRemote over a directory tree this process can reach (a
// test's): /etc/litevirt/pki maps to PKIDir and every other absolute path
// under Root. The file commands run here under sh; the others are recorded,
// not run.
type LocalAddTarget struct {
	Root, PKIDir string
	// Binary is the file pushed as the litevirt binary.
	Binary string
	// FailSetup is what running setup returns; FailWrite what writing a
	// path (as the host names it) returns.
	FailSetup error
	FailWrite map[string]error
	// Events are what reached the host, in order: "write <path>",
	// "run <cmd>" and "sh <kind>".
	Events []string
}

func (d *LocalAddTarget) Path(path string) string {
	if path == remotePKIDir || strings.HasPrefix(path, remotePKIDir+"/") {
		return filepath.Join(d.PKIDir, strings.TrimPrefix(path, remotePKIDir))
	}
	return filepath.Join(d.Root, path)
}

func (d *LocalAddTarget) Unpath(path string) string {
	if rel, err := filepath.Rel(d.PKIDir, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.Join(remotePKIDir, rel)
	}
	rel, err := filepath.Rel(d.Root, path)
	if err != nil {
		return path
	}
	return "/" + rel
}

func (d *LocalAddTarget) ReadFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(d.Path(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (d *LocalAddTarget) Run(cmd string) error {
	d.Events = append(d.Events, "run "+cmd)
	return nil
}

func (d *LocalAddTarget) RunWithInput(cmd string, _ []byte) error {
	d.Events = append(d.Events, "run "+cmd)
	if strings.HasSuffix(cmd, "bash -s") {
		return d.FailSetup
	}
	return nil
}

func (d *LocalAddTarget) WriteFile(path string, data []byte, mode os.FileMode) error {
	d.Events = append(d.Events, "write "+path)
	if err := d.FailWrite[path]; err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Path(path)), 0o755); err != nil {
		return err
	}
	return secretfile.Write(d.Path(path), data, mode)
}

func (d *LocalAddTarget) Shell(kind, cmd string) ([]byte, error) {
	d.Events = append(d.Events, "sh "+kind)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w", kind, err)
	}
	return out, nil
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

const remoteConfig = "/etc/litevirt/config.yaml"

// maxConfigRead is the most of a config.yaml the add reads (ReadFile over
// SSH stops there); a file that size or larger is refused, never truncated.
const maxConfigRead = 1 << 20

// addConfigPorts are the ports an add assumes: peers dial the host's gRPC on
// grpcPort (AdmitHost records it) and its gossip on gossipPort (join_peers).
var addConfigPorts = map[string]int{"grpc_port": 7443, "gossip_port": 7946}

// mergeAddConfig is the machine's existing config.yaml with the keys an add
// must set edited in place, line by line: host_name, advertise_address,
// join_peers, pki_dir (the directory the add installs the credentials to)
// and the enforcement block, which becomes the cluster's, or goes when the
// cluster has none (its flags must equal the peers'). Every other byte is
// kept. A key the file lacks is appended.
//
// It refuses what it cannot edit safely: more than one document, a mapping
// that is not in block style, a port the add would not reach the host on, or
// an edit that changes any other key's value (an alias into a replaced
// block, say).
func mergeAddConfig(existing []byte, p hostAddPlan) ([]byte, error) {
	before, err := configMapping(existing)
	if err != nil {
		return nil, err
	}
	for key, want := range addConfigPorts {
		if v, ok := before[key]; ok && fmt.Sprint(v) != strconv.Itoa(want) {
			return nil, fmt.Errorf("%s is %v: peers reach a host only on %d, so the host would be unreachable "+
				"(set %s: %d, or remove the key)", key, v, want, key, want)
		}
	}
	edits := []struct {
		key  string
		text string // "" deletes the key
	}{
		{"host_name", fmt.Sprintf("host_name: %q\n", p.hostName)},
		{"advertise_address", fmt.Sprintf("advertise_address: %q\n", p.hostAddr)},
		{"join_peers", "join_peers: " + strings.TrimSpace(p.peersYAML) + "\n"},
		{"pki_dir", "pki_dir: " + remotePKIDir + "\n"},
		{"enforcement", strings.TrimRight(p.enforcement, "\n") + "\n"},
	}
	if strings.TrimSpace(p.enforcement) == "" {
		edits[len(edits)-1].text = ""
	}
	lines := strings.SplitAfter(string(existing), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if n := len(lines); n > 0 && !strings.HasSuffix(lines[n-1], "\n") {
		lines[n-1] += "\n"
	}
	for _, e := range edits {
		start, end, found := topLevelKeySpan(lines, e.key)
		switch {
		case found:
			repl := []string{}
			if e.text != "" {
				repl = []string{e.text}
			}
			lines = append(lines[:start], append(repl, lines[end:]...)...)
		case e.text != "":
			lines = append(lines, e.text)
		}
	}
	merged := []byte(strings.Join(lines, ""))

	// Every key the add does not set must decode exactly as before, and the
	// keys it sets as it set them.
	after, err := configMapping(merged)
	if err != nil {
		return nil, fmt.Errorf("the edited file does not parse (%v)", err)
	}
	want, err := configMapping([]byte(strings.Join([]string{edits[0].text, edits[1].text, edits[2].text,
		edits[3].text, edits[4].text}, "")))
	if err != nil {
		return nil, fmt.Errorf("the keys to set: %w", err)
	}
	set := map[string]bool{}
	for _, e := range edits {
		set[e.key] = true
	}
	for k, v := range before {
		if !set[k] && !reflect.DeepEqual(after[k], v) {
			return nil, fmt.Errorf("editing it would change %s", k)
		}
	}
	for k := range set {
		if !reflect.DeepEqual(after[k], want[k]) {
			return nil, fmt.Errorf("%s did not come out as set", k)
		}
	}
	if len(after) != len(before)+countMissing(before, want) {
		return nil, fmt.Errorf("editing it would add or drop a key")
	}
	return merged, nil
}

// countMissing is how many keys of want before lacks, minus the keys before
// has that the merge removes (want lacks them and they are set keys): the
// change in key count a correct merge makes.
func countMissing(before, want map[string]interface{}) int {
	n := 0
	for k := range want {
		if _, ok := before[k]; !ok {
			n++
		}
	}
	if _, ok := before["enforcement"]; ok {
		if _, ok := want["enforcement"]; !ok {
			n--
		}
	}
	return n
}

// configMapping decodes a config that is one block-style YAML mapping.
func configMapping(b []byte) (map[string]interface{}, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("it holds more than one YAML document")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode || doc.Content[0].Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("it is not a block-style YAML mapping")
	}
	m := map[string]interface{}{}
	if err := doc.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// topLevelKeySpan finds key's lines among lines: its own line at column 0,
// and every line after it that is indented, or blank before more indented
// ones. end is one past the last.
func topLevelKeySpan(lines []string, key string) (start, end int, found bool) {
	for i, l := range lines {
		rest, ok := strings.CutPrefix(l, key)
		if !ok || !strings.HasPrefix(strings.TrimLeft(rest, " \t"), ":") {
			continue
		}
		end = i + 1
		for j := i + 1; j < len(lines); j++ {
			t := lines[j]
			if strings.TrimSpace(t) == "" {
				continue
			}
			if t[0] != ' ' && t[0] != '\t' {
				break
			}
			end = j + 1
		}
		return i, end, true
	}
	return 0, 0, false
}

// hostConfig is the host's config.yaml with the add's keys edited in, as a
// file to install at the path it resolves to (a symlinked config stays a
// symlink) and at its own mode; nil when the host has none.
func hostConfig(r addRemote, p hostAddPlan) (*addFile, error) {
	q := ssh.ShellQuote(r.Path(remoteConfig))
	out, err := r.Shell("config", fmt.Sprintf("if [ -e %s ]; then readlink -f -- %s; stat -L -c %%a -- %s; fi", q, q, q))
	if err != nil {
		return nil, fmt.Errorf("read the host's %s: %w", remoteConfig, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return nil, nil
	}
	refuse := func(why error) error {
		return fmt.Errorf("refusing to add %s: its %s could not be kept (%v), and the add would drop the settings "+
			"in it. Fix the file, or move it aside to have the add write a new one", p.hostName, remoteConfig, why)
	}
	if len(fields) != 2 {
		return nil, refuse(fmt.Errorf("unexpected stat output %q", out))
	}
	mode, err := strconv.ParseUint(fields[1], 8, 32)
	if err != nil {
		return nil, refuse(err)
	}
	path := r.Unpath(fields[0])
	cur, ok, err := r.ReadFile(path)
	if err != nil || !ok {
		return nil, fmt.Errorf("read the host's %s (%s): %v", remoteConfig, path, err)
	}
	if len(cur) >= maxConfigRead {
		return nil, refuse(fmt.Errorf("it is 1 MiB or larger, more than the add reads"))
	}
	merged, err := mergeAddConfig(cur, p)
	if err != nil {
		return nil, refuse(err)
	}
	return &addFile{path, merged, os.FileMode(mode)}, nil
}
