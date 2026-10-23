package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/secretfile"
	"github.com/litevirt/litevirt/internal/ssh"
	"gopkg.in/yaml.v3"
)

// HostAdd adds a new host to an existing cluster.
func HostAdd(ctx context.Context, c pb.LiteVirtClient, sshTarget string, hostName string, joinPeers []string) error {
	// The name becomes <pkiDir>/<name>.crt|.key beside the CA: checked first.
	// Whether it is new (the full rule) is decided from the cluster's hosts
	// below, before anything is minted here or any machine is dialled; a list
	// that cannot be read refuses the add.
	if err := pki.ValidateExistingHostName(hostName); err != nil {
		return err
	}
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
	hostsResp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list the cluster's hosts before adding %s: %w", hostName, err)
	}
	if err := checkAddName(hostsResp.GetHosts(), hostName); err != nil {
		return err
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
	rt, err := ssh.Resolve(sshTarget) // the ssh config's HostName, as the dial uses
	if err != nil {
		return err
	}
	parsedHost = rt.Host()
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

	sc, err := ssh.NewClientResolved(rt)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	return hostAddTo(ctx, c, &sshAddRemote{sshRemotePKI{sc: sc}}, hostAddPlan{
		pkiDir: pkiDir, hostName: hostName, hostAddr: hostAddr, peersYAML: peersYAML,
		enforcement: enforcement, gossipKeyPath: gossipKeyPath, migHolder: migHolder,
		binPath: binPath, setupScript: setupScript,
		rerun: addRerunCmd(hostName, sshTarget),
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
//
// The staged paths are the attempt's own: tagged with the serial of the
// certificate it asks the cluster to admit and a nonce of the attempt's
// (addStagedPath, <serial>-<nonce>). Two adds of one machine at once, from
// two operators, and a rerun while the admitted add is still running, never
// write, install or remove each other's files: a rerun stages its own copy
// of the admitted pair, and an attempt that fails or is refused removes, and
// rolls back, only files that carry its nonce. `lv host rm` removes every
// attempt's of the serial it revoked.
func hostAddTo(ctx context.Context, c pb.LiteVirtClient, r addRemote, p hostAddPlan) error {
	if err := pki.ValidateExistingHostName(p.hostName); err != nil {
		return err
	}
	// The commands an add prints to undo its admission name the host: a name
	// `lv host rm --serial` would refuse is refused here, before anything.
	if !settleName(p.hostName) {
		return fmt.Errorf("%s is not a host name: it must be printable, at most %d bytes, and not begin with '-'; "+
			"nothing was changed", strconv.Quote(p.hostName), safename.MaxNameLen)
	}
	ip := net.ParseIP(p.hostAddr)
	hostCrt, hostKey := filepath.Join(remotePKIDir, "host.crt"), filepath.Join(remotePKIDir, "host.key")

	hostsResp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return fmt.Errorf("list the cluster's hosts before adding %s: %w", p.hostName, err)
	}
	hosts := hostsResp.GetHosts()
	if err := checkAddName(hosts, p.hostName); err != nil {
		return err
	}
	installedPEM, installed, err := remoteCert(r, hostCrt)
	if err != nil {
		return err
	}
	if err := refuseAnotherMember(hosts, p, installed); err != nil {
		return err
	}

	nonce, err := attemptNonce()
	if err != nil {
		return err
	}
	var files []addFile
	// What this attempt may replace: what it finds, for a new admission. A
	// retry of an admission keeps what that admission's first attempt found
	// (recordedExpect), never what the retry finds.
	exp := addExpect{known: true, serial: installed}
	// An earlier add of this machine under this name: finish it with the
	// certificate it was admitted with, which the machine holds installed
	// or staged, or say that it already finished.
	serial, pairOnMachine, legacyPair := "", false, false
	var admittedCrt []byte // the staged certificate of the admission this add finishes
	if row := liveHost(hosts, p.hostName); row != nil && row.GetAddress() == p.hostAddr {
		admittedSerial := canonSerial(row.GetCertSerial())
		joining := row.GetState() == pb.HostState_HOST_JOINING
		if installed == admittedSerial && !joining {
			fmt.Printf("Host %s is already a member at %s and serves the certificate it was admitted with; nothing to do\n",
				p.hostName, p.hostAddr)
			return addedLocally(p)
		}
		if joining {
			if !validAttemptTag(admittedSerial) {
				return fmt.Errorf("%s is admitted (joining) with certificate serial %q, which is not a serial. Undo "+
					"the admission with `lv host rm %s`, then run `%s` again", p.hostName, row.GetCertSerial(), shellWord(p.hostName), p.rerun)
			}
			pair, where, err := admittedPairOnMachine(r, admittedSerial, installed == admittedSerial)
			if err != nil {
				return fmt.Errorf("the key %s holds beside its admitted certificate %s does not match it (%v), so "+
					"its daemon could not load the pair. Undo the admission with `%s`, then run `%s` again",
					p.hostName, admittedSerial, err, settleCmd(p, admittedSerial), p.rerun)
			}
			if where == pairAbsent {
				if installed != "" {
					return settled(fmt.Sprintf("%s is admitted (joining) with certificate %s, which the host holds neither "+
						"installed nor staged; it serves certificate %s, which is not that admission's, so this add changes "+
						"nothing. `%s` undoes the admission and leaves %s in place",
						p.hostName, admittedSerial, installed, settleCmd(p, admittedSerial), installed))
				}
				return fmt.Errorf("%s is admitted (joining) with certificate %s, which the host holds neither installed "+
					"nor staged. Undo the admission with `%s`, then run `%s` again",
					p.hostName, admittedSerial, settleCmd(p, admittedSerial), p.rerun)
			}
			if exp, err = recordedExpect(r, admittedSerial); err != nil {
				return err
			}
			serial, pairOnMachine = admittedSerial, true
			if where != pairInstalled {
				// Staged by the earlier attempt (or an earlier release's add,
				// untagged): this attempt stages a copy of its own, and leaves
				// the earlier attempt's files to it.
				files = append(files, addFile{hostCrt, pair[0], 0o644}, addFile{hostKey, pair[1], 0o600})
				legacyPair = where == pairStagedLegacy
				admittedCrt = pair[0]
			}
		}
	}
	// Another cluster's state on the machine (one that founded its own with
	// `lv host init --local`) is never merged into this one. A staged pair of
	// this cluster's joining admission proves an add that failed after it
	// (its daemon may have started) is this cluster's to finish.
	ca, err := localCA(p.pkiDir)
	if err != nil {
		return fmt.Errorf("read the cluster CA: %w", err)
	}
	if err := refuseForeignState(r, ca, admittedCrt, p.hostName+" at "+p.hostAddr, "add"); err != nil {
		return err
	}
	// Checked again right before the install (refuseSecondInstall); here,
	// so that a machine this add may not install on gets no admission and
	// no staged file of it.
	if err := refuseUnproven(r, p, serial, exp, installedPEM, installed); err != nil {
		return err
	}
	// Over a certificate this cluster revoked, the record of an attempt no
	// listed row was admitted with (its add died before the admission, and
	// could not unstage) protects nothing: it goes.
	if installed != "" && revokedHere(p.pkiDir, installedPEM) {
		removeOrphanRecords(r, hosts, serial)
	}

	// This machine's copies of what the add mints: in a private directory of
	// the attempt's, never at a path derived from the host's name.
	minted, err := os.MkdirTemp(p.pkiDir, ".add-")
	if err != nil {
		return fmt.Errorf("create a directory to mint %s's credentials in: %w", p.hostName, err)
	}
	defer os.RemoveAll(minted)
	if !pairOnMachine {
		pair, s, err := mintStaged(p.pkiDir, minted, p.hostName, ip)
		if err != nil {
			return err
		}
		serial = s
		files = append(files, addFile{hostCrt, pair[0], 0o644}, addFile{hostKey, pair[1], 0o600})
	}
	rest, err := addOtherFiles(p, minted, ip)
	if err != nil {
		return err
	}
	files = append(files, rest...)
	tag := serial + "-" + nonce
	fmt.Printf("  attempt %s: staging as .<file>.add-%s\n", nonce, tag)
	// A machine that already has a config (a re-added one) keeps it: the
	// keys the add must set are edited in, and setup leaves the file alone.
	cfg, err := hostConfig(r, p)
	if err != nil {
		return err
	}
	if cfg != nil {
		files = append(files, *cfg)
		p.configInstalled = true
	}
	bin, err := os.ReadFile(p.binPath)
	if err != nil {
		return fmt.Errorf("read the litevirt binary: %w", err)
	}

	// Upload everything to its staged path. Nothing it replaces yet.
	var wrote []string
	record := addRecordPath(tag)
	unstage := func() {
		if _, err := r.Shell("unstage", removeCmd(r, append(stagedPaths(wrote, tag), record))); err != nil {
			slog.Warn("could not remove the files staged on the host", "error", err)
		}
	}
	if _, err := r.Shell("mkdir", remotePKIDirsCmd(r.Path(etcLitevirtRemote), r.Path(remotePKIDir), r.Path(remoteMigrationDir))); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}
	// The attempt's record of what the machine served before the admission,
	// staged before its pair, so a retry of the admission finds it beside the
	// pair it reuses. Unknown (an earlier release staged the pair without
	// one) is recorded as nothing.
	if exp.known {
		if err := r.WriteFile(record, []byte(addRecordLine(p.hostName, exp.serial)), 0o600); err != nil {
			unstage()
			return fmt.Errorf("record what the host serves before adding it (nothing was admitted or installed): %w", err)
		}
	}
	for _, f := range append(files, addFile{remoteBinary, bin, 0o755}) {
		if f.data == nil {
			continue
		}
		wrote = append(wrote, f.path)
		if err := r.WriteFile(addStagedPath(f.path, tag), f.data, f.mode); err != nil {
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
	keepLocal(minted, p.pkiDir, p.hostName)
	failed := func(err error) error {
		// A refusal over a machine state nothing proves is this add's names
		// its own settling command, and no rerun.
		var s *settleError
		if errors.As(err, &s) {
			return err
		}
		return fmt.Errorf("%w\n%s is admitted to the cluster (joining) with certificate %s and counts as a voter "+
			"until it starts. Run `%s` to finish the add, or `%s` to undo the admission",
			err, p.hostName, serial, p.rerun, settleCmd(p, serial))
	}
	// The pair it installs is the admitted one: its own attempt's, checked
	// again now that the cluster has answered.
	if installed != serial {
		if err := stagedPairIs(r, serial, tag); err != nil {
			return failed(fmt.Errorf("the pair staged for certificate %s is not that certificate and its key (%v); "+
				"nothing was installed", serial, err))
		}
	}

	// From here to the end (install, setup, rollback) the machine is this
	// attempt's: it claims it in the machine's install record
	// (addInstalledMarker), and every command it then runs there checks,
	// under the add lock and in the process that holds it, that the record is
	// still its claim (machineClaim.cmd). A command of this attempt that runs
	// late (its connection lost) after another add has claimed the machine
	// does nothing.
	//
	// Of two adds of this machine, the second to get here installs nothing,
	// whatever its admission's stamp: the machine says another add installed
	// since this one began, holds the machine, or installed another name.
	prior, err := refuseSecondInstall(r, p, serial, exp, nonce)
	if err != nil {
		return failed(err)
	}
	// And the cluster is asked again, after a fresh pull, right before the
	// install: a host active at this address, or an earlier admission there
	// that has reached it since, keeps the address (AdmitHost is idempotent).
	if _, err := c.AdmitHost(admitCtx, &pb.AdmitHostRequest{Name: p.hostName, Address: p.hostAddr, CertSerial: serial}); err != nil {
		return failed(fmt.Errorf("the cluster refused the admission when asked again before installing (nothing was "+
			"installed): %w", err))
	}
	claimedAt := time.Now().Unix()
	m := machineClaim{r: r, mine: markerLine(p.hostName, serial, claimedAt, nonce, "installing"), settle: settleClaimPath(serial)}
	if err := m.take(prior); err != nil {
		if serr := refuseSettling(r, p, serial); serr != nil {
			return serr
		}
		return failed(fmt.Errorf("%w; nothing was installed", err))
	}

	// A machine re-added while its old daemon still runs would serve the
	// admitted identity from that stale process until setup restarts it.
	if err := r.Run(m.cmd("systemctl stop litevirt 2>/dev/null || true")); err != nil {
		return failed(fmt.Errorf("stop the host's daemon before installing: %w", err))
	}
	paths := make([]string, len(files))
	ours := map[string]string{} // what this attempt installs at each path, by hash
	for i, f := range files {
		paths[i] = f.path
		sum := sha256.Sum256(f.data)
		ours[f.path] = hex.EncodeToString(sum[:])
	}
	existedOut, err := r.Shell("exists", existsCmd(r, paths))
	if err != nil {
		return failed(fmt.Errorf("check which identity files the host already has: %w", err))
	}
	existed := existsSet(r, paths, existedOut)
	// Nothing the machine holds is overwritten without a copy, and the copies
	// go back if the add does not finish.
	suffix := ".pre-add-" + time.Now().UTC().Format("20060102T150405Z") + "-" + nonce
	restore := func(err error) error {
		// Only this attempt's install is undone, and only while the machine
		// still records its claim: checked by the rollback command itself.
		_, rerr := r.Shell("restore", m.cmd(restoreCmd(r, paths, existed, ours, suffix, tag)))
		switch {
		case exitStatus(rerr) == notOurMachine:
			return failed(fmt.Errorf("%w\nnothing was put back: the machine no longer records this attempt's claim "+
				"(%s), so the files there may be another add's; each replaced file's copy is kept beside it as "+
				"<file>%s", err, addInstalledMarker, suffix))
		case rerr != nil:
			return failed(fmt.Errorf("%w\nputting back the files it replaced failed too (%v): a file whose copy "+
				"was not moved back is kept beside it as <file>%s, and one that was may be at 0600 rather than "+
				"its own mode", err, rerr, suffix))
		}
		if err := m.give(prior); err != nil {
			slog.Warn("could not put back the machine's install record", "record", addInstalledMarker, "error", err)
		}
		return failed(fmt.Errorf("%w\nthe host's previous identity files were put back; the admitted ones are "+
			"staged beside them for the rerun", err))
	}
	if _, err := r.Shell("install", m.cmd(installCmd(r, paths, suffix, tag))); err != nil {
		return restore(fmt.Errorf("install the host identity: %w", err))
	}
	if _, err := r.Shell("binary", m.cmd(installCmd(r, []string{remoteBinary}, "", tag))); err != nil {
		return restore(fmt.Errorf("install the litevirt binary: %w", err))
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := r.Run(m.cmd("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv")); err != nil {
		return restore(fmt.Errorf("symlink lv: %w", err))
	}
	if err := finishAdd(r, p, serial, tag, admitted, m.cmd); err != nil {
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
	if _, err := r.Shell("discard", m.cmd(removeCmd(r, append(suffixed(discard, suffix), record)))); err != nil {
		slog.Warn("could not remove the copies of the replaced identity files", "suffix", suffix, "error", err)
	}
	if err := m.give(markerLine(p.hostName, serial, claimedAt, nonce, "installed")); err != nil {
		slog.Warn("could not record the finished install on the host", "record", addInstalledMarker, "error", err)
	}
	if legacyPair {
		if err := removeLegacyStagedPair(r, serial); err != nil {
			slog.Warn("could not remove the pair an earlier release's add left staged", "error", err)
		}
	}
	return addedLocally(p)
}

// remoteCert is the certificate at path on the machine and its serial, ""
// when there is none.
func remoteCert(r addRemote, path string) ([]byte, string, error) {
	b, ok, err := r.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read the host's %s before adding it: %w", filepath.Base(path), err)
	}
	if !ok {
		return nil, "", nil
	}
	return b, installedSerial(b), nil
}

// addExpect is what an add may find installed on the machine and replace:
// the certificate serial ("" for none) the admission's first attempt found
// there. known is false when no attempt recorded it (an earlier release's
// staged add); recorded says it is that first attempt's record, not this
// attempt's own finding.
type addExpect struct {
	known, recorded bool
	serial          string
}

// addRecordPath is where the attempt tag records what the machine served
// before it: beside its staged certificate, so `lv host rm` removes it with
// the serial's staged files.
func addRecordPath(tag string) string {
	return addStagedPath(filepath.Join(remotePKIDir, "host.crt"), tag) + ".before"
}

// addRecordLine is an attempt record: the name it adds, and the serial the
// machine served before it ("-" for none).
func addRecordLine(name, before string) string {
	if before == "" {
		before = "-"
	}
	return encodeName(name) + " " + before + "\n"
}

// encodeName is name as the first field of an install record or attempt
// record: as it is when it holds no blank, quote or control character
// (byte-identical to an earlier release's record), otherwise strconv.Quote'd.
func encodeName(name string) string {
	if name != "" && !strings.ContainsAny(name, " \t\r\n\v\f\"") && printableName(name) {
		return name
	}
	return strconv.Quote(name)
}

// splitName takes the name off the front of a record line: a quoted one
// (encodeName), or the first field. ok is false for a quote that does not
// parse.
func splitName(line string) (name, rest string, ok bool) {
	line = strings.TrimLeft(line, " \t")
	if strings.HasPrefix(line, "\"") {
		q, err := strconv.QuotedPrefix(line)
		if err != nil {
			return "", "", false
		}
		name, err = strconv.Unquote(q)
		return name, line[len(q):], err == nil
	}
	if i := strings.IndexAny(line, " \t\n"); i >= 0 {
		return line[:i], line[i:], true
	}
	return line, "", true
}

// markerLine is an install record: name (encodeName), serial, unix time,
// nonce and state.
func markerLine(name, serial string, at int64, nonce, state string) string {
	return fmt.Sprintf("%s %s %d %s %s", encodeName(name), serial, at, nonce, state)
}

// markerFields splits an install record into name, serial, time, and the
// nonce and state when it has them, as strings.Fields does a record whose
// name is one plain word. The name may be quoted (encodeName); an earlier
// release wrote a name with blanks as it is, and its fields after the name
// are then counted from the right: serial and time, then a nonce, then a
// state. nil for a record that does not parse.
func markerFields(line string) []string {
	line = strings.TrimRight(line, "\n")
	if strings.HasPrefix(strings.TrimLeft(line, " \t"), "\"") {
		name, rest, ok := splitName(line)
		if !ok {
			return nil
		}
		return append([]string{name}, strings.Fields(rest)...)
	}
	f := strings.Fields(line)
	tail := 2 // serial, time
	switch n := len(f); {
	case n >= 5 && (f[n-1] == "installing" || f[n-1] == "installed"):
		tail = 4
	case n >= 4 && validAttemptTag(f[n-1]) && isDigits(f[n-2]) && canonSerial(f[n-3]) != "":
		tail = 3
	}
	if len(f) < tail+1 {
		return f
	}
	name := strings.Join(f[:len(f)-tail], " ")
	return append([]string{name}, f[len(f)-tail:]...)
}

// recordFields splits an attempt record into its name and before-serial.
func recordFields(line string) []string {
	name, rest, ok := splitName(strings.TrimRight(line, "\n"))
	if !ok {
		return nil
	}
	return append([]string{name}, strings.Fields(rest)...)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// printableName reports whether name, read from a machine, may be printed
// in prose: no control characters, and no longer than a name the CLI takes.
func printableName(name string) bool {
	if name == "" || len(name) > safename.MaxNameLen || !utf8.ValidString(name) {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) || !unicode.IsPrint(c) && c != ' ' {
			return false
		}
	}
	return true
}

// addRecord is one attempt record found on the machine. A record whose
// content does not parse (bad is set) carries only its tag: its name and
// serial come from the machine, and are never printed or used.
type addRecord struct {
	tag, name, serial, before string
	bad                       bool
}

// addRecords lists every attempt record on the machine; with serial, only
// that admission's. The serial and nonce come from the file's name and are
// checked as hex; the name and the before-serial from its content, checked
// as a host name and a serial, or the record is bad.
func addRecords(r addRemote, serial string) ([]addRecord, error) {
	crt := filepath.Join(remotePKIDir, "host.crt")
	prefix := addStagedPath(crt, "")
	glob := prefix + serial
	if serial != "" {
		glob += "-"
	}
	out, err := r.Shell("records", fmt.Sprintf("for f in %s*.before; do [ -e \"$f\" ] && printf '%%s\\n' \"$f\"; done; true",
		ssh.ShellQuote(r.Path(glob))))
	if err != nil {
		return nil, fmt.Errorf("list the add records on the host: %w", err)
	}
	var recs []addRecord
	for _, l := range strings.Split(string(out), "\n") {
		if l == "" {
			continue
		}
		tag, ok := strings.CutPrefix(r.Unpath(l), prefix)
		if !ok {
			continue
		}
		tag = strings.TrimSuffix(tag, ".before")
		s, n, ok := strings.Cut(tag, "-")
		if !ok || !validAttemptTag(s) || !validAttemptTag(n) || canonSerial(s) != s || (serial != "" && s != serial) {
			continue
		}
		rec := addRecord{tag: tag, serial: s}
		b, ok, err := r.ReadFile(addRecordPath(tag))
		if err != nil {
			return nil, err
		}
		f := recordFields(string(b))
		switch {
		case !ok || len(f) != 2 || !printableName(f[0]):
			rec.bad = true
		case f[1] == "-":
			rec.name = f[0]
		case canonSerial(f[1]) != "":
			rec.name, rec.before = f[0], canonSerial(f[1])
		default:
			rec.bad = true
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// recordedExpect is what the first attempt of the admission serial found on
// the machine, from the records its attempts staged: unknown when there is
// none, or when one does not parse or they disagree.
func recordedExpect(r addRemote, serial string) (addExpect, error) {
	recs, err := addRecords(r, serial)
	if err != nil || len(recs) == 0 {
		return addExpect{}, err
	}
	for _, rec := range recs {
		if rec.bad || rec.before != recs[0].before {
			return addExpect{}, nil
		}
	}
	return addExpect{known: true, recorded: true, serial: recs[0].before}, nil
}

// removeOrphanRecords removes the attempt records of serials that no row in
// hosts holds and that are not serial: attempts that were never admitted.
func removeOrphanRecords(r addRemote, hosts []*pb.Host, serial string) {
	recs, err := addRecords(r, "")
	if err != nil {
		slog.Warn("could not list the add records on the host", "error", err)
		return
	}
	held := map[string]bool{serial: true}
	for _, h := range hosts {
		held[canonSerial(h.GetCertSerial())] = true
	}
	var gone []string
	for _, rec := range recs {
		if !held[rec.serial] {
			gone = append(gone, addRecordPath(rec.tag))
		}
	}
	if len(gone) == 0 {
		return
	}
	if _, err := r.Shell("unstage", removeCmd(r, gone)); err != nil {
		slog.Warn("could not remove the records of attempts that were never admitted", "error", err)
	}
}

// canonSerial is pki.CanonicalSerial's form of serial, "" when it is not one.
func canonSerial(serial string) string {
	c, err := pki.CanonicalSerial(serial)
	if err != nil {
		return ""
	}
	return c
}

// echoableName reports whether name, read from a machine, may be echoed in a
// command the operator is told to run: one `lv host rm` takes (settleName),
// and every byte printable ASCII (0x20-0x7E), so no control, bidi override,
// zero-width or look-alike character makes the command shown differ from
// the one that runs.
func echoableName(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return false
		}
	}
	return settleName(name)
}

// validHostName reports whether name is a host name the CLI accepts in a command
// it prints: letters, digits, '_', '.', '-', not leading '-'.
func validHostName(name string) bool {
	return safename.ValidateName(name) == nil && !strings.HasPrefix(name, "-")
}

// shellWord is s as one shell word: as it is when it is a plain host name or
// serial, otherwise single-quoted.
func shellWord(s string) string {
	if validHostName(s) {
		return s
	}
	return ssh.ShellQuote(s)
}

// revokedHere reports whether certificate (PEM) was issued by the cluster CA
// in pkiDir and is revoked in its CRL: a host `lv host rm` removed. Another
// CA's certificate of the same serial is not.
func revokedHere(pkiDir string, certPEM []byte) bool {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return false
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return false
	}
	cblk, _ := pem.Decode(caPEM)
	if cblk == nil {
		return false
	}
	ca, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil || cert.CheckSignatureFrom(ca) != nil {
		return false
	}
	return pki.IsCertRevoked(pkiDir, cert.SerialNumber)
}

// serialRevokedHere reports whether the cluster CA's CRL in pkiDir revokes
// serial (hex): the admission of that serial was removed.
func serialRevokedHere(pkiDir, serial string) bool {
	sn, ok := new(big.Int).SetString(serial, 16)
	return ok && pki.IsCertRevoked(pkiDir, sn)
}

// settleError is a refusal over a machine state that nothing proves is this
// add's. Its message names the one command that settles it, and no rerun.
type settleError struct{ msg string }

func (e *settleError) Error() string { return e.msg }

func settled(msg string) error { return &settleError{msg} }

// addRerunCmd is `lv host add --name <host> <target>`, each word shell-safe:
// the command that finishes an add that failed after its admission.
func addRerunCmd(hostName, target string) string {
	return fmt.Sprintf("lv host add --name %s %s", shellWord(hostName), shellWord(target))
}

// settleCmd is the command that undoes the admission of serial for p, and
// only that admission: the row of p's name if it holds that certificate,
// otherwise no row (its staged files on the machine and its revocation).
func settleCmd(p hostAddPlan, serial string) string {
	return fmt.Sprintf("lv host rm %s --serial %s --address %s", shellWord(p.hostName), shellWord(serial), shellWord(p.hostAddr))
}

// refuseUnproven refuses an add that would replace what nothing proves it
// may: the machine's certificate now (nowPEM, serial now) must be the
// admission's own (serial), what exp says the admission's first attempt
// found, nothing when that is unknown, or a certificate this cluster
// revoked. Nor may another add's attempt record on the machine stand
// unsettled over a certificate it did not find: the machine changed after
// an add that neither finished nor was undone.
func refuseUnproven(r addRemote, p hostAddPlan, serial string, exp addExpect, nowPEM []byte, now string) error {
	if err := refuseSettling(r, p, serial); err != nil {
		return err
	}
	ok := (serial != "" && now == serial) || (exp.known && now == exp.serial) || (!exp.known && now == "") ||
		(now != "" && revokedHere(p.pkiDir, nowPEM))
	if !ok {
		found := "no certificate"
		if exp.serial != "" {
			found = "certificate " + exp.serial
		}
		var what string
		switch {
		case !exp.recorded && exp.known:
			// This attempt's own finding, at its start.
			return settled(fmt.Sprintf("the machine's certificate changed since this add began (it serves %s now, "+
				"not %s): another add installed on it first, and this one installs nothing. `%s` undoes this add's "+
				"admission and leaves %s in place", now, found, settleCmd(p, serial), now))
		case exp.known:
			what = fmt.Sprintf("its first attempt found %s there", found)
		default:
			what = "an earlier release's add staged it without recording what the machine served"
		}
		return settled(fmt.Sprintf("%s is admitted with certificate %s, and %s; the machine serves certificate %s "+
			"now, which nothing proves is this admission's or revoked by this cluster, so this add stops nothing and "+
			"installs nothing. `%s` undoes the admission and leaves %s in place",
			p.hostName, serial, what, now, settleCmd(p, serial), now))
	}
	// Nothing installed, the admission's own, or proven decommissioned:
	// no other attempt's record protects it.
	if now == "" || now == serial || revokedHere(p.pkiDir, nowPEM) {
		return nil
	}
	recs, err := addRecords(r, "")
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.serial == serial || rec.serial == now || serialRevokedHere(p.pkiDir, rec.serial) {
			continue
		}
		if rec.bad {
			// Its content came from the machine and is not printed.
			return settled(fmt.Sprintf("the machine holds an add record that does not parse (%s), so what an earlier "+
				"add found there is unknown and the certificate it serves now (%s) is not proven this add's to replace; "+
				"this add changes nothing. Check that file on the machine",
				addRecordPath(rec.tag), now))
		}
		if rec.before == now {
			continue
		}
		found := "no certificate"
		if rec.before != "" {
			found = "certificate " + rec.before
		}
		if !echoableName(rec.name) {
			// A name `lv host rm` would not take, or one a terminal may show
			// as other than it is, is not printed, nor a command with it. One
			// it takes is printed quoted (shellWord).
			return settled(fmt.Sprintf("an earlier add of this machine (certificate %s, attempt %s) found %s here and "+
				"was neither finished nor undone; the machine serves certificate %s now, which nothing proves is that "+
				"add's, so this add changes nothing. Its record %s names a host the CLI cannot name in a command: check it "+
				"on the machine", rec.serial, rec.tag, found, now, addRecordPath(rec.tag)))
		}
		other := hostAddPlan{hostName: rec.name, hostAddr: p.hostAddr}
		return settled(fmt.Sprintf("an earlier add of this machine as %s (certificate %s, attempt %s) found %s here "+
			"and was neither finished nor undone; the machine serves certificate %s now, which nothing proves is that "+
			"add's, so this add changes nothing. `%s` settles that add and leaves %s in place",
			rec.name, rec.serial, rec.tag, found, now, settleCmd(other, rec.serial), now))
	}
	return nil
}

// refuseSettling refuses an add of the admission serial while a settle of it
// (`lv host rm --serial`) has claimed the machine (settleClaimPath): it
// revokes that admission, and is finished by its own command.
func refuseSettling(r addRemote, p hostAddPlan, serial string) error {
	if serial == "" {
		return nil
	}
	_, ok, err := r.ReadFile(settleClaimPath(serial))
	if err != nil || !ok {
		return err
	}
	return settled(fmt.Sprintf("`lv host rm --serial %s` claimed this machine to undo the admission of certificate %s "+
		"(%s) and has not finished, so this add installs nothing. `%s` finishes it", serial, serial,
		settleClaimPath(serial), settleCmd(p, serial)))
}

// liveHost is the listed (live) row of name, or nil.
// checkAddName applies the new-name rule to a name no live host holds; a live
// row (an add being resumed, or one already finished) keeps the name an older
// build admitted. A removed name is not listed, so re-adding it is a new name.
// An add keeps this machine's copies under hosts/<name>/ (keptHostDir), so no
// name's pair, migration pair included, can be another host's.
func checkAddName(hosts []*pb.Host, name string) error {
	if liveHost(hosts, name) == nil {
		if err := pki.ValidateHostName(name); err != nil {
			return err
		}
	}
	return nil
}

// migrationPairCollision is the refusal for host name whose migration pair,
// <pkiDir>/<name>-migration.crt|.key, is the file host other's own pair is
// kept in.
func migrationPairCollision(pkiDir, name, other string) error {
	crt := filepath.Join(pkiDir, name+"-migration.crt")
	return fmt.Errorf("host %s's migration pair would be written to %s and %s, which hold host %s's own "+
		"certificate and key: the two names collide in this machine's PKI directory. Rename one of the "+
		"two hosts: remove it (`lv host rm %s`) and add it again under another name (`lv host add --name`)",
		name, crt, strings.TrimSuffix(crt, ".crt")+".key", other, other)
}

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
		case installed != "" && canonSerial(h.GetCertSerial()) == installed:
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

// mintStaged mints hostName's pair, with the CA in pkiDir, into the
// attempt's directory minted (as host.crt and host.key, whatever the name)
// and returns its contents and serial. The name is checked here too: it is
// the pair's Common Name, and keepLocal keeps the pair under it.
func mintStaged(pkiDir, minted, hostName string, ip net.IP) ([2][]byte, string, error) {
	if err := pki.ValidateExistingHostName(hostName); err != nil {
		return [2][]byte{}, "", err
	}
	crt := filepath.Join(minted, "host.crt")
	key := filepath.Join(minted, "host.key")
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
// CA, the gossip key and the host's migration credentials (minted into the
// attempt's directory minted).
func addOtherFiles(p hostAddPlan, minted string, ip net.IP) ([]addFile, error) {
	crt := filepath.Join(minted, "migration.crt")
	key := filepath.Join(minted, "migration.key")
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

// keptHostsDir is where, under the operator's pki directory, an add keeps
// its copy of each host's credentials: hosts/<name>/, apart from the
// cluster's own files, so no host name can reach ca.crt or this machine's
// host pair.
const keptHostsDir = "hosts"

// keptHostDir is hostName's directory under pkiDir/hosts, or "" for a name
// that is not one plain path element (pki.ValidateHostPathName, the rule for
// every name, new or admitted by an older release, that becomes a path).
func keptHostDir(pkiDir, hostName string) string {
	if pki.ValidateHostPathName(hostName) != nil {
		return ""
	}
	return filepath.Join(pkiDir, keptHostsDir, hostName)
}

// keepLocal moves this machine's minted copies, from the attempt's directory
// minted, to keptHostDir once admitted. A failure leaves nothing kept: the
// admitted pair is also staged on the host, and the rerun takes it from
// there.
func keepLocal(minted, pkiDir, hostName string) {
	dir := keptHostDir(pkiDir, hostName)
	if dir == "" {
		slog.Warn("not keeping this machine's copy of the admitted credentials: the host name is not a file name",
			"host", hostName)
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("could not keep this machine's copy of the admitted credentials", "dir", dir, "error", err)
		return
	}
	for _, n := range []string{"host.crt", "host.key", "migration.crt", "migration.key"} {
		src := filepath.Join(minted, n)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(dir, n)); err != nil {
			slog.Warn("could not keep this machine's copy of the admitted credentials", "path", src, "error", err)
		}
	}
}

// finishAdd writes the audit admission record and runs setup, which starts
// the daemon.
//
// Each of its writes on the host is run through guard (machineClaim.cmd);
// the rejoin record is staged at tag's path first.
func finishAdd(r addRemote, p hostAddPlan, serial, tag string, admitted *pb.AdmitHostResponse, guard func(string) string) error {
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
		if err := r.WriteFile(addStagedPath(rejoinPath, tag), rejoin, 0644); err != nil {
			return fmt.Errorf("push %s: %w", corrosion.AuditRejoinFileName, err)
		}
		if _, err := r.Shell("rejoin", guard(installCmd(r, []string{rejoinPath}, "", tag))); err != nil {
			return fmt.Errorf("put %s in place: %w", corrosion.AuditRejoinFileName, err)
		}
	} else if remove {
		if _, err := r.Shell("rejoin", guard(removeCmd(r, []string{rejoinPath}))); err != nil {
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
	if err := r.RunWithInput(guard(remoteAddSetupCommand(p.hostName, p.hostAddr, p.peersYAML, p.enforcement, p.configInstalled)), []byte(p.setupScript)); err != nil {
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

// addStagedPath is where the add attempt tagged tag (the serial it is
// admitted with) stages the file it installs at path: .<name>.add-<tag>
// beside it.
func addStagedPath(path, tag string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".add-"+tag)
}

// legacyStagedPath is where an earlier release's add staged path, untagged.
func legacyStagedPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".add")
}

func stagedPaths(paths []string, tag string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = addStagedPath(p, tag)
	}
	return out
}

// validAttemptTag reports whether tag, a certificate serial, can name staged
// files: lower-case hex. A serial read from the cluster's hosts row is
// replicated data, and must not carry a path.
func validAttemptTag(tag string) bool {
	if tag == "" || len(tag) > 64 {
		return false
	}
	for _, c := range tag {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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

// existsCmd prints the mode and path of each of paths that exists, one per
// line (a symlink's target's mode).
func existsCmd(r addRemote, paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		q := ssh.ShellQuote(r.Path(p))
		fmt.Fprintf(&b, "if [ -e %s ]; then printf '%%s %%s\\n' \"$(stat -L -c %%a -- %s)\" %s; fi; ", q, q, q)
	}
	return b.String()
}

// existsSet reads existsCmd's output back into paths: each existing path's
// octal mode, which a restore puts back.
func existsSet(r addRemote, paths []string, out []byte) map[string]string {
	listed := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if mode, path, ok := strings.Cut(l, " "); ok {
			if _, err := strconv.ParseUint(mode, 8, 32); err == nil {
				listed[path] = mode
			}
		}
	}
	got := map[string]string{}
	for _, p := range paths {
		if m, ok := listed[r.Path(p)]; ok {
			got[p] = m
		}
	}
	return got
}

// installCmd moves each path's file staged by the attempt tag into place,
// synced before and after the rename. With a suffix, every file it replaces
// is first copied to path+suffix: its content (a symlinked key is followed)
// at 0600.
func installCmd(r addRemote, paths []string, suffix, tag string) string {
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
		q, s := ssh.ShellQuote(r.Path(p)), ssh.ShellQuote(r.Path(addStagedPath(p, tag)))
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

// restoreCmd undoes installCmd, for the files this attempt installed and
// only those. A path whose staged file is still there was never replaced. A
// path whose content is what this attempt installed (ours, its sha256) goes
// back to its staged path (the attempt tag's), so the admitted file stays on
// the host for a rerun, and its copy back into place at the file's own mode
// (existed, from existsSet; the copy is 0600); one with no copy did not
// exist. A path holding anything else was not written by this attempt: it is
// left as it is, with the copy beside it, and the command fails.
func restoreCmd(r addRemote, paths []string, existed, ours map[string]string, suffix, tag string) string {
	var cmd strings.Builder
	cmd.WriteString("rc=0; ")
	for _, p := range paths {
		q := ssh.ShellQuote(r.Path(p))
		s, b := ssh.ShellQuote(r.Path(addStagedPath(p, tag))), ssh.ShellQuote(r.Path(p)+suffix)
		fmt.Fprintf(&cmd, "if [ -e %s ]; then rm -f -- %s || rc=1; ", s, b)
		fmt.Fprintf(&cmd, "elif [ -e %s ] && [ \"$(sha256sum < %s | cut -d' ' -f1)\" != %s ]; then rc=1; else ", q, q, ssh.ShellQuote(ours[p]))
		fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s || rc=1; fi; ", q, q, s)
		if mode := existed[p]; mode != "" {
			fmt.Fprintf(&cmd, "if [ -e %s ]; then mv -fT -- %s %s && chmod %s %s || rc=1; fi; ", b, b, q, mode, q)
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
	// path (as the host names it; a staged path untagged, .<name>.add)
	// returns.
	FailSetup error
	FailWrite map[string]error
	// OnSetup, when set, runs when setup does; its error is setup's.
	OnSetup func() error
	// Events are what reached the host, in order: "write <path>",
	// "run <cmd>" and "sh <kind>".
	Events []string
	// DaemonState is what `systemctl is-active litevirt.service` answers on
	// the machine ("" is inactive).
	DaemonState string
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
	if strings.Contains(cmd, "bash -s") {
		if d.OnSetup != nil {
			return d.OnSetup()
		}
		return d.FailSetup
	}
	return nil
}

func (d *LocalAddTarget) WriteFile(path string, data []byte, mode os.FileMode) error {
	d.Events = append(d.Events, "write "+path)
	key := path
	if i := strings.LastIndex(path, ".add-"); i >= 0 {
		key = path[:i+len(".add")]
	}
	if err := d.FailWrite[key]; err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Path(path)), 0o755); err != nil {
		return err
	}
	return secretfile.Write(d.Path(path), data, mode)
}

func (d *LocalAddTarget) Shell(kind, cmd string) ([]byte, error) {
	d.Events = append(d.Events, "sh "+kind)
	if kind == daemonProbeKind {
		// Not the unit of the machine running the test.
		if d.DaemonState == "" {
			return []byte("inactive\n"), nil
		}
		return []byte(d.DaemonState + "\n"), nil
	}
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
		binPath: t.Binary, rerun: addRerunCmd(hostName, "root@"+hostAddr),
	})
}

// UseMachinesForTests stands this process in for an operator machine that is
// not a cluster node, whatever the machine running the test is: its daemon
// config is read from configPath (a path that does not exist means none), and
// `lv host rm` reaches the machine at each address of machines through its
// LocalAddTarget instead of SSH (an address not listed fails to connect). It
// returns what puts both back. It swaps process globals without a lock: not
// for parallel tests.
func UseMachinesForTests(configPath string, machines map[string]*LocalAddTarget) (restore func()) {
	oldPath, oldDial := daemonConfigPath, dialAdmissionMachine
	daemonConfigPath = configPath
	dialAdmissionMachine = func(addr string) (addRemote, func(), error) {
		if m, ok := machines[addr]; ok {
			return m, func() {}, nil
		}
		return nil, nil, fmt.Errorf("SSH connect: no machine at %s (test)", addr)
	}
	return func() { daemonConfigPath, dialAdmissionMachine = oldPath, oldDial }
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
			why := "peers dial the host at %d, so it would be unreachable"
			if key == "gossip_port" {
				// memberlist advertises its own port; what breaks is the
				// seed lv host add writes into this node's and later hosts'
				// join_peers.
				why = "peers and later adds seed the host at %d"
			}
			return nil, fmt.Errorf("%s is %v: "+why+" (set %s: %d, or remove the key)", key, v, want, key, want)
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
		if strings.Contains(err.Error(), "anchor") {
			return nil, fmt.Errorf("the edited file does not parse (%v): a line the add kept is an alias to an "+
				"anchor in a key it replaced", err)
		}
		return nil, fmt.Errorf("the edited file does not parse (%v): the file has a layout it cannot edit line "+
			"by line (a quoted or explicit key, a second document, or a value it could not delimit)", err)
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
			return nil, fmt.Errorf("editing it would change %s: the file has a layout it cannot edit line by line "+
				"(its value depends on a key the add replaces, or the add could not tell where that key's lines end)", k)
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
	span:
		for j := i + 1; j < len(lines); j++ {
			t := lines[j]
			trimmed := strings.TrimSpace(t)
			switch {
			case trimmed == "":
			case continuesValue(t):
				end = j + 1
			case strings.HasPrefix(t, "#"):
				// A column-0 comment belongs to the block when more of the
				// block follows it, as a commented-out option does.
				if !moreFollows(lines[j+1:]) {
					break span
				}
			default:
				break span
			}
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

// Where admittedPairOnMachine found the admitted pair.
const (
	pairAbsent = iota
	pairInstalled
	pairStaged       // at the paths an add tagged with the serial staged it to
	pairStagedLegacy // at an earlier release's untagged staged paths
)

// admittedPairOnMachine finds the pair of the admitted certificate serial on
// the host: installed (installed says the host serves it), staged by the add
// that was admitted with it, or staged by an earlier release's add. It
// checks the key there is the certificate's, and returns the legacy pair's
// contents, which the add stages again at its own paths.
func admittedPairOnMachine(r addRemote, serial string, installed bool) ([2][]byte, int, error) {
	crt, key := filepath.Join(remotePKIDir, "host.crt"), filepath.Join(remotePKIDir, "host.key")
	var pair [2][]byte
	if installed {
		_, err := readPair(r, crt, key, serial)
		return pair, pairInstalled, err
	}
	staged, err := stagedAttempts(r, crt, serial)
	if err != nil {
		return pair, pairAbsent, err
	}
	var perr error
	for _, tag := range staged {
		p, err := readPair(r, addStagedPath(crt, tag), addStagedPath(key, tag), serial)
		if err == nil {
			return p, pairStaged, nil
		}
		perr = err
	}
	if perr != nil {
		return pair, pairAbsent, perr
	}
	if b, ok, err := r.ReadFile(legacyStagedPath(crt)); err != nil {
		return pair, pairAbsent, err
	} else if ok && installedSerial(b) == serial {
		pair, err := readPair(r, legacyStagedPath(crt), legacyStagedPath(key), serial)
		return pair, pairStagedLegacy, err
	}
	return pair, pairAbsent, nil
}

// stagedPairIs checks that the pair the attempt tag staged is certificate
// serial and its key: what the install moves into place.
func stagedPairIs(r addRemote, serial, tag string) error {
	crt, key := filepath.Join(remotePKIDir, "host.crt"), filepath.Join(remotePKIDir, "host.key")
	_, err := readPair(r, addStagedPath(crt, tag), addStagedPath(key, tag), serial)
	return err
}

// attemptNonce is a fresh attempt's nonce, which every file it stages
// carries.
func attemptNonce() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("draw an attempt nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// stagedAttempts lists the attempt tags (<serial>-<nonce>) under which path
// is staged for serial on the host.
func stagedAttempts(r addRemote, path, serial string) ([]string, error) {
	prefix := addStagedPath(path, serial+"-")
	out, err := r.Shell("staged", fmt.Sprintf("for f in %s*; do [ -e \"$f\" ] && printf '%%s\\n' \"$f\"; done; true",
		ssh.ShellQuote(r.Path(prefix))))
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, l := range strings.Split(string(out), "\n") {
		if l == "" {
			continue
		}
		rest, ok := strings.CutPrefix(r.Unpath(l), prefix)
		if !ok || !validAttemptTag(rest) {
			continue
		}
		tags = append(tags, serial+"-"+rest)
	}
	return tags, nil
}

// removeLegacyStagedPair removes the untagged pair an earlier release's add
// staged, only when its certificate is serial's. It first claims the pair by
// renaming it to a name of its own, so an older add staging a new pair there
// meanwhile keeps it; a claimed pair of another serial goes back, unless a
// new one has taken its place.
func removeLegacyStagedPair(r addRemote, serial string) error {
	crt := legacyStagedPath(filepath.Join(remotePKIDir, "host.crt"))
	key := legacyStagedPath(filepath.Join(remotePKIDir, "host.key"))
	nonce, err := attemptNonce()
	if err != nil {
		return err
	}
	ccrt, ckey := crt+".rm-"+nonce, key+".rm-"+nonce
	q := func(p string) string { return ssh.ShellQuote(r.Path(p)) }
	if _, err := r.Shell("claim", fmt.Sprintf("if [ -e %s ]; then mv -fT -- %s %s; if [ -e %s ]; then mv -fT -- %s %s; fi; fi",
		q(crt), q(crt), q(ccrt), q(key), q(key), q(ckey))); err != nil {
		return err
	}
	b, ok, err := r.ReadFile(ccrt)
	if err != nil || !ok {
		return err
	}
	// The two renames are not one: an older add may have staged a new pair
	// between them. Only a claimed certificate of serial with its own key
	// goes; anything else goes back where it was.
	k, okk, err := r.ReadFile(ckey)
	if err != nil {
		return err
	}
	if installedSerial(b) == serial && okk {
		if _, perr := tls.X509KeyPair(b, k); perr == nil {
			_, err = r.Shell("unstage", removeCmd(r, []string{ccrt, ckey}))
			return err
		}
	}
	_, err = r.Shell("unclaim", fmt.Sprintf("rc=0; mv -nT -- %s %s || rc=1; if [ -e %s ]; then mv -nT -- %s %s || rc=1; fi; exit $rc",
		q(ccrt), q(crt), q(ckey), q(ckey), q(key)))
	return err
}

// addLock is the file whose flock(2) every command an add runs on a machine
// it has claimed takes, in the shell that runs it (machineClaim.cmd), for as
// long as that command runs: a command delayed past its add's lost
// connection still runs under it, or not at all.
const addLock = "/etc/litevirt/.lv-add.lock"

// addInstalledMarker records which add holds the machine or installed it
// last: "<name> <serial> <unix time> <nonce> <installing|installed>" (an
// earlier form has three or four fields, and is an install). Changed only
// under addLock, by a compare-and-swap.
const addInstalledMarker = "/etc/litevirt/.lv-add-installed"

// addLockWait is how long, in seconds, a command waits for addLock while
// another command holds it (a setup can hold it for minutes). A var so tests
// can shorten it.
var addLockWait = 600

// staleClaim is how long a claim of another add with no finished install
// keeps a second add out: an add's commands after its claim are short, but
// for setup, which holds addLock while it runs. A claim older than this is
// an add that died; taking it over is safe, since a late command of that add
// finds the claim is no longer its own and does nothing.
const staleClaim = 10 * time.Minute

// freshInstall is how long an install under another name keeps a second add
// of the machine from installing when that name's certificate is not revoked
// here: long past the time an admission takes to reach every host.
const freshInstall = time.Hour

// addNow is the clock refuseSecondInstall reads an install record's age by.
// A var so tests can fix it.
var addNow = time.Now

// notOurMachine is the exit status of a guarded command that found the
// machine claimed by another (machineClaim.cmd).
const notOurMachine = 97

// lockedCmd runs body in a shell that holds addLock while it runs, and only
// when cond holds there. Without flock(1) on the host it refuses: an add does
// not change a machine unlocked.
func lockedCmd(r addRemote, cond, body string) string {
	lock := ssh.ShellQuote(r.Path(addLock))
	return fmt.Sprintf("command -v flock >/dev/null 2>&1 || { echo 'flock(1) is not installed on the host; "+
		"lv host add does not change the machine without its lock' >&2; exit 98; }; "+
		"mkdir -p -- %s || exit 1; exec 9>>%s || exit 1; "+
		"flock -w %d 9 || { echo 'another command holds the add lock %s' >&2; exit 96; }; "+
		"if %s; then ( %s ); else echo 'this add no longer holds the machine: %s records another' >&2; exit %d; fi",
		ssh.ShellQuote(filepath.Dir(r.Path(addLock))), lock, addLockWait, addLock, cond, body, addInstalledMarker, notOurMachine)
}

// markerIs is the shell test that the install record is line exactly
// (without its newline); markerAbsent that there is none.
func markerIs(r addRemote, line string) string {
	return fmt.Sprintf("[ \"$(cat -- %s 2>/dev/null)\" = %s ]", ssh.ShellQuote(r.Path(addInstalledMarker)), ssh.ShellQuote(line))
}

func markerAbsent(r addRemote) string {
	return fmt.Sprintf("[ ! -e %s ]", ssh.ShellQuote(r.Path(addInstalledMarker)))
}

// setMarkerCmd writes line as the install record ("" removes it): the new
// file synced, renamed into place, then its directory synced, so the record
// is on disk before anything the add installs after it. A failed sync fails
// the command (and a claim fails the add before it installs anything):
// `sync DIR` needs coreutils 8.24 or later, as the add's other syncs do, and
// an older sync refuses the operand rather than skip it.
func setMarkerCmd(r addRemote, line, nonce string) string {
	m := ssh.ShellQuote(r.Path(addInstalledMarker))
	dir := ssh.ShellQuote(filepath.Dir(r.Path(addInstalledMarker)))
	tmp := ssh.ShellQuote(r.Path(addInstalledMarker) + ".new-" + nonce)
	if line == "" {
		return fmt.Sprintf("rm -f -- %s && sync -- %s", m, dir)
	}
	return fmt.Sprintf("umask 077; printf '%%s\\n' %s > %s && sync -- %s && mv -fT -- %s %s && sync -- %s",
		ssh.ShellQuote(line), tmp, tmp, tmp, m, dir)
}

// machineClaim is an add's claim of the machine: mine is its install record;
// settle is the path of a settle's claim of its admission (settleClaimPath),
// which none of its commands runs past.
type machineClaim struct {
	r      addRemote
	mine   string
	settle string
}

// holds is the shell test that the machine is this claim's: it records the
// claim, and no settle of its admission has claimed it.
func (m machineClaim) holds(record string) string {
	if m.settle == "" {
		return record
	}
	return record + fmt.Sprintf(" && [ ! -e %s ]", ssh.ShellQuote(m.r.Path(m.settle)))
}

// cmd is body run under addLock, only while the machine records this claim.
func (m machineClaim) cmd(body string) string {
	return lockedCmd(m.r, m.holds(markerIs(m.r, m.mine)), body)
}

func (m machineClaim) nonce() string {
	if f := markerFields(m.mine); len(f) >= 4 {
		return f[3]
	}
	return "x"
}

// take claims the machine, from the record prior that refuseSecondInstall
// read ("" when there was none): only if it is still that.
func (m machineClaim) take(prior string) error {
	cond := markerAbsent(m.r)
	if prior != "" {
		cond = markerIs(m.r, prior)
	}
	_, err := m.r.Shell("claim", lockedCmd(m.r, m.holds(cond), setMarkerCmd(m.r, m.mine, m.nonce())))
	if exitStatus(err) == notOurMachine {
		return fmt.Errorf("another add claimed this machine since this one read %s: run this again once it has "+
			"finished", addInstalledMarker)
	}
	if err != nil {
		return fmt.Errorf("claim the machine in %s: %w", addInstalledMarker, err)
	}
	return nil
}

// give replaces this claim with line ("" removes the record), only while the
// machine still records the claim.
func (m machineClaim) give(line string) error {
	_, err := m.r.Shell("claim", m.cmd(setMarkerCmd(m.r, line, m.nonce())))
	return err
}

// exitStatus is the exit status of a remote command's err, -1 when it has
// none.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var s interface{ ExitStatus() int }
	if errors.As(err, &s) {
		return s.ExitStatus()
	}
	var e interface{ ExitCode() int }
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return -1
}

// refuseSecondInstall refuses to install serial for p when the machine is not
// this add's to install on: its certificate is not one exp, serial or this
// cluster's CRL proves it may replace (refuseUnproven); or its install record
// (addInstalledMarker) is another add's claim younger than staleClaim, or
// another admission's install (whatever its name) less than freshInstall ago
// whose certificate this cluster's CRL does not revoke (`lv host rm` revokes
// it). It returns the record it read, which the claim then replaces only if
// it is still there (machineClaim.take).
func refuseSecondInstall(r addRemote, p hostAddPlan, serial string, exp addExpect, nonce string) (string, error) {
	nowPEM, now, err := remoteCert(r, filepath.Join(remotePKIDir, "host.crt"))
	if err != nil {
		return "", err
	}
	if err := refuseUnproven(r, p, serial, exp, nowPEM, now); err != nil {
		return "", err
	}
	b, ok, err := r.ReadFile(addInstalledMarker)
	if err != nil || !ok {
		return "", err
	}
	prior := strings.TrimRight(string(b), "\n")
	f := markerFields(prior)
	if len(f) < 3 {
		return prior, nil
	}
	at, _ := strconv.ParseInt(f[2], 10, 64)
	when := time.Unix(at, 0)
	// The record's fields come from the machine: printed only once checked.
	name, other, attempt := "(unreadable)", canonSerial(f[1]), "(unreadable)"
	if validHostName(f[0]) {
		name = f[0]
	}
	shown := other
	if shown == "" {
		shown = "(unreadable)"
	}
	if len(f) >= 4 && validAttemptTag(f[3]) {
		attempt = f[3]
	}
	if len(f) >= 5 && f[4] == "installing" && f[3] != nonce && addNow().Sub(when) < staleClaim {
		return "", fmt.Errorf("another `lv host add` holds this machine (attempt %s, for %s with certificate %s, since "+
			"%s), and this one installs nothing. Run this again once it has finished; if it died, after %s",
			attempt, name, shown, when.UTC().Format(time.RFC3339), when.Add(staleClaim).UTC().Format(time.RFC3339))
	}
	// The record's admission, not its name, decides: the same name may be
	// another admission's (one this replica has not received, say). Its
	// recent install is replaced only when what the machine serves is
	// proven not to be it: nothing, this admission's own certificate, or one
	// this cluster's CA issued and revoked. The record's serial being
	// revoked proves nothing about the certificate installed.
	if other == serial || addNow().Sub(when) >= freshInstall || now == "" || now == serial || revokedHere(p.pkiDir, nowPEM) {
		return prior, nil
	}
	return "", settled(fmt.Sprintf("another admission installed this machine as %s (certificate %s) at %s, and the "+
		"machine serves certificate %s, which this cluster has not revoked, so this add installs nothing: a machine is "+
		"admitted under one name. `%s` undoes this add's admission and leaves the machine as it is",
		name, shown, when.UTC().Format(time.RFC3339), now, settleCmd(p, serial)))
}

// readPair reads the certificate at crt and the key at key on the host, and
// checks the certificate's serial is serial and the key is its key.
func readPair(r addRemote, crt, key, serial string) ([2][]byte, error) {
	var pair [2][]byte
	c, okc, err := r.ReadFile(crt)
	if err != nil {
		return pair, err
	}
	k, okk, err := r.ReadFile(key)
	if err != nil {
		return pair, err
	}
	if !okc || !okk {
		return pair, fmt.Errorf("%s or %s is missing", crt, key)
	}
	if got := installedSerial(c); got != serial {
		return pair, fmt.Errorf("%s is certificate %q, not %s", crt, got, serial)
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		return pair, err
	}
	return [2][]byte{c, k}, nil
}

// continuesValue reports whether line, after a top-level key, is part of its
// value: indented, a block sequence item at the key's own indent (as PyYAML
// and Ansible write them), or a flow collection's closer at column 0.
func continuesValue(line string) bool {
	switch {
	case line[0] == ' ' || line[0] == '\t':
		return true
	case line == "-\n" || strings.HasPrefix(line, "- "):
		return true
	case strings.HasPrefix(line, "]") || strings.HasPrefix(line, "}"):
		return true
	}
	return false
}

// moreFollows reports whether the next line in lines that is neither blank
// nor a comment continues a value.
func moreFollows(lines []string) bool {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(l, "#") {
			continue
		}
		return continuesValue(l)
	}
	return false
}
