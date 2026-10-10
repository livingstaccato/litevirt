package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netutil"
	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
	"github.com/litevirt/litevirt/internal/ssh"
	"github.com/litevirt/litevirt/internal/systemdunit"
)

var (
	lookupUserByName = osuser.Lookup
	chownPath        = os.Chown
)

// HostInit bootstraps the first host in the cluster.
// 1. Generate CA (if not exists)
// 2. Generate host certificate
// 3. Push CA + host cert + litevirtd binary + setup script via SSH
// 4. Run setup script to install deps and start litevirtd
func HostInit(ctx context.Context, sshTarget string, hostName string, force bool) error {
	// Parse SSH target to get IP for cert SAN
	parsedHost, _, err := parseSSHTarget(sshTarget)
	if err != nil {
		return err
	}
	hostAddr, err := resolveHost(parsedHost)
	if err != nil {
		return err
	}

	// Connect and inspect the target BEFORE anything is minted or pushed, so a
	// refusal leaves both this machine's PKI dir and the target untouched.
	slog.Info("connecting to host", "target", sshTarget)
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	// ABSENT and UNREADABLE must not look alike here: see classifyRemoteConfig.
	rawCfg, runErr := sc.RunOutput(remoteConfigProbe(daemonConfigPath))
	existingCfg, absent, err := classifyRemoteConfig(string(rawCfg), runErr)
	if err != nil && !force {
		return err
	}
	if !absent {
		if err := refuseIfAlreadyAMember(sshTarget, []byte(existingCfg), force); err != nil {
			return err
		}
	}

	pkiDir := PKIDir()
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return fmt.Errorf("create PKI dir: %w", err)
	}

	// 1. Generate CA if it doesn't exist
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		slog.Info("generating cluster CA")
		if err := pki.GenerateCA(caPath, caKeyPath); err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
	}

	// 2. Generate CLI client certificate if it doesn't exist
	clientCertPath := filepath.Join(pkiDir, "client.crt")
	clientKeyPath := filepath.Join(pkiDir, "client.key")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("generating CLI client certificate")
		if err := pki.GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}

	// The cluster gossip key, minted beside the CA the first time and reused
	// after. The new-cluster enforcement block enforces it from the start.
	gossipKeyPath, _, err := ensureLocalGossipKey(pkiDir)
	if err != nil {
		return fmt.Errorf("gossip key: %w", err)
	}

	// 3. Generate host certificate
	slog.Info("generating host certificate", "host", hostName, "address", hostAddr)
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")

	ip := net.ParseIP(hostAddr)
	if err := pki.GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, hostName, ip); err != nil {
		return fmt.Errorf("generate host cert: %w", err)
	}

	// 4. Push files to host
	slog.Info("pushing files to host", "target", sshTarget)
	remotePKIDir := "/etc/litevirt/pki"
	if err := sc.Run(fmt.Sprintf("mkdir -p %s", remotePKIDir)); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}

	// The host KEY is 0600. It is the node's entire cluster identity: peer mTLS
	// authenticates with it and audit rows are signed with it, so a local user
	// who can read it can both impersonate the host to every peer and forge its
	// audit history. It shipped 0644 because CopyFile's default mode was
	// invisible at the call site.
	for _, f := range []struct {
		local, remote string
		mode          os.FileMode
	}{
		{caPath, filepath.Join(remotePKIDir, "ca.crt"), 0644},
		{hostCertPath, filepath.Join(remotePKIDir, "host.crt"), 0644},
		{hostKeyPath, filepath.Join(remotePKIDir, "host.key"), 0600},
		// 0600 for the same reason as host.key: whoever reads it speaks gossip.
		{gossipKeyPath, filepath.Join(remotePKIDir, pki.GossipKeyName), 0600},
	} {
		if err := sc.CopyFileMode(f.local, f.remote, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(f.local), err)
		}
	}
	// Migration-TLS credentials from the separate migration CA, so storage
	// migrations to and from this host are encrypted. nil: init founds a
	// cluster, so there is no host holding another CA's credentials to ask.
	migFiles, err := issueMigrationCredentials(pkiDir, hostName, ip, nil)
	if err != nil {
		return err
	}
	if err := pushMigrationCredentials(sc, migFiles); err != nil {
		return err
	}

	// Push litevirtd binary
	binPath, err := findDaemonBinary()
	if err != nil {
		return fmt.Errorf("find litevirtd binary: %w", err)
	}
	slog.Info("pushing litevirt binary", "path", binPath)
	if err := sc.CopyFile(binPath, "/usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("push litevirt binary: %w", err)
	}
	if err := sc.Run("chmod 755 /usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("chmod litevirt: %w", err)
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := sc.Run("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv"); err != nil {
		return fmt.Errorf("symlink lv: %w", err)
	}

	// 4. Push and run setup script
	slog.Info("running host setup")
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}

	// bash -s with the script on stdin: it never lands on the remote filesystem,
	// so there is no path for a local user on the target to pre-create, no window
	// between writing it and running it, and nothing to clean up if this process
	// dies in between.
	if err := sc.RunWithInput(remoteInitSetupCommand(hostName, hostAddr, existingCfg), []byte(setupScript)); err != nil {
		return fmt.Errorf("run setup script: %w", err)
	}

	fmt.Printf("Host %s initialized successfully at %s\n", hostName, hostAddr)
	fmt.Printf("  gRPC endpoint: %s:7443 (mTLS)\n", hostAddr)
	return nil
}

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

	// Generate host certificate
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")

	ip := net.ParseIP(hostAddr)
	if err := pki.GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, hostName, ip); err != nil {
		return fmt.Errorf("generate host cert: %w", err)
	}

	// Push to host
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	remotePKIDir := "/etc/litevirt/pki"
	if err := sc.Run(fmt.Sprintf("mkdir -p %s", remotePKIDir)); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}

	// The host KEY is 0600. It is the node's entire cluster identity: peer mTLS
	// authenticates with it and audit rows are signed with it, so a local user
	// who can read it can both impersonate the host to every peer and forge its
	// audit history. It shipped 0644 because CopyFile's default mode was
	// invisible at the call site.
	for _, f := range []struct {
		local, remote string
		mode          os.FileMode
	}{
		{caPath, filepath.Join(remotePKIDir, "ca.crt"), 0644},
		{hostCertPath, filepath.Join(remotePKIDir, "host.crt"), 0644},
		{hostKeyPath, filepath.Join(remotePKIDir, "host.key"), 0600},
	} {
		if err := sc.CopyFileMode(f.local, f.remote, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(f.local), err)
		}
	}
	if pushGossipKey {
		if err := sc.CopyFileMode(gossipKeyPath, filepath.Join(remotePKIDir, pki.GossipKeyName), 0600); err != nil {
			return fmt.Errorf("push %s: %w", pki.GossipKeyName, err)
		}
	}
	// Migration-TLS credentials from the cluster's migration CA, decided above,
	// so storage migrations with this host are encrypted.
	migFiles, err := issueMigrationCredentials(pkiDir, hostName, ip, migHolder)
	if err != nil {
		return err
	}
	if err := pushMigrationCredentials(sc, migFiles); err != nil {
		return err
	}

	// Push litevirtd binary
	binPath, err := findDaemonBinary()
	if err != nil {
		return fmt.Errorf("find litevirtd binary: %w", err)
	}
	slog.Info("pushing litevirt binary", "path", binPath)
	if err := sc.CopyFile(binPath, "/usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("push litevirt binary: %w", err)
	}
	if err := sc.Run("chmod 755 /usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("chmod litevirt: %w", err)
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := sc.Run("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv"); err != nil {
		return fmt.Errorf("symlink lv: %w", err)
	}

	// Run setup
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}
	// hostAddr is the address this command just put in the certificate SAN and the
	// address peers were told to dial, so it is also the address the node must
	// advertise. Leaving the daemon to auto-detect meant it registered with its
	// default-route source IP — a different interface on a multi-homed host — and
	// that value was then copied into the join_peers of every host added after it.
	serial, err := pki.CertSerial(hostCertPath)
	if err != nil {
		return fmt.Errorf("read generated host certificate serial: %w", err)
	}
	admitted, err := c.AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: hostName, Address: hostAddr, CertSerial: serial,
	})
	if err != nil {
		return fmt.Errorf("admit host identity to the cluster: %w", err)
	}
	// The name's audit chain position, signed with the CA, so the new machine's
	// daemon holds its own audit rows until that history has reached it instead
	// of starting a second chain under an old name. Before setup, which starts
	// the daemon. A name with no history gets no record — and loses any a
	// previous machine under the name left behind.
	rejoin, remove, err := AuditRejoinFile(pkiDir, hostName, serial, admitted)
	if err != nil {
		return fmt.Errorf("sign %s's audit admission record: %w", hostName, err)
	}
	rejoinPath := filepath.Join(remotePKIDir, corrosion.AuditRejoinFileName)
	if rejoin != nil {
		if err := sc.WriteFile(rejoinPath, rejoin, 0644); err != nil {
			return fmt.Errorf("push %s: %w", corrosion.AuditRejoinFileName, err)
		}
	} else if remove {
		if err := sc.Run("rm -f " + ssh.ShellQuote(rejoinPath)); err != nil {
			return fmt.Errorf("remove a stale %s: %w", corrosion.AuditRejoinFileName, err)
		}
	}
	// Admission must replicate before setup starts the daemon. A re-added node's
	// local database still contains its tombstone; starting it first lets its boot
	// state update put a fresh timestamp on that tombstone and race the admission
	// back out to the cluster.
	if err := sc.RunWithInput(remoteAddSetupCommand(hostName, hostAddr, peersYAML, enforcement), []byte(setupScript)); err != nil {
		return fmt.Errorf("run setup script after admitting the host identity: %w", err)
	}

	// Back-fill the new host into THIS machine's gossip seed list. The daemon
	// needs a restart to pick it up, and memberlist may discover the peer through
	// existing members anyway — but the seed list is now load-bearing for more
	// than gossip, so only one failure here is benign.
	//
	// Running `lv` from a workstation is supported, and a workstation has no
	// daemon config to update. That is errNotALocalNode, and it is fine.
	//
	// Anything else means this machine IS a cluster node whose join_peers could
	// not be updated, and a slog.Warn is not enough: an empty join_peers is what
	// makes a node look like a FOUNDER, so leaving it wrong sets up a later
	// state.db rebuild to mint a fresh admin credential over the cluster's.
	if err := ensureLocalPeer(daemonConfigPath, hostAddr, 7946); err != nil {
		if errors.Is(err, errNotALocalNode) {
			slog.Info("this machine is not a cluster node, so it has no join_peers to back-fill",
				"config", daemonConfigPath)
		} else {
			return fmt.Errorf("host %s WAS added to the cluster, but this machine's own "+
				"join_peers in %s could not be updated (%w) — add %s to it by hand before "+
				"restarting the daemon, or this node still looks like a founder",
				hostName, daemonConfigPath, err, net.JoinHostPort(hostAddr, strconv.Itoa(7946)))
		}
	}

	fmt.Printf("Host %s added to cluster at %s\n", hostName, hostAddr)
	return nil
}

// AuditRejoinFile is the CA-signed admission record `lv host add` writes into a
// re-added machine's pki dir (corrosion.AuditRejoinFileName): the audit chain
// position the admitting node holds for the name, bound to the certificate
// (certSerial) minted for this machine.
//
// It returns no record for a name with no history. remove then says whether an
// existing record on the machine should go: only when the admitting daemon
// vouched for "no history" (AuditPositionProven). A daemon too old to vouch
// answers 0 for every name, and deleting a record on its word would let a
// rebuilt host fork; a record for another certificate is ignored by the daemon
// anyway.
func AuditRejoinFile(pkiDir, hostName, certSerial string, admitted *pb.AdmitHostResponse) (record []byte, remove bool, err error) {
	if admitted.GetAuditTailSeq() <= 0 {
		return nil, admitted.GetAuditPositionProven(), nil
	}
	// A position the daemon did not vouch for is not signed either: an
	// unreleased build answered positions on a weaker test of its replica.
	if !admitted.GetAuditPositionProven() {
		return nil, false, nil
	}
	rj, err := corrosion.SignAuditRejoin(pkiDir, hostName, certSerial,
		admitted.GetAuditTailSeq(), admitted.GetAuditTailHash())
	if err != nil {
		return nil, false, err
	}
	b, err := json.MarshalIndent(rj, "", "  ")
	return b, false, err
}

// ensureLocalPeer adds a gossip peer address to the local daemon config if not already present.
func ensureLocalPeer(cfgPath string, addr string, gossipPort int) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errNotALocalNode
		}
		return err
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	// JoinHostPort: this string is written into the remote node's config.yaml as
	// a join_peers entry, so a mangled IPv6 address becomes a permanent bad seed.
	peerAddr := net.JoinHostPort(addr, strconv.Itoa(gossipPort))

	// Get existing peers.
	var peers []string
	if raw, ok := cfg["join_peers"]; ok && raw != nil {
		if list, ok := raw.([]interface{}); ok {
			for _, p := range list {
				if s, ok := p.(string); ok {
					if s == peerAddr {
						return nil // already present
					}
					peers = append(peers, s)
				}
			}
		}
	}

	peers = append(peers, peerAddr)
	cfg["join_peers"] = peers

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, out, 0644)
}

// findDaemonBinary locates the litevirt binary to distribute. Since the CLI
// and daemon are now one binary, the running executable is itself a valid
// candidate — but prefer a sibling/installed `litevirt` so a freshly-built
// bin/litevirt is picked up during dev.
func findDaemonBinary() (string, error) {
	self, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(self), "litevirt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Check common install paths.
	for _, p := range []string{"/usr/local/bin/litevirt", "/usr/bin/litevirt"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// The running binary is itself the combined litevirt binary.
	if self != "" {
		return self, nil
	}
	return "", fmt.Errorf("litevirt binary not found — build it first or place it next to the running binary")
}

// HostInitLocal bootstraps litevirt on the local machine (no SSH).
// Intended for single-node standalone setups.
// mintLocalHostCert issues the first host's certificate, covering the address
// PEERS will dial as well as loopback.
//
// It used to pass 127.0.0.1 alone, which is the one address guaranteed to mean a
// different machine to whoever dials it — so no peer could ever complete a
// handshake with the first node, and the documented advice ("use the remote form")
// is circular, because a node cannot init itself remotely. The only way through
// was copying the CA to a second node and re-issuing the first node's certificate
// from there.
//
// addr empty falls back to the default-route source IP. That is the wrong answer
// on a multi-homed host, which is exactly why --address exists: on a box whose
// cluster network is not the default route, the operator has to say so, and the
// same value belongs in advertise_address.
func mintLocalHostCert(pkiDir, hostName, addr string) error {
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if addr == "" {
		addr = netutil.OutboundIP()
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		// Not an IP (a name, or nothing detectable). GenerateHostCert always adds
		// loopback and the DNS name, so this stays usable for a single-node install
		// while still being honest in the log about what peers will and will not
		// be able to verify.
		slog.Warn("no usable IP address for this host's certificate; peers dialling it by "+
			"address will fail TLS verification. Pass --address <ip>", "host", hostName, "addr", addr)
	}
	slog.Info("generating host certificate", "host", hostName, "address", addr)
	return pki.GenerateHostCert(caPath, caKeyPath,
		filepath.Join(pkiDir, hostName+".crt"), filepath.Join(pkiDir, hostName+".key"),
		hostName, ip)
}

func HostInitLocal(ctx context.Context, hostName, advertiseAddr string, force bool) error {
	// Same hazard as the remote form: the setup script rewrites config.yaml and
	// passes an explicit empty join_peers, so re-running --local against a node
	// that is already in a cluster erases its peer list.
	existingCfg, err := os.ReadFile(daemonConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read the existing %s: %w", daemonConfigPath, err)
	}
	if err := refuseIfAlreadyAMember("this host", existingCfg, force); err != nil {
		return err
	}

	pkiDir := PKIDir()
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return fmt.Errorf("create PKI dir: %w", err)
	}

	// 1. Generate CA if it doesn't exist
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		slog.Info("generating cluster CA")
		if err := pki.GenerateCA(caPath, caKeyPath); err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
	}

	// 2. Generate CLI client certificate if it doesn't exist.
	clientCertPath := filepath.Join(pkiDir, "client.crt")
	clientKeyPath := filepath.Join(pkiDir, "client.key")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("generating CLI client certificate")
		if err := pki.GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}

	// 3. Generate the host certificate.
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")
	if err := mintLocalHostCert(pkiDir, hostName, advertiseAddr); err != nil {
		return err
	}

	// 4. Copy daemon certs to system PKI dir. The daemon host key stays
	// root-owned; the user CLI gets a separate client certificate below.
	remotePKIDir := "/etc/litevirt/pki"
	if err := os.MkdirAll(remotePKIDir, 0700); err != nil {
		return fmt.Errorf("create system PKI dir: %w", err)
	}
	gossipKeyPath, _, err := ensureLocalGossipKey(pkiDir)
	if err != nil {
		return fmt.Errorf("gossip key: %w", err)
	}
	for src, dst := range map[string]string{
		caPath:        filepath.Join(remotePKIDir, "ca.crt"),
		hostCertPath:  filepath.Join(remotePKIDir, "host.crt"),
		hostKeyPath:   filepath.Join(remotePKIDir, "host.key"),
		gossipKeyPath: filepath.Join(remotePKIDir, pki.GossipKeyName),
	} {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", filepath.Base(src), err)
		}
		// The Chmod this used to do afterwards was too late: WriteFile truncates in
		// place, so the key was already in the loose inode. secretfile renames a
		// fresh 0600 file over it instead, and never widens an operator's mode.
		if err := secretfile.Write(dst, data, 0600); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(dst), err)
		}
	}

	// Migration-TLS credentials from the separate migration CA. The daemon
	// installs them for QEMU, so storage migrations with this host are
	// encrypted once a peer is provisioned too.
	// nil: init founds a cluster, so there is no host holding another CA's
	// credentials to ask about.
	migFiles, err := issueMigrationCredentials(pkiDir, hostName, net.ParseIP(advertiseAddr), nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(remoteMigrationDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", remoteMigrationDir, err)
	}
	for _, f := range migFiles {
		data, err := os.ReadFile(f.local)
		if err != nil {
			return fmt.Errorf("read %s: %w", filepath.Base(f.local), err)
		}
		if err := secretfile.Write(f.remote, data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.remote, err)
		}
	}

	if err := installLocalCLIClientBundle(pkiDir); err != nil {
		return err
	}

	// 5. Run setup script locally
	slog.Info("running local host setup")
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}

	// Streamed on stdin, same as the remote form: no file means no path for a
	// local user to pre-create and no write-then-execute window.
	cmd := execCommand("bash", "-s")
	cmd.Stdin = strings.NewReader(setupScript)
	cmd.Env = append(os.Environ(), localInitSetupEnv(hostName, advertiseAddr)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setup script failed: %w", err)
	}

	fmt.Printf("Host %s initialized locally\n", hostName)
	fmt.Println("  Start the daemon: systemctl enable --now litevirt.service")
	fmt.Println("  Or run directly:  litevirt daemon")
	return nil
}

type cliPKITarget struct {
	dir   string
	uid   int
	gid   int
	chown bool
}

func installLocalCLIClientBundle(srcPKIDir string) error {
	targets, err := localCLIClientPKITargets()
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := installCLIClientBundle(srcPKIDir, target); err != nil {
			return err
		}
	}
	return nil
}

func localCLIClientPKITargets() ([]cliPKITarget, error) {
	targets := []cliPKITarget{{dir: PKIDir()}}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" || sudoUser == "root" {
		return targets, nil
	}

	u, err := lookupUserByName(sudoUser)
	if err != nil {
		return nil, fmt.Errorf("resolve sudo user %q for CLI cert install: %w", sudoUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("parse uid for sudo user %q: %w", sudoUser, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("parse gid for sudo user %q: %w", sudoUser, err)
	}

	sudoTarget := cliPKITarget{
		dir:   filepath.Join(u.HomeDir, ".config", "litevirt", "pki"),
		uid:   uid,
		gid:   gid,
		chown: true,
	}

	if os.Getenv("LV_CONFIG_DIR") != "" {
		targets[0].uid = uid
		targets[0].gid = gid
		targets[0].chown = true
	}
	if filepath.Clean(sudoTarget.dir) != filepath.Clean(targets[0].dir) {
		targets = append(targets, sudoTarget)
	}

	return targets, nil
}

func installCLIClientBundle(srcPKIDir string, target cliPKITarget) error {
	if err := os.MkdirAll(target.dir, 0700); err != nil {
		return fmt.Errorf("create CLI PKI dir %s: %w", target.dir, err)
	}
	files := []struct {
		name string
		mode os.FileMode
	}{
		{name: "ca.crt", mode: 0644},
		{name: "client.crt", mode: 0644},
		{name: "client.key", mode: 0600},
	}
	for _, file := range files {
		src := filepath.Join(srcPKIDir, file.name)
		dst := filepath.Join(target.dir, file.name)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read CLI %s: %w", file.name, err)
		}
		// Ownership rides along with the write, on the descriptor. A chown of the
		// PATHNAME afterwards would be a local privilege escalation: root is writing
		// into a directory the target user owns, os.Chown follows symlinks, and the
		// window between publishing the file and chowning it is theirs to use.
		//
		// file.mode is a ceiling: an operator who tightened client.key to 0400 keeps
		// 0400, and a re-run never widens ca.crt/client.crt back to 0644.
		uid, gid := -1, -1
		if target.chown {
			uid, gid = target.uid, target.gid
		}
		if err := secretfile.WriteOwned(dst, data, file.mode, uid, gid); err != nil {
			return fmt.Errorf("write CLI %s: %w", file.name, err)
		}
	}
	if target.chown {
		if err := chownDirNoFollow(target.dir, target.uid, target.gid); err != nil {
			return fmt.Errorf("chown CLI PKI dir %s: %w", target.dir, err)
		}
	}
	return nil
}

// chownDirNoFollow changes the ownership of a DIRECTORY without following a
// symlink at the final path component.
//
// os.Chown resolves the whole path, which is unsafe for a directory whose name
// the target user controls. installCLIClientBundle chowns the CLI PKI
// directory to the invoking user, and localCLIClientPKITargets places it under
// that user's own home -- and MkdirAll neither guarantees the directory is
// newly created nor stops it being REPLACED between the writes and the chown.
// Under `sudo lv host init` the user renames the directory and drops a symlink
// to a root-owned one in its place; root follows it and hands that directory's
// ownership over.
//
// O_NOFOLLOW makes the final component a symlink an ERROR rather than
// something to resolve, O_DIRECTORY makes "is it a directory" part of the open
// instead of an assumption, and chowning the DESCRIPTOR lands the change on
// the inode that was opened rather than on whatever the name means by the time
// the syscall runs. Together they close the window instead of narrowing it.
//
// A var so tests can substitute it; nothing in production reassigns it.
var chownDirNoFollow = func(dir string, uid, gid int) error {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open %s without following symlinks: %w", dir, err)
	}
	defer f.Close()
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	return nil
}

// execCommand wraps exec.Command for testability.
var execCommand = execCommandImpl

func execCommandImpl(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

func parseSSHTarget(target string) (host string, user string, err error) {
	// Parse "user@host" or "user@host:port"
	user = "root"
	host = target
	for i, c := range target {
		if c == '@' {
			user = target[:i]
			host = target[i+1:]
			break
		}
	}
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid SSH target: %s", target)
	}
	return host, user, nil
}

// lookupHost is a seam so resolveHost's address-family preference can be tested
// without depending on what the machine's resolver happens to return.
var lookupHost = net.LookupHost

// resolveHost resolves a hostname to an IP address for use in cert SANs.
//
// It prefers IPv4 and refuses an AAAA-only name. The resolved address does not
// stay in the certificate: it also becomes hosts.address (the address every peer
// dials) and an entry in the gossip seed list, and cluster transport is IPv4-only
// today — gossip and gRPC both bind 0.0.0.0, and advertise_address rejects IPv6
// for the same reason (see internal/daemon/config.go). Returning addrs[0] meant a
// dual-stack name could plant an IPv6 address into the cluster through this path
// even with advertise_address unset, and LookupHost order is not stable, so the
// same command could succeed on one run and produce an unreachable host on the
// next. Fail here, where the operator is watching, rather than at the first peer
// health probe.
func resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("resolve host %q: IPv6 is not supported for cluster "+
				"transport (gossip and gRPC bind 0.0.0.0); use the host's IPv4 address", host)
		}
		return host, nil
	}
	addrs, err := lookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("resolve host %q: %v", host, err)
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return ip.To4().String(), nil
		}
	}
	return "", fmt.Errorf("resolve host %q: only IPv6 addresses found (%v) and cluster "+
		"transport is IPv4-only; give the host an A record or pass its IPv4 address directly",
		host, addrs)
}

// shellEnvPrefix renders env assignments as a shell command prefix, with every
// VALUE single-quoted.
//
// The remote path joins these into one command line and hands it to
// session.Run, which is an SSH exec request: sshd runs it through the login
// shell, so an assignment word undergoes command substitution before the
// command it prefixes ever starts. JOIN_PEERS is built from hosts.address — a
// replicated, peer-writable column — so an unquoted join let any node with SQL
// access execute as root on every host added afterwards, before the daemon,
// PKI or systemd units were in place.
//
// Only the value is quoted. Quoting the KEY too would stop the word being an
// assignment at all.
//
// This is NOT applied to the local path, which passes the same slice as
// cmd.Env, where a shell never sees it and quotes would become part of the
// value.
func shellEnvPrefix(env []string) string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			out = append(out, ssh.ShellQuote(kv))
			continue
		}
		out = append(out, k+"="+ssh.ShellQuote(v))
	}
	return strings.Join(out, " ")
}

// noConfigSentinel is what the remote probe prints when the config genuinely
// does not exist, so that "absent" is a positive statement rather than the
// absence of output.
const noConfigSentinel = "__LV_NO_CONFIG__"

// remoteConfigProbe reads the target's daemon config, distinguishing ABSENT
// from UNREADABLE.
//
// The old probe was `cat <path> 2>/dev/null || true`, which turns both into
// empty output. `-e` answers the existence question separately, and cat's exit
// status is no longer swallowed, so a file that exists but cannot be read
// fails the command instead of reporting nothing.
func remoteConfigProbe(path string) string {
	return fmt.Sprintf("if [ -e %s ]; then cat -- %s; else printf '%%s' '%s'; fi",
		ssh.ShellQuote(path), ssh.ShellQuote(path), noConfigSentinel)
}

// classifyRemoteConfig turns the probe's result into absent/present, refusing
// anything it cannot tell apart.
//
// A failed read is NOT an absence. refuseIfAlreadyAMember is the guard that
// stops `lv host init` running against a live member, and the setup script it
// gates rewrites config.yaml with join_peers: []. A node that loses that file
// loses its peer list AND the signal that stops it minting an admin
// credential -- a later state.db rebuild then mints a fresh admin row that
// wins LWW and replaces the cluster's real admin password on every peer.
//
// So only the sentinel means absent. A non-zero exit, or empty output with no
// sentinel, means the probe did not answer and the run is refused -- with the
// same --force escape hatch the parse failure already has.
func classifyRemoteConfig(out string, runErr error) (string, bool, error) {
	if runErr != nil {
		return "", false, fmt.Errorf("could not read the target's %s: %w\n"+
			"Refusing: an unreadable config is not an absent one, and initializing over a "+
			"live member erases its join_peers. Fix the read, or pass --force if you are "+
			"certain this node is spare", daemonConfigPath, runErr)
	}
	if strings.TrimSpace(out) == noConfigSentinel {
		return "", true, nil
	}
	if strings.TrimSpace(out) == "" {
		return "", false, fmt.Errorf("the probe for the target's %s returned nothing at all, "+
			"not even the absent-marker; refusing rather than assuming there is no config "+
			"there. Pass --force if you are certain this node is spare", daemonConfigPath)
	}
	return out, false, nil
}

// foundingSetupEnv tells the setup script this node is founding a cluster, so it
// may write the founder marker (genesisMarkerScript). Only `lv host init` sets
// it. It is deliberately NOT in setupScriptEnv, which `lv host add` also uses:
// an added node carrying it would mint its own admin credential and replace the
// cluster's (colonelpanik/litevirt#186).
const foundingSetupEnv = "LITEVIRT_GENESIS=1"

// genesisMarkerScript writes or clears the founder marker in the data dir. The
// daemon mints the cluster's first admin credential only while the marker
// exists, and deletes it once it has. It is written only when founding AND the
// data dir shows no sign of earlier membership: no state.db, so re-running
// `lv host init` against a live member does not re-arm a mint for the day its
// state.db is lost; and no capability latch (split_brain_activated.<token>),
// which survives that loss, so a former member re-initialised with --force or
// while its cluster is unreachable does not mint a second admin either. Every other
// setup clears a marker left by a `host init` whose daemon never started.
// LV_DATA_DIR exists for tests; the daemon's data_dir is /var/lib/litevirt.
const genesisMarkerScript = `
# Founder marker: licenses this node's daemon to mint the cluster's first admin.
LV_DATA_DIR="${LV_DATA_DIR:-/var/lib/litevirt}"
# Capability latches survive a state.db loss: a node holding one has run as a
# member and is not founding anything.
if [ "${LITEVIRT_GENESIS:-}" = "1" ] && [ ! -e "${LV_DATA_DIR}/state.db" ] && \
   ! compgen -G "${LV_DATA_DIR}/split_brain_activated.*" > /dev/null; then
    touch "${LV_DATA_DIR}/genesis-pending"
else
    rm -f "${LV_DATA_DIR}/genesis-pending"
fi
`

// localInitSetupEnv is the setup environment for `lv host init --local`.
func localInitSetupEnv(hostName, advertiseAddr string) []string {
	return append(setupScriptEnv(hostName, advertiseAddr, localInitJoinPeers), foundingSetupEnv)
}

// setupScriptEnv is the environment the setup script reads to write the daemon
// config. One place, so the local and remote paths cannot disagree about it —
// they already had, which is how the local path shipped with no advertise_address.
// localInitJoinPeers is the JOIN_PEERS value `lv host init` hands the setup
// script: an empty YAML list, because the local host is starting a cluster and
// has nobody to join.
const localInitJoinPeers = "[]"

func setupScriptEnv(hostName, advertiseAddr, joinPeers string) []string {
	return setupScriptEnvWith(hostName, advertiseAddr, joinPeers, enforcementYAML(daemonConfigPath, joinPeers))
}

// remoteInitSetupCommand is the command line `lv host init <target>` runs the
// setup script under: the same setupScriptEnv the --local form passes, as
// shell-quoted assignments.
//
// It used to be `HOST_NAME=<name> bash -s` and nothing more, so a cluster
// founded from a workstation got no advertise_address and none of the
// new-cluster enforcement defaults — only a --local init ever wrote them.
//
// The block is decided from the TARGET's config (targetCfg, the text the
// member probe read; empty when it had none), never from the invoking
// machine's: that machine may be a workstation, or a node of some other
// cluster whose flags have nothing to do with the one being founded. A target
// re-initialised with --force keeps its own block, as --local keeps the local
// one; a fresh target starts with newClusterEnforcement.
func remoteInitSetupCommand(hostName, hostAddr, targetCfg string) string {
	block := enforcementBlockOf(targetCfg)
	if block == "" {
		block = newClusterEnforcement
	}
	// foundingSetupEnv: `lv host init` founds a cluster, so the script may write
	// the founder marker. setupScriptEnvWith is shared with `lv host add`, which
	// must never carry it.
	env := append(setupScriptEnvWith(hostName, hostAddr, localInitJoinPeers, block), foundingSetupEnv)
	return shellEnvPrefix(env) + " bash -s"
}

// remoteAddSetupCommand is the command line `lv host add` runs the setup script
// under. peersYAML is built from hosts.address, a replicated, peer-writable
// column, and sshd runs this line through the login shell, so every value MUST
// go through shellEnvPrefix. It is a function of its own so a test can run the
// exact line HostAdd sends through a real shell.
func remoteAddSetupCommand(hostName, hostAddr, peersYAML, enforcement string) string {
	return fmt.Sprintf("%s bash -s",
		shellEnvPrefix(setupScriptEnvWith(hostName, hostAddr, peersYAML, enforcement)))
}

// readPeerConfig reads an existing cluster node's daemon config over SSH. It
// returns ok=false when the node answered that it has no config. A seam so the
// add path can be tested without a node to SSH into.
var readPeerConfig = func(sshTarget string) (cfg string, ok bool, err error) {
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return "", false, fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()
	raw, runErr := sc.RunOutput(remoteConfigProbe(daemonConfigPath))
	cfg, absent, err := classifyRemoteConfig(string(raw), runErr)
	if err != nil {
		return "", false, err
	}
	return cfg, !absent, nil
}

// addSetupEnforcement is the enforcement block `lv host add` hands the new
// host: the CLUSTER's block, read from a node of it, verbatim — including when
// the answer is "no block".
//
// Capability latches need config uniformity, so the new host must boot with
// the flags its peers have. This used to read only the invoking machine's
// config and fall back to nothing, so an add run from a workstation (which has
// no daemon config) silently provisioned a host with no enforcement block.
//
// "The cluster" is the one joinPeers came from: the daemon the CLI is talking
// to, which LV_HOST can point at a cluster this machine is not a node of. So
// this machine's own config is an answer only when it provably belongs to that
// cluster. Copied from a node of another cluster, it gave the new host that
// cluster's flags (gossip encryption off, say, so no gossip key was pushed
// either), and `add` reported success for a host that could never join.
//
// In order:
//   - this machine's own daemon config, when its advertise_address is one of
//     joinPeers: it is a node of that cluster;
//   - otherwise each join peer's config over SSH, as sshUser (the user the
//     target is being reached as), first answer wins;
//   - otherwise a refusal. Guessing is what the old fallback did.
func addSetupEnforcement(sshUser string, joinPeers []string) (string, error) {
	var why []string
	block, ok, reason := localEnforcementForPeers(joinPeers)
	if ok {
		return block, nil
	}
	if reason != "" {
		why = append(why, reason)
	}
	for _, p := range joinPeers {
		target := sshTargetForPeer(sshUser, p)
		cfg, ok, rerr := readPeerConfig(target)
		switch {
		case rerr != nil:
			why = append(why, fmt.Sprintf("%s: %v", target, rerr))
		case !ok:
			why = append(why, fmt.Sprintf("%s: no %s", target, daemonConfigPath))
		default:
			return enforcementBlockOf(cfg), nil
		}
	}
	return "", fmt.Errorf("could not read the cluster's enforcement block, which the new host "+
		"must boot with so its flags match its peers': %s. Run `lv host add` on a cluster node, "+
		"or from a machine that can SSH to one as %q", strings.Join(why, "; "), sshUser)
}

// sshTargetForPeer is the SSH target for a join peer ("host:port"), reached as
// sshUser when one is given.
func sshTargetForPeer(sshUser, peer string) string {
	host := peer
	if h, _, err := net.SplitHostPort(peer); err == nil {
		host = h
	}
	if sshUser == "" {
		return host
	}
	return sshUser + "@" + host
}

// localEnforcementForPeers returns this machine's enforcement block when its
// daemon config belongs to the cluster joinPeers name (ok), and otherwise why
// it was not used — empty when there is simply no config, as on a workstation.
// A config without advertise_address proves nothing: its address is
// auto-detected and cannot be matched against the peers.
func localEnforcementForPeers(joinPeers []string) (block string, ok bool, why string) {
	raw, err := os.ReadFile(daemonConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, ""
	}
	if err != nil {
		return "", false, fmt.Sprintf("this machine's %s: %v", daemonConfigPath, err)
	}
	var cfg struct {
		AdvertiseAddress string `yaml:"advertise_address"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return "", false, fmt.Sprintf("this machine's %s could not be parsed: %v", daemonConfigPath, err)
	}
	addr := strings.TrimSpace(cfg.AdvertiseAddress)
	if addr == "" {
		return "", false, fmt.Sprintf("this machine's %s sets no advertise_address, so it "+
			"cannot be shown to belong to the cluster being joined", daemonConfigPath)
	}
	for _, p := range joinPeers {
		host := p
		if h, _, serr := net.SplitHostPort(p); serr == nil {
			host = h
		}
		if host == addr {
			return enforcementBlockOf(string(raw)), true, ""
		}
	}
	return "", false, fmt.Sprintf("this machine (advertise_address %s) is not one of the "+
		"cluster's hosts, so its %s is another cluster's", addr, daemonConfigPath)
}

// setupScriptEnvWith is setupScriptEnv with the enforcement block decided by
// the caller.
func setupScriptEnvWith(hostName, advertiseAddr, joinPeers, enforcement string) []string {
	return []string{
		"HOST_NAME=" + hostName,
		// The address that just went into the certificate SAN. Without it the daemon
		// auto-detects, registers with its default-route source IP — the wrong
		// interface on a multi-homed host — and the operator has to notice and
		// correct it, which needed a genuine RESTART, because init leaves the daemon
		// running and `systemctl start` is then a no-op.
		"ADVERTISE_ADDRESS=" + advertiseAddr,
		"JOIN_PEERS=" + joinPeers,
		"PCI_RESCAN_INTERVAL=0",
		"PCI_UDEV_HOOK=false",
		"SRIOV_MANAGED=false",
		"SRIOV_MAX_VFS=8",
		// The capability-latch model requires config uniformity: a token is
		// advertised only while a host's enforcement.* flag is on, so a host
		// added with a config missing the block silently weakens the cluster.
		// A re-admitted signer with no enforcement.audit_signature wrote
		// unsigned audit rows reported as tampering cluster-wide (2026-08-01),
		// back when the flag defaulted off; it still carries an explicit false.
		// Base64: the remote path joins this env into one shell command line,
		// so a multi-line YAML block must travel as a single token.
		"ENFORCEMENT_B64=" + base64.StdEncoding.EncodeToString([]byte(enforcement)),
	}
}

// newClusterEnforcement is the enforcement block a brand-new cluster starts
// with. The two shared-storage protections, and gossip encryption: every other
// flag stays at its documented default here, because this is a safety floor,
// not a policy.
//
// recovery_claim is the one default written out anyway. This build reads a
// missing key as true, but the build before it reads it as false, and a host
// rolled back to that build after recovery_claim_v1 has latched is not
// WAL-quarantined (it knows the token): with no key it would mint and run
// uncertified recovery proofs, the second owner the token exists to prevent.
// An explicit true survives the rollback (colonelpanik/litevirt#250).
//
// Gossip encryption is on the floor for the same reason as the fences: an
// existing cluster has to walk it on in three rolling restarts because nodes
// two stages apart cannot gossip, but a new cluster has no plaintext node to
// stay compatible with. `lv host init` mints the key and `lv host add` pushes it
// with this block, so every host starts enforced together.
//
// Default-off is the right design for an EXISTING cluster — a flag flip must
// never change behaviour mid-roll, which is what the monotone latch buys. It is
// the wrong design for a cluster that has no behaviour yet. Shipped off, a
// best-effort (lenient SSH) fence that never landed reports success, the
// coordinator reschedules, and a VM with a writable shared disk is started on a
// second host while the first still has it open. The code to refuse that is in
// the binary; it was simply switched off on every cluster ever created.
//
// Safe to write here precisely because a latch needs every enforcement-relevant
// member: a node carrying these flags into an existing cluster changes nothing
// on its own, which is why this is scoped to a new cluster rather than withheld
// out of caution.
const newClusterEnforcement = `enforcement:
  safe_fence_default: true    # a best-effort (unconfirmable) fence must carry an operator
                              # proof (` + "`lv host fence-confirm`" + `) before reschedule/promote
  shared_storage_fence: true  # an ownership transfer of a writable shared disk needs a
                              # proof-grade fence of the source host
  gossip_encryption: true     # gossip is encrypted with pki_dir/gossip.key, and anything
                              # unencrypted or under another key is dropped
  recovery_claim: true        # this build's default, written out so a host rolled back to
                              # an older build (which reads a missing key as false) keeps
                              # enforcing single-winner recovery claims
`

// enforcementYAML decides what enforcement block a host being initialised
// should boot with.
//
// A host JOINING a cluster inherits that cluster's block verbatim, whatever it
// says and even when it says nothing: capability latches require config
// uniformity, and a host that boots with flags its peers lack is the silent
// mid-roll behaviour change the default-off design exists to prevent. The
// migration path for those clusters is a deliberate operator flip, not a
// side effect of adding a node.
//
// A host STARTING one — no join peers, and no enforcement block to inherit —
// gets the safe defaults. There is no existing behaviour to preserve.
func enforcementYAML(path, joinPeers string) string {
	if block := enforcementYAMLFrom(path); block != "" {
		return block
	}
	if hasJoinPeers(joinPeers) {
		return ""
	}
	return newClusterEnforcement
}

// hasJoinPeers reports whether a JOIN_PEERS value names anybody. It arrives
// as YAML, so an empty list — "[]", which is what `lv host init` sends — means
// no peers just as "" does.
func hasJoinPeers(joinPeers string) bool {
	p := strings.TrimSpace(joinPeers)
	return p != "" && strings.ReplaceAll(p, " ", "") != "[]"
}

// enforcementYAMLFrom extracts the `enforcement:` mapping from a daemon config
// verbatim — the key line plus every following line indented deeper. Empty on a
// missing file or absent block: adding a host must never fail on this, and an
// empty value makes the setup script append nothing.
func enforcementYAMLFrom(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return enforcementBlockOf(string(raw))
}

// enforcementBlockOf is enforcementYAMLFrom over a config's text.
func enforcementBlockOf(raw string) string {
	lines := strings.Split(raw, "\n")
	var b strings.Builder
	in := false
	for _, line := range lines {
		if strings.HasPrefix(line, "enforcement:") {
			in = true
			b.WriteString("enforcement:\n")
			continue
		}
		if in {
			if line == "" || (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) {
				break
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if !in {
		return ""
	}
	return b.String()
}

func getSetupScript() (string, error) {
	// Try to read from embedded or local path
	// For now, return the script inline
	return setupScriptContent, nil
}

const setupScriptContent = `#!/bin/bash
set -euo pipefail

echo "=== litevirt host setup ==="

# Install dependencies (skip apt-get update to avoid unrelated repo errors).
if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq qemu-system-x86 qemu-utils libvirt-daemon-system \
        genisoimage bridge-utils haproxy keepalived 2>/dev/null || {
        echo "Some packages may be missing. Trying apt-get update first..."
        apt-get update -qq -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=/dev/null 2>/dev/null || true
        apt-get install -y -qq qemu-system-x86 libvirt-daemon-system \
            genisoimage bridge-utils haproxy keepalived
    }
elif command -v dnf &>/dev/null; then
    dnf install -y qemu-kvm-core libvirt-daemon-kvm \
        genisoimage bridge-utils haproxy keepalived
fi

# Enable libvirtd with TLS for migration (port 16514).
# Uses systemd socket activation — enable libvirtd-tls.socket alongside
# the default sockets. Cert symlinks are created by litevirtd on startup
# (pki.SetupLibvirtTLS), but we also create them here for first boot.
sed -i 's/^#\?listen_tls.*/listen_tls = 1/' /etc/libvirt/libvirtd.conf
mkdir -p /etc/pki/CA /etc/pki/libvirt/private
ln -sf /etc/litevirt/pki/ca.crt /etc/pki/CA/cacert.pem
ln -sf /etc/litevirt/pki/host.crt /etc/pki/libvirt/servercert.pem
ln -sf /etc/litevirt/pki/host.key /etc/pki/libvirt/private/serverkey.pem
ln -sf /etc/litevirt/pki/host.crt /etc/pki/libvirt/clientcert.pem
ln -sf /etc/litevirt/pki/host.key /etc/pki/libvirt/private/clientkey.pem
systemctl enable libvirtd-tls.socket
# Full restart: stop everything, start sockets (including TLS), let service auto-start.
systemctl stop libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket 2>/dev/null
systemctl reset-failed libvirtd 2>/dev/null
sleep 1
systemctl start libvirtd-tls.socket libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket
echo "Enabled libvirtd TLS (port 16514)"

# Create litevirt directories
mkdir -p /var/lib/litevirt/{images,disks,cloudinit}
mkdir -p /etc/litevirt
` + genesisMarkerScript + `
# Libvirt storage pools are auto-created by litevirtd on startup
# (from storage_pools config or a default local pool).

# Configure AppArmor to allow QEMU access to litevirt paths (Ubuntu/Debian).
if [ -d /etc/apparmor.d ] && command -v apparmor_parser &>/dev/null; then
    mkdir -p /etc/apparmor.d/local/abstractions
    if [ ! -f /etc/apparmor.d/local/abstractions/libvirt-qemu ] || \
       ! grep -q '/var/lib/litevirt' /etc/apparmor.d/local/abstractions/libvirt-qemu; then
        echo '/var/lib/litevirt/** rwk,' >> /etc/apparmor.d/local/abstractions/libvirt-qemu
        echo "AppArmor: added litevirt path to libvirt-qemu profile"
        systemctl reload apparmor 2>/dev/null || apparmor_parser -r /etc/apparmor.d/libvirt/TEMPLATE.qemu 2>/dev/null || true
    fi
fi

# Write litevirtd config
cat > /etc/litevirt/config.yaml << CONF
host_name: "${HOST_NAME}"
grpc_port: 7443
metrics_port: 7444
gossip_port: 7946
pki_dir: /etc/litevirt/pki
data_dir: /var/lib/litevirt
${ADVERTISE_ADDRESS:+advertise_address: "${ADVERTISE_ADDRESS}"}
join_peers: ${JOIN_PEERS:-[]}
pci:
  rescan_interval: "${PCI_RESCAN_INTERVAL:-0}"
  udev_hook: ${PCI_UDEV_HOOK:-false}
  sriov:
    managed: ${SRIOV_MANAGED:-false}
    max_vfs_per_pf: ${SRIOV_MAX_VFS:-8}
CONF

# Propagate the adding node's enforcement block: capability latches require
# config uniformity, and a host that boots without the flags silently weakens
# the cluster (a re-admitted signer without enforcement.audit_signature writes
# unsigned audit rows that every node reports as tampering).
if [ -n "${ENFORCEMENT_B64:-}" ]; then
    echo "${ENFORCEMENT_B64}" | base64 -d >> /etc/litevirt/config.yaml
    echo "enforcement config propagated from the adding node"
fi

# pci.udev_hook is deprecated: real-time PCI events are covered by
# pci.rescan_interval, and the old curl-to-REST udev rule was unreliable. This
# installer no longer writes a udev rule; the daemon warns if the flag is set.

# Load vfio-pci kernel module (needed for PCI passthrough).
modprobe vfio-pci 2>/dev/null || true

# Install the systemd units. The text comes from internal/systemdunit so this
# script and the upgrade path cannot disagree; they previously drifted, leaving
# this copy with a tight start limit and a rollback with NO sentinel gate.
cat > ` + systemdunit.MainPath + ` << 'UNIT'
` + systemdunit.Main + `UNIT

cat > ` + systemdunit.RollbackPath + ` << 'UNIT'
` + systemdunit.Rollback + `UNIT

mkdir -p "$(dirname ` + systemdunit.NeedrestartPath + `)"
cat > ` + systemdunit.NeedrestartPath + ` << 'DROPIN'
` + systemdunit.Needrestart + `DROPIN
systemctl daemon-reload
systemctl enable litevirt.service
systemctl restart litevirt.service

echo "=== litevirt setup complete ==="
`

// errNotALocalNode reports that this machine carries no daemon config, so it is
// a workstation running `lv` rather than a cluster node. It is the ONLY reason
// ensureLocalPeer is allowed to fail quietly: there is nothing to back-fill.
// Every other failure means this node IS a member whose seed list is now wrong.
var errNotALocalNode = errors.New("this machine has no litevirt daemon config, so it is not a cluster node")

// refuseIfAlreadyAMember stops `lv host init` from re-initialising a node that
// already belongs to a cluster.
//
// host init rewrites the target's whole config.yaml from the setup-script
// template, and that template writes `join_peers: ${JOIN_PEERS:-[]}` while host
// init sets no JOIN_PEERS. Pointed at a member, it silently erases that node's
// peer list.
//
// The peer list is not only gossip seeding. It is also what distinguishes a node
// that is JOINING a cluster from one FOUNDING it: the daemon declines to mint an
// admin credential when peers are configured. Erasing the field puts the node
// back on the mint path, so a later state.db rebuild mints a fresh admin and
// replicates it over the cluster's own credential.
//
// cfgYAML is the target's current config, or empty when it has none.
func refuseIfAlreadyAMember(target string, cfgYAML []byte, force bool) error {
	if force || len(bytes.TrimSpace(cfgYAML)) == 0 {
		return nil
	}

	var cfg struct {
		JoinPeers []string `yaml:"join_peers"`
	}
	if err := yaml.Unmarshal(cfgYAML, &cfg); err != nil {
		// Not evidence the node is fresh. host init is about to overwrite this
		// file, so "I cannot read what I am replacing" is a reason to stop.
		return fmt.Errorf("%s already has %s and it could not be parsed (%v); "+
			"`lv host init` rewrites that file, so it will not run against a node whose "+
			"current join_peers it cannot read — re-run with --force to overwrite it anyway",
			target, daemonConfigPath, err)
	}
	if len(cfg.JoinPeers) == 0 {
		// A founder legitimately carries an empty list, and re-running init
		// against a half-finished first node is the normal repair.
		return nil
	}

	return fmt.Errorf("%s is already a cluster member: %s lists join_peers (%s). "+
		"`lv host init` rewrites that file from the setup template and would reset "+
		"join_peers to [], which also removes the signal that stops this node minting "+
		"an admin credential of its own. Use `lv host add` to add a node to a cluster, "+
		"or re-run with --force to re-initialise this one anyway",
		target, daemonConfigPath, strings.Join(cfg.JoinPeers, ", "))
}
