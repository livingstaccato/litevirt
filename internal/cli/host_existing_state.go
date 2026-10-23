package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/ssh"
	"gopkg.in/yaml.v3"
)

// stateProbe is what refuseForeignState reads on the target machine.
// addRemote satisfies it, over SSH and over a test's directory.
type stateProbe interface {
	ReadFile(path string) (data []byte, ok bool, err error)
	Shell(kind, cmd string) ([]byte, error)
	Path(path string) string
	Unpath(path string) string
}

// defaultRemoteDataDir is the daemon's data_dir when the config names none
// (daemon.LoadConfig's default).
const defaultRemoteDataDir = "/var/lib/litevirt"

// stateProbeKind and daemonProbeKind are the Shell kinds refuseForeignState
// runs: the data dir's database and latch files, and the daemon's unit.
const (
	stateProbeKind  = "existing-state"
	daemonProbeKind = "existing-daemon"
)

// refuseForeignState refuses a machine that holds litevirt state of a
// cluster other than the one whose CA certificate is ourCA (nil: this
// machine has no cluster CA yet, so no state on the target can be its).
//
// `lv host add` and `lv host init root@...` push this cluster's CA and a
// host identity, and keep what the machine's data dir holds. Over a
// machine that founded its own cluster (`lv host init --local`), that
// merges two clusters: its state.db brings its own users (a second
// `admin`), its own audit genesis and its own capability latches, and its
// gossip key stays in force.
//
// What proves the state is this cluster's is the machine holding this
// cluster's CA certificate. A removed host (`lv host rm` leaves its files
// in place) does, and is re-added. A machine that holds another CA, or a
// database, latches or a running daemon with no CA certificate at all, is
// refused: nothing tells whose cluster the state is, and there is no
// override. The way forward is to move the state aside, or to join in the
// other direction.
//
// verb names the command in the refusal ("add", "init").
func refuseForeignState(m stateProbe, ourCA []byte, target, verb string) error {
	refuse := func(found []string) error {
		return fmt.Errorf("refusing to %s %s: it holds litevirt state that is not this cluster's:\n  - %s\n"+
			"It looks like a machine that founded or joined another cluster (for instance with `lv host init --local`). "+
			"Going ahead would merge that cluster's users, audit history, capability latches and gossip key into this one. "+
			"Nothing was changed. Either:\n"+
			"  - make it a new machine: on it, `systemctl stop litevirt; systemctl disable litevirt`, then move "+
			"/etc/litevirt, the data dir (%s by default), /root/.config/litevirt and /etc/pki/qemu aside "+
			"(nothing needs deleting), and run this command again; or\n"+
			"  - join in the other direction: add this cluster's machines to the cluster that one founded",
			verb, target, strings.Join(found, "\n  - "), defaultRemoteDataDir)
	}

	cfgPath := daemonConfigPathOnTarget
	pkiDirs := []string{remotePKIDir}
	dataDir := defaultRemoteDataDir
	raw, ok, err := m.ReadFile(cfgPath)
	if err != nil {
		return refuse([]string{fmt.Sprintf("%s could not be read (%v), so where its state lives is unknown", cfgPath, err)})
	}
	if ok {
		var cfg struct {
			DataDir string `yaml:"data_dir"`
			PKIDir  string `yaml:"pki_dir"`
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return refuse([]string{fmt.Sprintf("%s does not parse (%v), so where its state lives is unknown", cfgPath, err)})
		}
		if cfg.DataDir != "" {
			dataDir = path.Clean(cfg.DataDir)
		}
		if p := path.Clean(cfg.PKIDir); cfg.PKIDir != "" && p != remotePKIDir {
			pkiDirs = append(pkiDirs, p)
		}
	}

	ours := parseCerts(ourCA)
	var found []string
	proven := false
	for _, dir := range pkiDirs {
		caPath := path.Join(dir, "ca.crt")
		b, ok, err := m.ReadFile(caPath)
		if err != nil {
			return refuse([]string{fmt.Sprintf("%s could not be read (%v)", caPath, err)})
		}
		if !ok {
			if _, keyOK, err := m.ReadFile(path.Join(dir, "ca.key")); err != nil || keyOK {
				found = append(found, fmt.Sprintf("a CA key %s with no CA certificate beside it", path.Join(dir, "ca.key")))
			}
			continue
		}
		theirs := parseCerts(b)
		switch {
		case len(theirs) == 0:
			found = append(found, fmt.Sprintf("%s, which holds no certificate this command can read", caPath))
		case !sameCA(ours, theirs):
			found = append(found, fmt.Sprintf("%s, a CA that is not this cluster's (%s)", caPath, theirs[0].Subject.String()))
		default:
			proven = true
		}
	}

	// A database or latch, or a running daemon, is fine under this
	// cluster's CA (a removed host being re-added), and is someone else's
	// under any other, or none.
	var state []string
	out, err := m.Shell(stateProbeKind, stateFilesCmd(m.Path(dataDir)))
	if err != nil {
		return refuse([]string{fmt.Sprintf("its data dir %s could not be inspected (%v)", dataDir, err)})
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			state = append(state, m.Unpath(line))
		}
	}
	out, err = m.Shell(daemonProbeKind, daemonActiveCmd)
	if err != nil {
		return refuse([]string{fmt.Sprintf("whether litevirt.service runs could not be told (%v)", err)})
	}
	running := daemonRunning(string(out))
	if proven {
		// The host certificate, too, must be this cluster's when state is kept.
		if len(state) > 0 || running {
			crt := path.Join(remotePKIDir, "host.crt")
			if b, ok, err := m.ReadFile(crt); err != nil {
				return refuse([]string{fmt.Sprintf("%s could not be read (%v)", crt, err)})
			} else if ok && !issuedBy(b, ours) {
				found = append(found, fmt.Sprintf("%s, a host certificate this cluster's CA did not issue", crt))
			}
		}
	} else {
		for _, s := range state {
			found = append(found, fmt.Sprintf("%s, with no CA certificate of this cluster's beside it", s))
		}
		if running {
			found = append(found, "a running litevirt.service, with no CA certificate of this cluster's on the machine")
		}
	}
	if len(found) > 0 {
		return refuse(found)
	}
	return nil
}

// daemonConfigPathOnTarget is where the daemon's config lives on a machine
// litevirt was set up on.
const daemonConfigPathOnTarget = "/etc/litevirt/config.yaml"

// stateFilesCmd lists the files in dataDir (as the shell names it) that
// show a daemon has run there: its database and its capability latches.
func stateFilesCmd(dataDir string) string {
	q := ssh.ShellQuote(dataDir)
	return fmt.Sprintf(`d=%s; for f in "$d"/state.db "$d"/state.db-wal "$d"/split_brain_activated.*; do `+
		`if [ -e "$f" ]; then printf '%%s\n' "$f"; fi; done`, q)
}

// daemonActiveCmd prints litevirt.service's state, or "none" on a machine
// without systemd (where setup could not have installed it).
const daemonActiveCmd = `if command -v systemctl >/dev/null 2>&1; then ` +
	`systemctl is-active litevirt.service 2>/dev/null || true; else echo none; fi`

// daemonRunning reads daemonActiveCmd's output: anything but a stopped or
// absent unit counts as running.
func daemonRunning(out string) bool {
	switch strings.TrimSpace(out) {
	case "inactive", "failed", "unknown", "none", "":
		return false
	}
	return true
}

func parseCerts(b []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return certs
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
}

func sameCA(ours, theirs []*x509.Certificate) bool {
	for _, a := range ours {
		for _, b := range theirs {
			if bytes.Equal(a.Raw, b.Raw) {
				return true
			}
		}
	}
	return false
}

func issuedBy(certPEM []byte, cas []*x509.Certificate) bool {
	certs := parseCerts(certPEM)
	if len(certs) == 0 {
		return false
	}
	for _, ca := range cas {
		if certs[0].CheckSignatureFrom(ca) == nil {
			return true
		}
	}
	return false
}

// localCA is this machine's cluster CA certificate in pkiDir, nil when it
// has none.
func localCA(pkiDir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}
