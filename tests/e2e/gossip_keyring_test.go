package e2e

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/memberlist"

	"github.com/litevirt/litevirt/internal/pki"
)

// Gossip encryption on a live cluster (colonelpanik/litevirt#259, step 2).
//
// The fleet tier proves the stage machine and the rotation against real
// memberlist in one process. What it cannot prove is that the DEPLOYED daemons
// are running the keyring the files on disk say they are, and that a real
// peer's gossip port refuses a stranger. These read the daemon's own PKI dir,
// so they run on a cluster node (localMode) as root.

const e2ePKIDir = "/etc/litevirt/pki"

func localGossipState(t *testing.T) pki.GossipKeyringState {
	t.Helper()
	if !localMode {
		t.Skip("needs the local daemon's PKI dir; run this suite on a cluster node")
	}
	b, err := os.ReadFile(e2ePKIDir + "/" + pki.GossipKeyringStateName)
	if os.IsNotExist(err) {
		t.Skip("no gossip-keyring.state: the daemon predates gossip keyrings")
	}
	if err != nil {
		t.Fatalf("read the gossip state file: %v", err)
	}
	s, err := pki.ParseGossipKeyringState(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func localGossipKeyring(t *testing.T) [][]byte {
	t.Helper()
	ring, err := pki.LoadGossipKeyring(e2ePKIDir + "/" + pki.GossipKeyName)
	if err != nil {
		t.Fatalf("load the local gossip key (run as root): %v", err)
	}
	return ring
}

// TestGossipKeyring_DaemonUsesTheKeyOnDisk: the daemon reports, by key ID, the
// keyring it is using. On a keyed node that must be exactly gossip.key — the
// file reload is what rotation relies on, and a daemon silently holding an
// older keyring is how a rotation's last phase would cut it off.
func TestGossipKeyring_DaemonUsesTheKeyOnDisk(t *testing.T) {
	requireHosts(t, 1)
	s := localGossipState(t)
	if s.Mode == "off" {
		t.Skipf("gossip encryption is off on %s", localHost)
	}
	want := pki.GossipKeyIDs(localGossipKeyring(t))
	if strings.Join(s.Keys, ",") != strings.Join(want, ",") {
		t.Fatalf("%s is live on %v but gossip.key holds %v", localHost, s.Keys, want)
	}
	t.Logf("%s: gossip stage %s, primary %s, %d rejected", localHost, s.Mode, s.Primary, s.Rejected)
}

// probeJoin joins peer as a bare memberlist stranger. plaintext keeps the
// keyring but sends unencrypted, as the install stage does.
func probeJoin(t *testing.T, name string, ring [][]byte, plaintext bool, peer string) error {
	t.Helper()
	cfg := memberlist.DefaultLANConfig()
	cfg.Name = name
	cfg.BindAddr = "0.0.0.0"
	cfg.BindPort = 0
	cfg.LogOutput = io.Discard
	if ring != nil {
		kr, err := memberlist.NewKeyring(ring[1:], ring[0])
		if err != nil {
			t.Fatal(err)
		}
		cfg.Keyring = kr
		if plaintext {
			cfg.GossipVerifyIncoming, cfg.GossipVerifyOutgoing = false, false
		}
	}
	ml, err := memberlist.Create(cfg)
	if err != nil {
		t.Fatalf("create probe: %v", err)
	}
	defer ml.Shutdown()
	_, err = ml.Join([]string{peer})
	return err
}

// TestGossipKeyring_EnforcedPeersRefusePlaintext sends plaintext joins to every
// host's gossip port and requires each to refuse them. Admission refuses the
// probe's name anyway, so a failed join alone proves nothing; the control is a
// probe that holds the cluster key and encrypts, which the peer answers (it
// sends its state before it decides whether to admit the sender). The sharp
// case is the probe that HOLDS the key but sends plaintext: it could read an
// encrypted answer, so only the peer refusing plaintext — the enforced stage,
// not staged — stops it. An unkeyed probe is refused by staged peers too.
// (internal/corrosion TestGossip_EnforcedNodeAnswersAKeyedStrangerOnly pins
// this reading of memberlist.)
func TestGossipKeyring_EnforcedPeersRefusePlaintext(t *testing.T) {
	requireHosts(t, 1)
	if s := localGossipState(t); s.Mode != "enforced" {
		t.Skipf("gossip encryption is %s on %s, not enforced", s.Mode, localHost)
	}
	ring := localGossipKeyring(t)
	for _, h := range hostNames {
		peer := net.JoinHostPort(hostRecordAddress(t, h), "7946")
		if err := probeJoin(t, uniqueName("gossip-keyed"), ring, false, peer); err != nil {
			t.Errorf("control: a probe holding the cluster key could not reach %s (%s): %v — "+
				"the refusals below would prove nothing", h, peer, err)
			continue
		}
		if err := probeJoin(t, uniqueName("gossip-keyed-plain"), ring, true, peer); err == nil {
			t.Errorf("%s (%s) answered a plaintext join from a probe holding the key: it is accepting "+
				"plaintext, so it is not at gossip_encryption: true", h, peer)
		}
		if err := probeJoin(t, uniqueName("gossip-plain"), nil, false, peer); err == nil {
			t.Errorf("%s (%s) answered a gossip join from a probe without the key", h, peer)
		}
	}
}
