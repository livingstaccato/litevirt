package cli

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// envFromCommand pulls KEY='value' assignments off the front of a remote setup
// command line, undoing shellEnvPrefix's single-quoting.
func envFromCommand(t *testing.T, cmd string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, word := range strings.Fields(cmd) {
		k, v, ok := strings.Cut(word, "=")
		if !ok {
			break // "bash" — the assignments are over
		}
		out[k] = strings.Trim(v, "'")
	}
	return out
}

func decodedEnforcement(t *testing.T, env map[string]string) string {
	t.Helper()
	b64, ok := env["ENFORCEMENT_B64"]
	if !ok {
		t.Fatalf("remote setup command carries no ENFORCEMENT_B64: %v", env)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode ENFORCEMENT_B64: %v", err)
	}
	return string(raw)
}

// Remote `lv host init` hands the setup script the same environment the local
// form does. It used to run `HOST_NAME=<name> bash -s` and nothing else, so a
// cluster created from a workstation got no advertise_address, and none of the
// new-cluster fence defaults that only `--local` init ever wrote.
func TestRemoteInitSetupCommand_CarriesTheSetupEnvironment(t *testing.T) {
	// The INVOKING machine's config is somebody else's cluster: remote init must
	// not copy its block onto the node it is founding.
	useConfig(t, "enforcement:\n  safe_fence_default: false\n  hlc_lww: true\n")

	env := envFromCommand(t, remoteInitSetupCommand("node-1", "10.0.0.1", ""))

	if env["HOST_NAME"] != "node-1" {
		t.Errorf("HOST_NAME = %q, want node-1", env["HOST_NAME"])
	}
	if env["ADVERTISE_ADDRESS"] != "10.0.0.1" {
		t.Errorf("ADVERTISE_ADDRESS = %q, want the address put in the certificate SAN", env["ADVERTISE_ADDRESS"])
	}
	if env["JOIN_PEERS"] != "[]" {
		t.Errorf("JOIN_PEERS = %q, want [] for the founding node", env["JOIN_PEERS"])
	}
	block := decodedEnforcement(t, env)
	for _, want := range []string{"safe_fence_default: true", "shared_storage_fence: true"} {
		if !strings.Contains(block, want) {
			t.Errorf("remote init's enforcement block is missing %q; got:\n%s", want, block)
		}
	}
	if strings.Contains(block, "hlc_lww") {
		t.Errorf("remote init copied the invoking machine's enforcement block onto the new cluster:\n%s", block)
	}
}

// A target re-initialised with --force keeps its own enforcement block, as the
// --local form keeps the local one.
func TestRemoteInitSetupCommand_KeepsTheTargetsOwnBlock(t *testing.T) {
	useConfig(t, "")
	block := decodedEnforcement(t, envFromCommand(t,
		remoteInitSetupCommand("node-1", "10.0.0.1", "host_name: node-1\nenforcement:\n  audit_signature: true\n")))
	if block != "enforcement:\n  audit_signature: true\n" {
		t.Errorf("block = %q, want the target's own", block)
	}
}

func stubPeerConfig(t *testing.T, fn func(target string) (string, bool, error)) *[]string {
	t.Helper()
	old := readPeerConfig
	t.Cleanup(func() { readPeerConfig = old })
	var asked []string
	readPeerConfig = func(target string) (string, bool, error) {
		asked = append(asked, target)
		return fn(target)
	}
	return &asked
}

// `lv host add` from a machine that is not a cluster node reads the block from a
// node that is. It used to read only the invoking machine's config, found none
// on a workstation, and provisioned the new host with no enforcement block at
// all — the silent config drift that holds latches off.
func TestAddSetupEnforcement_FromAWorkstationReadsAClusterNode(t *testing.T) {
	useConfig(t, "") // no local daemon config: a workstation
	asked := stubPeerConfig(t, func(string) (string, bool, error) {
		return "host_name: node-1\nenforcement:\n  shared_storage_fence: true\n", true, nil
	})

	block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946"})
	if err != nil {
		t.Fatalf("addSetupEnforcement: %v", err)
	}
	if block != "enforcement:\n  shared_storage_fence: true\n" {
		t.Errorf("block = %q, want the cluster node's", block)
	}
	if len(*asked) == 0 || (*asked)[0] != "root@10.0.0.1" {
		t.Errorf("read the config from %v, want root@10.0.0.1", *asked)
	}
}

// A cluster whose nodes carry no block is still an answer: the new host gets
// none, exactly like its peers.
func TestAddSetupEnforcement_AClusterWithNoBlockGivesNone(t *testing.T) {
	useConfig(t, "")
	stubPeerConfig(t, func(string) (string, bool, error) { return "host_name: node-1\n", true, nil })

	block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946"})
	if err != nil || block != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", block, err)
	}
}

// When no cluster node's config can be read, add refuses rather than
// provisioning a host with a guessed — in practice, an empty — block.
func TestAddSetupEnforcement_RefusesWhenNoClusterConfigCanBeRead(t *testing.T) {
	useConfig(t, "")
	stubPeerConfig(t, func(string) (string, bool, error) { return "", false, errors.New("connection refused") })

	block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946", "10.0.0.2:7946"})
	if err == nil {
		t.Fatalf("add proceeded with enforcement block %q although no cluster node's config could be read", block)
	}
	if !strings.Contains(err.Error(), "enforcement") {
		t.Errorf("the refusal does not say what it could not read: %v", err)
	}
}

// Run from a node of the join peers' cluster — its advertise_address is one of
// them — add uses that node's own config and SSHes nowhere.
func TestAddSetupEnforcement_OnAClusterNodeUsesItsOwnConfig(t *testing.T) {
	useConfig(t, "advertise_address: 10.0.0.1\nenforcement:\n  audit_signature: true\n")
	asked := stubPeerConfig(t, func(string) (string, bool, error) {
		return "", false, errors.New("must not be called")
	})

	block, err := addSetupEnforcement("root", []string{"10.0.0.2:7946", "10.0.0.1:7946"})
	if err != nil || block != "enforcement:\n  audit_signature: true\n" {
		t.Errorf("got (%q, %v), want this node's block", block, err)
	}
	if len(*asked) != 0 {
		t.Errorf("read a peer's config (%v) although this node has its own", *asked)
	}
}

// The CLI can address a different cluster from the one this machine is a node
// of (LV_HOST), and joinPeers then come from THAT cluster. This node's block
// belongs to its own cluster and must not be copied onto the new host: here it
// would carry gossip encryption off into a cluster that enforces it, and no
// gossip key would be pushed, so the new host could never join.
func TestAddSetupEnforcement_ANodeOfAnotherClusterReadsTheJoinPeers(t *testing.T) {
	useConfig(t, "host_name: a1\nadvertise_address: 10.0.0.1\njoin_peers: [\"10.0.0.2:7946\"]\n"+
		"enforcement:\n  gossip_encryption: off\n")
	asked := stubPeerConfig(t, func(string) (string, bool, error) {
		return "host_name: b1\nenforcement:\n  gossip_encryption: enforce\n", true, nil
	})

	block, err := addSetupEnforcement("root", []string{"10.9.0.1:7946", "10.9.0.2:7946"})
	if err != nil {
		t.Fatalf("addSetupEnforcement: %v", err)
	}
	if block != "enforcement:\n  gossip_encryption: enforce\n" {
		t.Errorf("block = %q, want the join peers' cluster's, not this node's", block)
	}
	if len(*asked) == 0 || (*asked)[0] != "root@10.9.0.1" {
		t.Errorf("read the config from %v, want root@10.9.0.1", *asked)
	}
}

// A node of another cluster that cannot reach the join peers' configs refuses
// rather than falling back to its own block.
func TestAddSetupEnforcement_ANodeOfAnotherClusterRefusesWhenPeersAreUnreadable(t *testing.T) {
	useConfig(t, "advertise_address: 10.0.0.1\nenforcement:\n  gossip_encryption: off\n")
	stubPeerConfig(t, func(string) (string, bool, error) { return "", false, errors.New("connection refused") })

	block, err := addSetupEnforcement("root", []string{"10.9.0.1:7946"})
	if err == nil {
		t.Fatalf("add proceeded with block %q from this machine, which is not a node of the join peers' cluster", block)
	}
}

// A local config that names no advertise_address proves nothing about which
// cluster it belongs to, so the peers are read.
func TestAddSetupEnforcement_ALocalConfigWithNoAdvertiseAddressReadsThePeers(t *testing.T) {
	useConfig(t, "enforcement:\n  audit_signature: true\n")
	stubPeerConfig(t, func(string) (string, bool, error) {
		return "enforcement:\n  shared_storage_fence: true\n", true, nil
	})

	block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946"})
	if err != nil || block != "enforcement:\n  shared_storage_fence: true\n" {
		t.Errorf("got (%q, %v), want the peer's block", block, err)
	}
}
