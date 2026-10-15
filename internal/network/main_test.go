package network

import (
	"os"
	"testing"
)

// TestMain points the created-bridge records at a temp dir, so a test that
// reaches EnsureBridge's create path never writes into the host's /run, and
// gives the package a host with no address but loopback.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lv-network-test-bridges-")
	if err != nil {
		panic(err)
	}
	createdBridgeDir = dir
	// The runner's own addresses must not decide whether a test's VTEP is
	// "this host" (isLocalAddress): only loopback is, unless a test says so.
	hostAddrs = func() (localAddrs, error) {
		return localAddrs{"127.0.0.1": {Dev: "lo"}}, nil
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
