package grpcapi

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/storage"
)

// TestMain knocks bcrypt cost down to MinCost for the grpcapi suite.
// The package has 880+ tests and many touch CreateUser / Login /
// CreateToken / EnrollTOTP, all of which hash at auth.BcryptCost.
// bcrypt.DefaultCost (10) ≈ 80 ms/hash on modern hardware; under
// `-race` instrumentation it climbs into the hundreds of ms — driving
// total `go test -race` runtime past 4 minutes for this package alone.
// MinCost (4) drops that to ~1 ms/hash with no loss of test coverage,
// because the production cost constant lives in internal/auth/cost.go
// and is exercised separately in production builds.
func TestMain(m *testing.M) {
	auth.BcryptCost = bcrypt.MinCost
	// Most fixtures call the migration helpers as a peer the VM's row does
	// not name as its owner; recording a stub would wait out the replica
	// catch-up for each. The tests of that wait set it themselves.
	moveCatchUp = 0
	// Test disks live in temporary directories, which may be a tmpfs; a
	// layer-2 overlay is refused there in production (pitoverlay.Placement).
	pitoverlay.AllowVolatileForTest()
	// No test reads the machine's own NVIDIA driver: with no nvidia-smi no
	// GPU is in MIG mode. The MIG tests install a fake one.
	pci.SetNvidiaSMI("/nonexistent/litevirt-test/nvidia-smi")
	// No test looks up a real NFS server name: each name gets an address of
	// its own in the benchmarking range. Tests that need names to share an
	// address, or to fail, override it themselves.
	storage.OverrideNFSResolverForTest(func(_ context.Context, host string) ([]netip.Addr, error) {
		h := fnv.New32a()
		h.Write([]byte(host))
		v := h.Sum32()
		return []netip.Addr{netip.AddrFrom4([4]byte{198, 18 + byte(v>>16)&1, byte(v >> 8), byte(v)})}, nil
	})
	before := packageDirEntries()
	code := m.Run()
	// No test may write relative to the working directory (the package dir):
	// concurrent test processes share it, so one process's promote marker is
	// another's to delete. A server without a dataDir does exactly that.
	if code == 0 {
		for name := range packageDirEntries() {
			if !before[name] {
				fmt.Fprintf(os.Stderr, "FAIL: tests left %q in the package directory; a test server has no per-test dataDir\n", name)
				code = 1
			}
		}
	}
	os.Exit(code)
}

func packageDirEntries() map[string]bool {
	out := map[string]bool{}
	ents, _ := os.ReadDir(".")
	for _, e := range ents {
		out[e.Name()] = true
	}
	return out
}
