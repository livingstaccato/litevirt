package grpcapi

import (
	"context"
	"hash/fnv"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/auth"
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
	// No test looks up a real NFS server name: each name gets an address of
	// its own in the benchmarking range. Tests that need names to share an
	// address, or to fail, override it themselves.
	storage.OverrideNFSResolverForTest(func(_ context.Context, host string) ([]netip.Addr, error) {
		h := fnv.New32a()
		h.Write([]byte(host))
		v := h.Sum32()
		return []netip.Addr{netip.AddrFrom4([4]byte{198, 18 + byte(v>>16)&1, byte(v >> 8), byte(v)})}, nil
	})
	os.Exit(m.Run())
}
