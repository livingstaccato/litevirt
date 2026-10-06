package grpcapi

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// fakeNFSResolver answers from names; any other name does not resolve.
func fakeNFSResolver(t *testing.T, names map[string][]string) {
	t.Helper()
	t.Cleanup(storage.OverrideNFSResolverForTest(func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{a}, nil
		}
		var out []netip.Addr
		for _, s := range names[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("lookup %s: no such host", host)
		}
		return out, nil
	}))
}

// IMP-1: an export's server is the set of addresses it resolves to at create.
// Two servers that share any address are one server, whatever their names.
func TestPoolRound4_ServerIdentityIsItsAddresses(t *testing.T) {
	names := map[string][]string{
		"nas":          {"10.0.0.5"},
		"nas.corp.lan": {"10.0.0.9", "10.0.0.5"},
		"other":        {"10.0.0.7"},
	}
	for source, shared := range map[string]bool{
		"10.0.0.5:/x":       true,
		"nas.corp.lan:/x":   true,
		"nas.corp.lan:/x/y": true,
		"nas.corp.lan:/":    true,
		"other:/x":          false,
		"10.0.0.9:/y":       false,
	} {
		t.Run(source, func(t *testing.T) {
			fakeNFSResolver(t, names)
			s := newPoolTestServer(t)
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: "host-b", Name: "first", Driver: "nfs", Source: "nas:/x", Project: "acme"})
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
				Name: "second", Driver: "nfs", Source: source, Target: t.TempDir(), Options: noPrepare, Project: "bravo"})
			if shared {
				wantSharedRefusal(t, source+" beside nas:/x", err)
			} else {
				notSharedRefusal(t, source+" beside nas:/x", err)
			}
		})
	}
}

// IMP-1: a server whose name does not resolve cannot be told apart from any
// other, so the create is refused — the new pool's, or another NFS pool's
// whose export path overlaps the new one's (another pool's server is not
// named: the pool may be another project's).
func TestPoolRound4_UnresolvableServerIsRefusedAtCreate(t *testing.T) {
	for name, tc := range map[string]struct{ existing, source string }{
		"the new pool's server":   {"", "ghost:/x"},
		"another pool's server":   {"ghost:/x", "nas:/x/y"},
		"another host's pool's":   {"ghost:/", "nas:/y"},
		"the new pool, no others": {"", "ghost:/"},
	} {
		t.Run(name, func(t *testing.T) {
			fakeNFSResolver(t, map[string][]string{"nas": {"10.0.0.5"}})
			s := newPoolTestServer(t)
			if tc.existing != "" {
				host := s.hostName
				if strings.HasPrefix(name, "another host") {
					host = "host-b"
				}
				upsertPool(t, s, corrosion.StoragePoolRecord{HostName: host, Name: "first", Driver: "nfs", Source: tc.existing, Target: t.TempDir()})
			}
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
				Name: "second", Driver: "nfs", Source: tc.source, Target: t.TempDir(), Options: noPrepare})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "resolve") {
				t.Fatalf("got %v, want FailedPrecondition naming the failed resolve", err)
			}
			if tc.existing != "" && strings.Contains(err.Error(), "ghost") {
				t.Errorf("the refusal names another pool's server: %v", err)
			}
			if _, ok, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "second"); ok {
				t.Fatalf("the refused pool was persisted")
			}
		})
	}
}

// IMP-1: another pool's server is resolved only when the export paths overlap;
// one that does not resolve does not block an export it could not share.
func TestPoolRound4_UnresolvableServerOfADisjointExportDoesNotBlock(t *testing.T) {
	fakeNFSResolver(t, map[string][]string{"nas": {"10.0.0.5"}})
	s := newPoolTestServer(t)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: "host-b", Name: "first", Driver: "nfs", Source: "ghost:/x"})
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "second", Driver: "nfs", Source: "nas:/y", Target: t.TempDir(), Options: noPrepare})
	notSharedRefusal(t, "nas:/y beside ghost:/x", err)
	if strings.Contains(err.Error(), "resolve") {
		t.Fatalf("a disjoint export's unresolvable server blocked the create: %v", err)
	}
}
