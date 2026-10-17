package grpcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// One claim whose release exhausts its budget (NetBox not answering) costs
// neither the next claim its release nor itself its orphan enqueue
// (re-review N9).
//
// Mutation: one budget for the whole loop, as before — the second release
// and the enqueue fail on the expired context, red.
func TestClaimSet_ASlowReleaseDoesNotSpendTheNextClaimsBudget(t *testing.T) {
	prevRelease := claimReleaseTimeout
	claimReleaseTimeout = 300 * time.Millisecond
	t.Cleanup(func() { claimReleaseTimeout = prevRelease })

	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var released []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/ipam/ip-addresses/"), "/")
		if id == "41" {
			select { // NetBox does not answer
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		mu.Lock()
		released = append(released, id)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := netbox.New(netbox.Config{BaseURL: srv.URL, TokenPath: token, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{hostName: "test-host", db: db, netbox: client}
	cs := &claimSet{srv: s}
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.100", OwnerKind: "vm", NetBoxID: 41, Identity: "id-1"})
	cs.add(claimedAddr{Network: "n", IP: "10.0.5.101", OwnerKind: "vm", NetBoxID: 42, Identity: "id-2"})
	cs.releaseAll(context.Background())

	mu.Lock()
	got := append([]string(nil), released...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "42" {
		t.Errorf("released %v; want the second claim released after the first timed out", got)
	}
	items, err := corrosion.DrainSyncQueue(context.Background(), db, "orphan", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "id-1" {
		t.Errorf("orphan checks = %v; want the timed-out claim named", items)
	}
}
