package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// (re-review rr2 5) A target not in clean form is refused interactively with
// the clean form it would be used as; a field longer than trustFieldMax is
// shown cut and refused; --expect-* stays exact for both.
//
// Mutations: drop the clean-form check — red; drop the length check — red;
// print fields uncut — red.
func TestPoolTrust_CLIRefusesNonCleanAndOverlongFields(t *testing.T) {
	ctx := context.Background()
	h := &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Target: "/srv/vmpool/../polkit"}}
	err := runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("y\n"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `"/srv/polkit"`) || len(h.confirmed) != 0 {
		t.Fatalf("a non-clean target: err=%v sent=%d, want a refusal naming /srv/polkit", err, len(h.confirmed))
	}
	long := "/srv/" + strings.Repeat("a", 3000)
	h = &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Target: long}}
	var out bytes.Buffer
	err = runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("y\n"), &out)
	if err == nil || !strings.Contains(err.Error(), "bytes") || len(h.confirmed) != 0 {
		t.Fatalf("an overlong target: err=%v sent=%d, want a refusal", err, len(h.confirmed))
	}
	if strings.Contains(out.String(), long) || !strings.Contains(out.String(), "more bytes") {
		t.Fatal("an overlong field was printed whole")
	}
	h = &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Target: long}}
	if err := runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{driver: "dir", target: long}, false, nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("the exact overlong value with --expect-target: %v", err)
	}
}
