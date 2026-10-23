package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// trustHost stands in for the pool's host: its row, which a forger may flip
// between the preview and the confirmation, and the confirmations it got.
type trustHost struct {
	pb.LiteVirtClient
	row       *pb.StoragePool
	flipTo    string // after the preview, the row's target becomes this
	confirmed []*pb.TrustStoragePoolRequest
}

func (h *trustHost) TrustStoragePool(_ context.Context, req *pb.TrustStoragePoolRequest, _ ...grpc.CallOption) (*pb.TrustStoragePoolResponse, error) {
	if req.GetPreview() {
		out := &pb.TrustStoragePoolResponse{Pool: &pb.StoragePool{Name: h.row.Name, Host: h.row.Host, Driver: h.row.Driver, Source: h.row.Source, Target: h.row.Target},
			Why: "this host neither created nor confirmed it"}
		if h.flipTo != "" {
			h.row.Target = h.flipTo
		}
		return out, nil
	}
	h.confirmed = append(h.confirmed, req)
	// Compared as the host compares (pooltrust.BindingOf cleans the target).
	if req.GetDriver() != h.row.Driver || req.GetSource() != h.row.Source || cleanOrEmpty(req.GetTarget()) != cleanOrEmpty(h.row.Target) {
		return nil, status.Error(codes.FailedPrecondition, "the row differs")
	}
	return &pb.TrustStoragePoolResponse{TrustedAs: "created or confirmed on this host"}, nil
}

func newTrustHost() *trustHost {
	return &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Target: "/srv/data"}}
}

// (review r0 I1) What is sent is what the operator confirmed, never a fresh
// read: a row flipped after the preview reaches the host as the value shown,
// and the host refuses it.
//
// Mutation: re-read the row (a second preview) after the confirmation and
// send that — the flipped target is sent and accepted, red.
func TestPoolTrust_CLISendsWhatWasConfirmed(t *testing.T) {
	h := newTrustHost()
	h.flipTo = "/var/lib/polkit-1/localauthority/50-local.d"
	var out bytes.Buffer
	err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("y\n"), &out)
	if err == nil {
		t.Fatal("the flipped row was trusted")
	}
	if len(h.confirmed) != 1 || h.confirmed[0].GetTarget() != "/srv/data" {
		t.Fatalf("confirmations sent = %v, want one naming the shown /srv/data", h.confirmed)
	}
	if !strings.Contains(out.String(), "/srv/data") {
		t.Fatalf("the shown row does not name its target:\n%s", out.String())
	}
}

// Interactively, nothing but y/yes confirms.
//
// Mutation: treat an empty answer as yes — red.
func TestPoolTrust_CLIInteractiveNeedsYes(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "no\n", ""} {
		h := newTrustHost()
		if err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader(answer), &bytes.Buffer{}); err == nil || len(h.confirmed) != 0 {
			t.Errorf("answer %q: err=%v sent=%d, want not confirmed and nothing sent", answer, err, len(h.confirmed))
		}
	}
	h := newTrustHost()
	if err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("yes\n"), &bytes.Buffer{}); err != nil || len(h.confirmed) != 1 {
		t.Fatalf("yes: err=%v sent=%d", err, len(h.confirmed))
	}
}

// Without a terminal it refuses unless the checked values are given, every
// value the row has, and equal to it; then exactly those are sent.
//
// Mutations: accept no --expect-* without a terminal — red; skip the
// comparison with the shown row — the mismatch is sent, red; skip the
// required --expect-source — red.
func TestPoolTrust_CLINonInteractiveNeedsTheCheckedValues(t *testing.T) {
	ctx := context.Background()
	h := newTrustHost()
	if err := runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{}, false, strings.NewReader(""), &bytes.Buffer{}); err == nil || len(h.confirmed) != 0 {
		t.Fatalf("no terminal, no --expect-*: err=%v sent=%d", err, len(h.confirmed))
	}
	if err := runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{driver: "dir", target: "/srv/other"}, false, nil, &bytes.Buffer{}); err == nil || len(h.confirmed) != 0 {
		t.Fatalf("a mismatching --expect-target: err=%v sent=%d", err, len(h.confirmed))
	}
	if err := runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{target: "/srv/data"}, false, nil, &bytes.Buffer{}); err == nil || len(h.confirmed) != 0 {
		t.Fatalf("no --expect-driver: err=%v sent=%d", err, len(h.confirmed))
	}
	nfs := &trustHost{row: &pb.StoragePool{Name: "n", Host: "h1", Driver: "nfs", Source: "srv:/x", Target: "/mnt/n"}}
	if err := runPoolTrust(ctx, nfs, "n", "h1", poolTrustExpect{driver: "nfs", target: "/mnt/n"}, false, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--expect-source") || len(nfs.confirmed) != 0 {
		t.Fatalf("an nfs row with no --expect-source: err=%v sent=%d", err, len(nfs.confirmed))
	}
	if err := runPoolTrust(ctx, h, "data", "h1", poolTrustExpect{driver: "dir", target: "/srv/data/"}, false, nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("the checked values: %v", err)
	}
	if len(h.confirmed) != 1 || h.confirmed[0].GetTarget() != "/srv/data" {
		t.Fatalf("sent = %v", h.confirmed)
	}
}
