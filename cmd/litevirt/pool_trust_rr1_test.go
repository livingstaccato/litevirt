package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// (re-review rr1 N1) The preview prints the host's row, and the row is what a
// forger writes: a field the forger controls (a dir pool's unused source)
// could drive the operator's terminal — move the cursor up, erase the real
// target line, print a benign one, conceal the rest. Nothing from the row
// reaches the terminal unescaped.
//
// Mutation: print the preview's fields without termSafe — red.
func TestRR1Probe_PreviewDoesNotDriveTheTerminal(t *testing.T) {
	h := &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir",
		Source: "x\x1b[8m", Target: "/var/lib/polkit-1/localauthority/50-local.d"}}
	var out bytes.Buffer
	_ = runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("n\n"), &out)
	if strings.ContainsAny(out.String(), "\x1b\r") {
		t.Errorf("the preview wrote control characters from the row to the terminal: %q", out.String())
	}
}

// (re-review rr1 N1) A row holding a control or format character is not
// confirmed interactively — what a terminal shows is not exactly the row —
// and nothing is sent; with --expect-* the exact strings are compared, so an
// operator who passes them can still confirm it.
//
// Mutation: skip the unprintable check — the y is taken and the row sent,
// red.
func TestPoolTrust_CLIRefusesInteractiveConfirmOfAnUnprintableRow(t *testing.T) {
	for _, row := range []*pb.StoragePool{
		{Name: "data", Host: "h1", Driver: "dir", Source: "x\x1b[8m", Target: "/srv/data"},
		{Name: "data", Host: "h1", Driver: "dir", Target: "/srv/da‮ta"},
	} {
		h := &trustHost{row: row}
		var out bytes.Buffer
		err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("y\n"), &out)
		if err == nil || !strings.Contains(err.Error(), "--expect-") || len(h.confirmed) != 0 {
			t.Errorf("row %q: err=%v sent=%d, want a refusal naming --expect-* and nothing sent", row.Target, err, len(h.confirmed))
		}
		if strings.ContainsAny(out.String(), "\x1b‮") {
			t.Errorf("the preview wrote the row's control characters raw: %q", out.String())
		}
	}
	h := &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Source: "x\x1b[8m", Target: "/srv/data"}}
	if err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{driver: "dir", source: "x\x1b[8m", target: "/srv/data"}, false, nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("the exact values with --expect-*: %v", err)
	}
}
