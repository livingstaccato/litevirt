package corrosion

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/metadata"
)

func localClientT(t *testing.T, dir string) *Client {
	t.Helper()
	c, err := NewLocalClient(dir, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func cachedStacksDigest(t *testing.T, c *Client) TableDigest {
	t.Helper()
	ds, err := c.StateDigestCached(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return digestOf(t, ds, "stacks")
}

// A write by another process fires no hook here. NewLocalClient (the one such
// writer, `lv user reset-admin`) touches the data directory's digest marker
// when it closes after writing, and the daemon's cache stops serving anything
// older than the marker.
func TestDigestCache_OutOfProcessWriteMarker(t *testing.T) {
	dir := t.TempDir()
	daemon := localClientT(t, dir)
	daemon.outOfProcess = false // stands in for the daemon's own client
	if err := InitSchema(context.Background(), daemon); err != nil {
		t.Fatal(err)
	}
	seedStacks(t, daemon, 5)
	before := cachedStacksDigest(t, daemon)

	// The other process's write, beneath this client's hook.
	if err := daemon.ExecOutOfProcessForTest(`UPDATE stacks SET state = 'x' WHERE name = 'stack-0001'`); err != nil {
		t.Fatal(err)
	}
	if got := cachedStacksDigest(t, daemon); got != before {
		t.Fatal("precondition: the unhooked write already reached the cache; the test cannot see the marker's effect")
	}
	if err := touchDigestMarker(dir); err != nil {
		t.Fatal(err)
	}
	// Cached first: a fresh scan stores what it finds, which would hide
	// whether the marker did anything.
	got := cachedStacksDigest(t, daemon)
	fresh, _ := daemon.StateDigest(context.Background())
	if got != digestOf(t, fresh, "stacks") {
		t.Fatalf("a cached digest older than the out-of-process marker was served: %+v", got)
	}
}

func TestNewLocalClient_CloseMarksOnlyAWrite(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, digestMarkerFile)
	setup := localClientT(t, dir)
	if err := InitSchema(context.Background(), setup); err != nil {
		t.Fatal(err)
	}
	setup.Close()
	os.Remove(marker)

	reader, err := NewLocalClient(dir, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.StateDigest(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a client that only read touched the digest marker")
	}

	writer, err := NewLocalClient(dir, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Execute(context.Background(), `INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at) VALUES ('w', 'h', 'y', 'active', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("a client that wrote did not touch the digest marker: %v", err)
	}
}

func TestFreshDigestKeyRoundTrip(t *testing.T) {
	out, _ := metadata.FromOutgoingContext(WithFreshDigest(context.Background()))
	if !FreshDigestRequested(metadata.NewIncomingContext(context.Background(), out)) {
		t.Fatal("a request marked fresh does not read as fresh on the server")
	}
	if FreshDigestRequested(context.Background()) {
		t.Fatal("an unmarked request reads as fresh")
	}
}
