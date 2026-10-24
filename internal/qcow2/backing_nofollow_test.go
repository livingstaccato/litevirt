package qcow2

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A BACKING layer swapped for a link between its judgement (EvalSymlinks +
// allow) and its open must not be read. The flatten is NoFollowSource, as
// flattenColdDisk calls it, and allow accepts only the legit backing's resolved
// path, as onlyAccepted(accepted) does. Red before every backing was opened
// O_NOFOLLOW with its path re-checked (openResolvedNoFollow).
//
// Mutations: open backings with os.Open again - the first, third and race tests
// go red. The readlink comparison in openResolvedNoFollow, which catches a
// directory on the way swapped for a link, is a path-level guard these file
// swaps do not exercise: TestFlattenBackingDirectorySwappedForALinkAfterAllowIsRefused
// is the one that goes red without it.
func backingFixture(t *testing.T) (dir, overlay, legit, secret string) {
	t.Helper()
	dir = t.TempDir()
	const size = 1 << 20
	legit = filepath.Join(dir, "base.raw")
	secret = filepath.Join(t.TempDir(), "other-tenant.raw")
	if err := os.WriteFile(legit, bytes.Repeat([]byte("LEGITIMATE-BASE-"), size/16), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, bytes.Repeat([]byte("OTHER-TENANT-SEC"), size/16), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay = filepath.Join(dir, "vm.qcow2")
	if err := CreateWithBackingFormat(overlay, "base.raw", "raw", size, nil); err != nil {
		t.Fatal(err)
	}
	return
}

// Deterministic: allow itself performs the swap after judging the name.
func TestFlattenRawBackingSwappedForALinkAfterAllowIsRefused(t *testing.T) {
	dir, overlay, legit, secret := backingFixture(t)
	realLegit, _ := filepath.EvalSymlinks(legit)
	allow := func(resolved string) error {
		if resolved != realLegit {
			return os.ErrPermission
		}
		_ = os.Rename(legit, legit+".saved")
		if err := os.Symlink(secret, legit); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	flat := filepath.Join(dir, ".flat")
	err := ConvertConfined(context.Background(), overlay, flat, &Options{Uncompressed: true, NoFollowSource: true}, allow)
	if err == nil {
		b, _ := os.ReadFile(flat)
		if bytes.Contains(b, []byte("OTHER-TENANT-SEC")) {
			t.Errorf("the flatten shipped the other tenant's file through a backing swapped for a link after it was judged")
		}
		t.Errorf("the flatten of a backing swapped for a link succeeded")
	}
}

// The same with a qcow2 backing: the next layer is opened by name too.
func TestFlattenQcow2BackingSwappedForALinkAfterAllowIsRefused(t *testing.T) {
	dir := t.TempDir()
	const size = 1 << 20
	legit := filepath.Join(dir, "base.qcow2")
	if err := Create(legit, size, nil); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "other.qcow2")
	if err := Create(secret, 3*size, nil); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "vm.qcow2")
	if err := CreateWithBacking(overlay, "base.qcow2", size, nil); err != nil {
		t.Fatal(err)
	}
	realLegit, _ := filepath.EvalSymlinks(legit)
	allow := func(resolved string) error {
		if resolved != realLegit {
			return os.ErrPermission
		}
		_ = os.Rename(legit, legit+".saved")
		if err := os.Symlink(secret, legit); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	chain, err := openChainFollow(overlay, allow, true)
	if err == nil {
		defer closeChain(chain)
		t.Errorf("a qcow2 backing swapped for a link after it was judged was opened (%d layers)", len(chain))
	}
}

// Undirected: a swap loop races the flatten, with no hook in the reader. Bounded
// by time, like the receive race test.
func TestFlattenBackingSwapRaceShipsNothing(t *testing.T) {
	dir, overlay, legit, secret := backingFixture(t)
	realLegit, _ := filepath.EvalSymlinks(legit)
	saved := legit + ".saved"
	lnk := filepath.Join(dir, ".lnk")
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			_ = os.Link(legit, saved)
			_ = os.Symlink(secret, lnk)
			_ = os.Rename(lnk, legit)
			_ = os.Rename(saved, legit)
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	attempts, leaked := 0, 0
	for time.Now().Before(deadline) && leaked == 0 {
		attempts++
		flat := filepath.Join(dir, ".flat")
		os.Remove(flat)
		err := ConvertConfined(context.Background(), overlay, flat, &Options{Uncompressed: true, NoFollowSource: true},
			func(r string) error {
				if r != realLegit {
					return os.ErrPermission
				}
				return nil
			})
		if err != nil {
			continue
		}
		if b, _ := os.ReadFile(flat); bytes.Contains(b, []byte("OTHER-TENANT-SEC")) {
			leaked++
		}
	}
	stop.Store(true)
	<-done
	if leaked > 0 {
		t.Errorf("a racing swap made the flatten ship another file as the backing (attempt %d)", attempts)
	}
}

// The top layer's header judgements read the OPEN file, not its name: with the
// name swapped for a clean image after the open, the external-data image behind
// the descriptor is still refused.
//
// Mutation: leave judge as the name for the top layer - the clean image at the
// name is judged, the external-data image is read, and this is red.
func TestFlattenTopLayerHeaderChecksReadTheOpenFile(t *testing.T) {
	dir := t.TempDir()
	const size = 1 << 20
	evil := filepath.Join(dir, "vm.qcow2")
	if err := Create(evil, size, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(evil, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var feat [8]byte
	binary.BigEndian.PutUint64(feat[:], incompatExternalDataFile)
	if _, err := f.WriteAt(feat[:], 72); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := AssertNoExternalData(evil); err == nil {
		t.Fatal("the fixture is not an external-data image")
	}
	clean := filepath.Join(dir, "clean.qcow2")
	if err := Create(clean, size, nil); err != nil {
		t.Fatal(err)
	}
	layerOpenedHook = func(string) {
		layerOpenedHook = nil
		_ = os.Rename(clean, evil) // the name now holds a clean image
	}
	t.Cleanup(func() { layerOpenedHook = nil })
	chain, err := openChainFollow(evil, nil, true)
	if err == nil {
		closeChain(chain)
		t.Fatalf("the external-data image behind the open file was accepted")
	}
	if !strings.Contains(err.Error(), "external") {
		t.Errorf("refused for another reason: %v", err)
	}
}

// A DIRECTORY on the backing's path swapped for a link after the backing is
// judged. O_NOFOLLOW guards only the final component, so only the readlink
// comparison in openResolvedNoFollow (the open file must still be named by the
// path allow judged) refuses this. Red with that comparison removed: the
// flatten ships the other directory's file. (Re-review 5b, R5b-1.)
func TestFlattenBackingDirectorySwappedForALinkAfterAllowIsRefused(t *testing.T) {
	const size = 1 << 20
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	legit := filepath.Join(sub, "base.raw")
	if err := os.WriteFile(legit, bytes.Repeat([]byte("LEGITIMATE-BASE-"), size/16), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "base.raw"), bytes.Repeat([]byte("OTHER-TENANT-SEC"), size/16), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "vm.qcow2")
	if err := CreateWithBackingFormat(overlay, "sub/base.raw", "raw", size, nil); err != nil {
		t.Fatal(err)
	}
	realLegit, err := filepath.EvalSymlinks(legit)
	if err != nil {
		t.Fatal(err)
	}
	allow := func(resolved string) error {
		if resolved != realLegit {
			return os.ErrPermission
		}
		if err := os.Rename(sub, sub+".saved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, sub); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	flat := filepath.Join(dir, ".flat")
	err = ConvertConfined(context.Background(), overlay, flat, &Options{Uncompressed: true, NoFollowSource: true}, allow)
	if err == nil {
		b, _ := os.ReadFile(flat)
		if bytes.Contains(b, []byte("OTHER-TENANT-SEC")) {
			t.Fatalf("the flatten shipped another directory's file through a directory swapped for a link after the judgement")
		}
		t.Fatalf("the flatten succeeded through a directory swapped for a link")
	}
	if !strings.Contains(err.Error(), "changed while it was opened") {
		t.Fatalf("refused, but not by the path re-check of the open backing: %v", err)
	}
}
