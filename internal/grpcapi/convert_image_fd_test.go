package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// convertImage (volume move, replica copies, point-in-time copies) runs
// qemu-img on a source whose chain was judged by name (CheckPoolPathNoSymlinks,
// precheckChain). Each file of that chain, and the destination, is handed to
// qemu-img as a descriptor this process opened with no link followed, judged
// regular and re-judged through (/proc/self/fd/N, a json: source naming every
// backing explicitly), so a name swapped for a link after the judgement and
// before qemu-img opens it is never followed. (Re-review 5b, O-2.)
//
// qemuImgRunHook swaps the name exactly there. Mutation: hand qemu-img the
// names again (the old argv) - all three are red.

const convertFDSize = 1 << 20

// qcow2WithData makes a standalone qcow2 at path whose guest view starts with
// marker.
func qcow2WithData(t *testing.T, path string, marker string) {
	t.Helper()
	raw := filepath.Join(t.TempDir(), "data.raw")
	if err := os.WriteFile(raw, bytes.Repeat([]byte(marker), convertFDSize/len(marker)), 0o600); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", raw, path)
}

func swapAtQemuImgRun(t *testing.T, name, target string) *bool {
	t.Helper()
	ran := false
	qemuImgRunHook = func() {
		if ran {
			return
		}
		ran = true
		if err := os.Rename(name, name+".saved"); err != nil {
			t.Error(err)
			return
		}
		if err := os.Symlink(target, name); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { qemuImgRunHook = nil })
	return &ran
}

func noProgress(*pb.MoveVolumeProgress) error { return nil }

func TestConvertImage_ASourceSwappedForALinkAfterItsChecksIsNotRead(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "vm-root.qcow2")
	qcow2WithData(t, src, "LEGITIMATE-DISK-")
	other := filepath.Join(t.TempDir(), "other.qcow2")
	qcow2WithData(t, other, "OTHER-TENANT-SEC")
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	ran := swapAtQemuImgRun(t, src, other)
	if err := convertImage(context.Background(), src, "qcow2", nil, dst, noProgress); err != nil {
		t.Fatalf("convertImage: %v", err)
	}
	if !*ran {
		t.Fatal("fixture: qemu-img did not run")
	}
	got := guestView(t, dst)
	if bytes.Contains(got, []byte("OTHER-TENANT-SEC")) || !bytes.Contains(got, []byte("LEGITIMATE-DISK-")) {
		t.Fatalf("the copy is not the source that was judged (read through the link swapped in after the checks)")
	}
}

func TestConvertImage_ABackingSwappedForALinkAfterItsChecksIsNotRead(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	qcow2WithData(t, base, "LEGITIMATE-BASE-")
	top := filepath.Join(dir, "vm-root.qcow2")
	// A relative backing name: qemu-img must still find it, beside the top.
	if err := qcow2.CreateWithBackingFormat(top, "base.qcow2", "qcow2", convertFDSize, nil); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.qcow2")
	qcow2WithData(t, other, "OTHER-TENANT-SEC")
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	ran := swapAtQemuImgRun(t, base, other)
	allowAny := func(layer, resolved, format string) error { return nil }
	if err := convertImage(context.Background(), top, "qcow2", allowAny, dst, noProgress); err != nil {
		t.Fatalf("convertImage: %v", err)
	}
	if !*ran {
		t.Fatal("fixture: qemu-img did not run")
	}
	got := guestView(t, dst)
	if bytes.Contains(got, []byte("OTHER-TENANT-SEC")) || !bytes.Contains(got, []byte("LEGITIMATE-BASE-")) {
		t.Fatalf("the copy does not hold the backing that was judged (read through the link swapped in after the checks)")
	}
}

func TestConvertImage_ADestinationSwappedForALinkIsNotWrittenThrough(t *testing.T) {
	needQemuImg(t)
	src := filepath.Join(t.TempDir(), "vm-root.qcow2")
	qcow2WithData(t, src, "LEGITIMATE-DISK-")
	out := t.TempDir()
	dst := filepath.Join(out, "out.qcow2")
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("VICTIM"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := swapAtQemuImgRun(t, dst, victim)
	if err := convertImage(context.Background(), src, "qcow2", nil, dst, noProgress); err != nil {
		t.Logf("convertImage: %v", err)
	}
	if !*ran {
		t.Fatal("fixture: qemu-img did not run")
	}
	if b, _ := os.ReadFile(victim); string(b) != "VICTIM" {
		t.Fatalf("qemu-img wrote through a link swapped in at the destination (%d bytes now at the link's target)", len(b))
	}
}

// The source's header rewritten in place (same file, so its name still leads
// to it) after the precheck judged its backing, to name another backing: the
// chain qemu-img gets is walked from the held file again, and a backing that
// is not the one the precheck accepted is refused.
// Mutation: drop the `resolved != accepted[i]` comparison in openBackings -
// the other backing is copied: red.
func TestConvertImage_ABackingRenamedInPlaceAfterItsChecksIsRefused(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	qcow2WithData(t, base, "LEGITIMATE-BASE-")
	other := filepath.Join(dir, "other.qcow2")
	qcow2WithData(t, other, "OTHER-TENANT-SEC")
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.CreateWithBackingFormat(top, "base.qcow2", "qcow2", convertFDSize, nil); err != nil {
		t.Fatal(err)
	}
	rewritten := false
	byNameReadHook = func(p string) {
		if rewritten || filepath.Base(p) != "base.qcow2" {
			return
		}
		rewritten = true
		runQemuImg(t, "rebase", "-u", "-b", "other.qcow2", "-F", "qcow2", top)
	}
	t.Cleanup(func() { byNameReadHook = nil })
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	allowAny := func(layer, resolved, format string) error { return nil }
	err := convertImage(context.Background(), top, "qcow2", allowAny, dst, noProgress)
	if !rewritten {
		t.Fatal("fixture: the header was not rewritten")
	}
	if err == nil {
		if bytes.Contains(guestView(t, dst), []byte("OTHER-TENANT-SEC")) {
			t.Fatal("the copy read a backing its checks never accepted")
		}
		t.Fatal("a copy whose source names a backing its checks did not accept went ahead")
	}
}

// The source swapped for a link while its checks run (between the descriptor
// convertImage holds and the by-name precheck): the name no longer leads to
// the file held, and the copy is refused rather than made from either.
// Mutation: drop verifyNamed - the copy goes ahead: red.
func TestConvertImage_ASourceSwappedDuringItsChecksIsRefused(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "vm-root.qcow2")
	qcow2WithData(t, src, "LEGITIMATE-DISK-")
	other := filepath.Join(t.TempDir(), "other.qcow2")
	qcow2WithData(t, other, "OTHER-TENANT-SEC")
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	swapped := false
	byNameReadHook = func(string) {
		if swapped {
			return
		}
		swapped = true
		if err := os.Rename(src, src+".saved"); err != nil {
			t.Error(err)
			return
		}
		if err := os.Symlink(other, src); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { byNameReadHook = nil })
	err := convertImage(context.Background(), src, "qcow2", nil, dst, noProgress)
	if !swapped {
		t.Fatal("fixture: the checks did not run")
	}
	if err == nil {
		t.Fatal("a copy whose source was swapped for a link during its checks went ahead")
	}
}

// A DIRECTORY on a backing's path swapped for a link after the backing's name
// was resolved and judged, just before it is opened: O_NOFOLLOW guards only
// the final component, and a name resolved again at check time agrees with
// the swap. The open file must be named by exactly the path the checks
// accepted. (Re-review of fix/migrate-followups, finding 1; the reviewer's
// probe.)
// Mutation: drop the readlink == resolved comparison in openBackings - the
// copy ships the other directory's file: red.
func TestConvertImage_ABackingDirectorySwappedAtTheOpenIsRefused(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "base.raw"), bytes.Repeat([]byte("LEGITIMATE-BASE-"), convertFDSize/16), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "base.raw"), bytes.Repeat([]byte("OTHER-TENANT-SEC"), convertFDSize/16), 0o600); err != nil {
		t.Fatal(err)
	}
	top := filepath.Join(dir, "vm-root.qcow2")
	if err := qcow2.CreateWithBackingFormat(top, "sub/base.raw", "raw", convertFDSize, nil); err != nil {
		t.Fatal(err)
	}
	legit, err := filepath.EvalSymlinks(filepath.Join(sub, "base.raw"))
	if err != nil {
		t.Fatal(err)
	}
	rule := func(layer, resolved, format string) error {
		if resolved != legit {
			return os.ErrPermission
		}
		return nil
	}
	swapped := false
	backingOpenHook = func(string) {
		if swapped {
			return
		}
		swapped = true
		if err := os.Rename(sub, sub+".saved"); err != nil {
			t.Error(err)
			return
		}
		if err := os.Symlink(other, sub); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { backingOpenHook = nil })
	f, err := os.CreateTemp(t.TempDir(), ".repl-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = convertImage(context.Background(), top, "qcow2", rule, f.Name(), noProgress)
	if !swapped {
		t.Fatal("fixture: the backing was never opened")
	}
	if err == nil {
		if bytes.Contains(guestView(t, f.Name()), []byte("OTHER-TENANT-SEC")) {
			t.Fatal("the copy read another directory's file through a directory swapped for a link at the backing's open")
		}
		t.Fatal("a copy whose backing's directory was swapped for a link at its open went ahead")
	}
}

// The last qcow2 layer's header rewritten IN PLACE (same file, so every name
// check passes) after the checks, to name a backing: qemu-img is told the
// layer has none ("backing": null), so it opens nothing the header now names.
// (Re-review of fix/migrate-followups, item 3; the reviewer's probe.)
// Mutation: leave "backing" out for the last qcow2 layer - the copy holds the
// newly named file's bytes: red.
func TestConvertImage_ABackingNameWrittenIntoTheLastLayerInPlaceIsNotFollowed(t *testing.T) {
	needQemuImg(t)
	top := filepath.Join(t.TempDir(), "vm-root.qcow2")
	if err := qcow2.Create(top, convertFDSize, nil); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret.raw")
	if err := os.WriteFile(secret, bytes.Repeat([]byte("OTHER-TENANT-SEC"), convertFDSize/16), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	qemuImgRunHook = func() {
		ran = true
		runQemuImg(t, "rebase", "-u", "-b", secret, "-F", "raw", top)
	}
	t.Cleanup(func() { qemuImgRunHook = nil })
	f, err := os.CreateTemp(t.TempDir(), ".repl-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = convertImage(context.Background(), top, "qcow2", nil, f.Name(), noProgress)
	if !ran {
		t.Fatal("fixture: qemu-img did not run")
	}
	if err == nil && bytes.Contains(guestView(t, f.Name()), []byte("OTHER-TENANT-SEC")) {
		t.Fatal("qemu-img followed a backing name written into the last layer in place after the checks")
	}
}

// A source layer that keeps its data in an external file is refused before
// qemu-img runs: qemu opens a data file with the image itself, by name.
func TestConvertImage_AnExternalDataFileIsRefused(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	top := filepath.Join(dir, "vm-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-o", "data_file="+filepath.Join(dir, "data.raw"), top, "1M")
	ran := false
	qemuImgRunHook = func() { ran = true }
	t.Cleanup(func() { qemuImgRunHook = nil })
	dst := filepath.Join(t.TempDir(), "out.qcow2")
	err := convertImage(context.Background(), top, "qcow2", nil, dst, noProgress)
	if status.Code(err) != codes.FailedPrecondition || ran {
		t.Fatalf("convertImage of an image with an external data file = %v (qemu-img ran: %v); want FailedPrecondition before qemu-img", err, ran)
	}
}

// A hard link planted at the destination (a pool-directory writer can link a
// file it cannot write under the temp's name) is refused: the destination
// must have exactly one name. (Re-review of fix/migrate-followups, item 4.)
// Mutation: drop the link-count check in openConvertTop - the copy writes
// through the link into the other file: red.
func TestConvertImage_AHardLinkAtTheDestinationIsRefused(t *testing.T) {
	needQemuImg(t)
	src := filepath.Join(t.TempDir(), "vm-root.qcow2")
	qcow2WithData(t, src, "LEGITIMATE-DISK-")
	out := t.TempDir()
	victim := filepath.Join(out, "victim")
	if err := os.WriteFile(victim, []byte("VICTIM"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(out, ".repl-x.tmp")
	if err := os.Link(victim, dst); err != nil {
		t.Fatal(err)
	}
	err := convertImage(context.Background(), src, "qcow2", nil, dst, noProgress)
	if b, _ := os.ReadFile(victim); string(b) != "VICTIM" {
		t.Fatal("the copy wrote through a hard link at the destination")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("convertImage onto a hard link = %v; want FailedPrecondition", err)
	}
}

// A refused copy removes the destination it created itself, and only that:
// a destination its caller made is the caller's to remove.
// Mutation: drop the removal in convertImageWith - "made here" red.
func TestConvertImage_ARefusedCopyRemovesTheDestinationItMade(t *testing.T) {
	needQemuImg(t)
	refused := func(t *testing.T) string {
		dir := t.TempDir()
		base := filepath.Join(dir, "base.qcow2")
		qcow2WithData(t, base, "LEGITIMATE-BASE-")
		top := filepath.Join(dir, "vm-root.qcow2")
		if err := qcow2.CreateWithBackingFormat(top, "base.qcow2", "qcow2", convertFDSize, nil); err != nil {
			t.Fatal(err)
		}
		return top
	}
	t.Run("made here", func(t *testing.T) {
		top := refused(t)
		dst := filepath.Join(t.TempDir(), "new.qcow2")
		if err := convertImage(context.Background(), top, "qcow2", nil, dst, noProgress); err == nil {
			t.Fatal("fixture: the copy was not refused")
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Fatal("a refused copy left the destination it created")
		}
	})
	t.Run("made by the caller", func(t *testing.T) {
		top := refused(t)
		f, err := os.CreateTemp(t.TempDir(), ".repl-*.tmp")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if err := convertImage(context.Background(), top, "qcow2", nil, f.Name(), noProgress); err == nil {
			t.Fatal("fixture: the copy was not refused")
		}
		if _, err := os.Lstat(f.Name()); err != nil {
			t.Fatalf("a refused copy removed its caller's destination: %v", err)
		}
	})
}
