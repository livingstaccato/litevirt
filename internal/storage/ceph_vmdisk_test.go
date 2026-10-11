package storage

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rbdExit is a failed rbd command as exec reports it: rbd exits with the
// errno of the failure (rbd.cc: return std::abs(r)).
type rbdExit int

func (e rbdExit) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e rbdExit) ExitCode() int { return int(e) }

// fakeCeph models the rbd semantics the VM-disk paths turn on: images and
// their snapshots exist or not, clone/import/create/rename/deep cp refuse an
// existing destination, rm refuses an image with snapshots, a protected
// snapshot cannot be removed. Every call is recorded as "<sub> <positional…>".
type fakeCeph struct {
	images map[string]map[string]bool // "pool/image" → snapshot → protected
	sizes  map[string]int64
	calls  []string
	fail   map[string]error // subcommand → injected failure
	// failOut is a failure with rbd's own output (subcommand → output, error).
	failOut map[string]struct {
		out []byte
		err error
	}
	before      map[string]func() // subcommand → run just before it
	partialCopy bool              // deep cp creates its destination, then fails
	listing     []string          // what `rbd ls` prints; nil → the images in the pool
	// A killed rbd client leaves a watch on the image it had open until the
	// OSD's watch timeout (30 s): until then `rbd rm` refuses it with EBUSY.
	now     time.Duration            // the fake's clock, advanced by cephSleep
	watched map[string]time.Duration // image → when its dead client's watch expires
	// The pools' trash: "pool/id" → the image moved there, which `rbd trash
	// rm` purges. Images get an id the first time `rbd info` reports one.
	trash map[string]fakeTrashed
	ids   map[string]string
}

type fakeTrashed struct {
	name, source string
	snaps        map[string]bool
	// watchedUntil: a client that had the image open before it was moved
	// keeps it open in the trash (lab 2, 19.2.3: `rbd trash mv` does not
	// refuse an open image).
	watchedUntil time.Duration
}

// watcherLine is how rados lists a watcher of an object.
const watcherLine = "watcher=10.78.0.13:0/3434 client.4242 cookie=1"

// trashed lists the trash entries of pool as "id name".
func (f *fakeCeph) trashed(pool string) []string {
	var out []string
	for k, e := range f.trash {
		if p, id, _ := strings.Cut(k, "/"); p == pool {
			out = append(out, id+" "+e.name)
		}
	}
	return out
}

func (f *fakeCeph) idOf(ref string) string {
	if f.ids == nil {
		f.ids = map[string]string{}
	}
	if id, ok := f.ids[ref]; ok {
		return id
	}
	id := fmt.Sprintf("1%011x", len(f.ids)+1+len(f.trash))
	f.ids[ref] = id
	return id
}

// installSleep makes the driver's retry waits advance the fake's clock.
func (f *fakeCeph) installSleep(t *testing.T) {
	t.Helper()
	prev := cephSleep
	cephSleep = func(ctx context.Context, d time.Duration) bool { f.now += d; return true }
	t.Cleanup(func() { cephSleep = prev })
}

func newFakeCeph() *fakeCeph {
	return &fakeCeph{images: map[string]map[string]bool{}, sizes: map[string]int64{}, fail: map[string]error{},
		failOut: map[string]struct {
			out []byte
			err error
		}{}, before: map[string]func(){}}
}

func (f *fakeCeph) has(ref string) bool { _, ok := f.images[ref]; return ok }

func (f *fakeCeph) snaps(ref string) int { return len(f.images[ref]) }

func (f *fakeCeph) called(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeCeph) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "qemu-img" {
		f.calls = append(f.calls, "qemu-img "+strings.Join(args, " "))
		if err := f.fail["qemu-img"]; err != nil {
			return []byte("qemu-img: injected"), err
		}
		return nil, os.WriteFile(args[len(args)-1], []byte("raw"), 0o600)
	}
	if name == "rados" {
		return f.rados(args)
	}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "--" {
		i += 2 // --id/--conf/--keyring <value>
	}
	var words, pos []string
	for j := i; j < len(args); j++ {
		if args[j] == "--" {
			pos = args[j+1:]
			break
		}
		words = append(words, args[j])
	}
	sub := words[0]
	if sub == "snap" || sub == "deep" || sub == "trash" {
		sub += " " + words[1]
	}
	if ctx.Err() != nil {
		// exec.CommandContext never starts a command on a cancelled context.
		f.calls = append(f.calls, "CANCELLED "+strings.TrimSpace(sub+" "+strings.Join(pos, " ")))
		return nil, ctx.Err()
	}
	if f.fail[sub] == context.Canceled && len(pos) > 0 {
		// The command is killed mid-run: its image keeps the dead client's
		// watch for 30 s.
		if f.watched == nil {
			f.watched = map[string]time.Duration{}
		}
		ref, _, _ := strings.Cut(pos[len(pos)-1], "@")
		f.watched[ref] = f.now + 30*time.Second
	}
	f.calls = append(f.calls, strings.TrimSpace(sub+" "+strings.Join(pos, " ")))
	if hook := f.before[sub]; hook != nil {
		hook()
	}
	if err := f.fail[sub]; err != nil {
		return []byte("rbd: injected failure"), err
	}
	if fo, ok := f.failOut[sub]; ok {
		return fo.out, fo.err
	}
	exists := []byte("rbd: create error: (17) File exists")
	missing := []byte("rbd: error opening image: (2) No such file or directory")
	switch sub {
	case "ls", "import":
		if sub == "ls" {
			if f.listing != nil {
				return []byte(strings.Join(f.listing, "\n")), nil
			}
			var names []string
			for ref := range f.images {
				if p, img, ok := strings.Cut(ref, "/"); ok && p == pos[0] {
					names = append(names, img)
				}
			}
			return []byte(strings.Join(names, "\n")), nil
		}
		if sub == "import" {
			dst := pos[1]
			if f.has(dst) {
				return exists, rbdExit(17)
			}
			f.images[dst] = map[string]bool{}
			f.sizes[dst] = 512 << 20
		}
		return nil, nil
	case "create":
		if f.has(pos[0]) {
			return exists, rbdExit(17)
		}
		f.images[pos[0]] = map[string]bool{}
		return nil, nil
	case "info":
		ref, snap, _ := strings.Cut(pos[0], "@")
		if !f.has(ref) {
			return missing, rbdExit(2)
		}
		if snap != "" {
			if _, ok := f.images[ref][snap]; !ok {
				return missing, rbdExit(2)
			}
		}
		return []byte(fmt.Sprintf(`{"size":%d,"id":"%s","snapshot_count":%d}`, f.sizes[ref], f.idOf(ref), len(f.images[ref]))), nil
	case "status":
		if !f.has(pos[0]) {
			return missing, rbdExit(2)
		}
		if until, ok := f.watched[pos[0]]; ok && f.now < until {
			return []byte(`{"watchers":[{"address":"10.78.0.13:0/3434","client":4242,"cookie":1}]}`), nil
		}
		return []byte(`{"watchers":[]}`), nil
	case "trash mv":
		// Lab 2 (19.2.3): `rbd trash mv` does NOT refuse an image a live
		// client has open; the client keeps it open in the trash.
		if !f.has(pos[0]) {
			return missing, rbdExit(2)
		}
		pool, _, _ := strings.Cut(pos[0], "/")
		if f.trash == nil {
			f.trash = map[string]fakeTrashed{}
		}
		f.trash[pool+"/"+f.idOf(pos[0])] = fakeTrashed{name: pos[0][len(pool)+1:], source: "USER", snaps: f.images[pos[0]], watchedUntil: f.watched[pos[0]]}
		delete(f.images, pos[0])
		delete(f.ids, pos[0])
		delete(f.watched, pos[0])
		return nil, nil
	case "trash rm":
		e, ok := f.trash[pos[0]]
		if !ok {
			return []byte("rbd: error: image not in trash: (2) No such file or directory"), rbdExit(2)
		}
		if f.now < e.watchedUntil {
			// Lab 2, verbatim (exit 16).
			return []byte("rbd: error: image still has watchers\nimage has watchers - not removing"), rbdExit(16)
		}
		if len(e.snaps) > 0 {
			return []byte("rbd: image has snapshots - not removing"), rbdExit(39)
		}
		delete(f.trash, pos[0])
		return nil, nil
	case "trash restore":
		e, ok := f.trash[pos[0]]
		if !ok {
			return []byte("rbd: restore error: (2) No such file or directory"), rbdExit(2)
		}
		pool, id, _ := strings.Cut(pos[0], "/")
		ref := pool + "/" + e.name
		if f.has(ref) {
			return []byte("rbd: restore error: an image with the same name already exists: (17) File exists"), rbdExit(17)
		}
		snaps := e.snaps
		if snaps == nil {
			snaps = map[string]bool{}
		}
		f.images[ref] = snaps
		f.idOf(ref)
		f.ids[ref] = id
		if e.watchedUntil > 0 {
			if f.watched == nil {
				f.watched = map[string]time.Duration{}
			}
			f.watched[ref] = e.watchedUntil
		}
		delete(f.trash, pos[0])
		return nil, nil
	case "trash ls":
		// 19.2.3, verbatim shapes (lab2-ceph-report-2.md): `source`,
		// `deleted_at` and `status` only with --long.
		long := false
		for _, w := range words {
			long = long || w == "--long" || w == "-l"
		}
		var entries []string
		for k, e := range f.trash {
			if p, id, _ := strings.Cut(k, "/"); p == pos[0] {
				if long {
					entries = append(entries, fmt.Sprintf(`{"id":"%s","name":"%s","source":"%s","deleted_at":"Fri Oct 10 22:56:08 2026","status":"expired at Fri Oct 10 22:56:08 2026"}`, id, e.name, e.source))
				} else {
					entries = append(entries, fmt.Sprintf(`{"id":"%s","name":"%s"}`, id, e.name))
				}
			}
		}
		return []byte("[" + strings.Join(entries, ",") + "]"), nil
	case "clone":
		ref, snap, _ := strings.Cut(pos[0], "@")
		if prot, ok := f.images[ref][snap]; !ok || !prot {
			return []byte("rbd: parent snapshot must be protected"), rbdExit(22)
		}
		if f.has(pos[1]) {
			return exists, rbdExit(17)
		}
		f.images[pos[1]] = map[string]bool{}
		f.sizes[pos[1]] = f.sizes[ref]
		return nil, nil
	case "deep cp":
		// rbd opens the source first: a missing source never reaches the
		// destination, and its output names no destination at all.
		if !f.has(pos[0]) {
			return missing, rbdExit(2)
		}
		if f.has(pos[1]) {
			return exists, rbdExit(17)
		}
		f.images[pos[1]] = map[string]bool{}
		f.sizes[pos[1]] = f.sizes[pos[0]]
		if f.partialCopy {
			return []byte("rbd: deep copy failed: (5) Input/output error"), rbdExit(5)
		}
		return nil, nil
	case "snap purge":
		for snap, prot := range f.images[pos[0]] {
			if prot {
				return []byte("rbd: snapshot is protected"), rbdExit(16)
			}
			delete(f.images[pos[0]], snap)
		}
		return nil, nil
	case "resize":
		f.sizes[pos[0]] = 1 // recorded; the size is asserted from the call
		return nil, nil
	case "snap create":
		ref, snap, _ := strings.Cut(pos[0], "@")
		f.images[ref][snap] = false
		return nil, nil
	case "snap protect", "snap unprotect":
		ref, snap, _ := strings.Cut(pos[0], "@")
		if _, ok := f.images[ref][snap]; ok {
			f.images[ref][snap] = sub == "snap protect"
		}
		return nil, nil
	case "snap rm":
		ref, snap, _ := strings.Cut(pos[0], "@")
		if f.images[ref][snap] {
			return []byte("rbd: snapshot is protected"), rbdExit(16)
		}
		delete(f.images[ref], snap)
		return nil, nil
	case "rename":
		if f.has(pos[1]) {
			return exists, rbdExit(17)
		}
		f.images[pos[1]] = f.images[pos[0]]
		f.sizes[pos[1]] = f.sizes[pos[0]]
		delete(f.images, pos[0])
		return nil, nil
	case "rm":
		if !f.has(pos[0]) {
			return missing, rbdExit(2)
		}
		if until, ok := f.watched[pos[0]]; ok && f.now < until {
			return []byte("rbd: error: image still has watchers\nThis means the image is still open or the client using it crashed. Try again after closing/unmapping it or waiting 30s for the crashed client to timeout."), rbdExit(16)
		}
		if f.snaps(pos[0]) > 0 {
			return []byte("rbd: image has snapshots - not removing"), rbdExit(39)
		}
		delete(f.images, pos[0])
		return nil, nil
	}
	return nil, nil
}

// rados answers `rados -p <pool> listwatchers rbd_header.<id>` for an image
// in the pool or in its trash, as rados prints it: one line per watcher.
func (f *fakeCeph) rados(args []string) ([]byte, error) {
	f.calls = append(f.calls, "rados "+strings.Join(args, " "))
	if err := f.fail["rados"]; err != nil {
		return []byte("rados: injected failure"), err
	}
	pool, obj := "", ""
	for i, a := range args {
		if a == "-p" && i+1 < len(args) {
			pool = args[i+1]
		}
		if strings.HasPrefix(a, "rbd_header.") {
			obj = strings.TrimPrefix(a, "rbd_header.")
		}
	}
	if e, ok := f.trash[pool+"/"+obj]; ok {
		if f.now < e.watchedUntil {
			return []byte(watcherLine + "\n"), nil
		}
		return nil, nil
	}
	for ref, id := range f.ids {
		if id == obj && strings.HasPrefix(ref, pool+"/") {
			if until, ok := f.watched[ref]; ok && f.now < until {
				return []byte(watcherLine + "\n"), nil
			}
			return nil, nil
		}
	}
	return []byte("error listing watchers " + pool + "/rbd_header." + obj + ": (2) No such file or directory"), rbdExit(2)
}

// labCephFiles writes a ceph.conf as cephadm writes it and a restricted
// client's keyring, and returns their paths and the key.
func labCephFiles(t *testing.T) (conf, keyring string, key []byte) {
	t.Helper()
	dir := t.TempDir()
	conf = filepath.Join(dir, "ceph.conf")
	if err := os.WriteFile(conf, []byte("# minimal ceph.conf\n[global]\n\tfsid = 0b0c\n\tmon_host = [v2:10.78.0.22:3300/0,v1:10.78.0.22:6789/0]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key = []byte("0123456789abcdef0123456789ab")
	keyring = filepath.Join(dir, "ceph.client.litevirt.keyring")
	body := "[client.litevirt]\n\tkey = " + base64.StdEncoding.EncodeToString(key) + "\n\tcaps mon = \"profile rbd\"\n"
	if err := os.WriteFile(keyring, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return conf, keyring, key
}

// The locator a VM disk is recorded and attached by names the pool's client
// identity and the monitors from its ceph.conf: what the domain XML needs for a
// restricted key (an <auth> secret, <host> elements), and nothing qemu-only.
func TestCephDiskLocator_CarriesIdentityAndMonitors(t *testing.T) {
	conf, keyring, _ := labCephFiles(t)
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{"id": "litevirt", "conf": conf, "keyring": keyring}, run: f.run}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "data", SizeBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	// I5: the monitors are NOT fixed into the locator: they are read from the
	// pool (or its conf) each time a domain is defined. The litevirt pool the
	// disk belongs to names its secret (I2).
	want := "rbd:lv/vm-data:id=litevirt:keyring=" + keyring + ":conf=" + conf + ":lvpool=ceph"
	if path != want {
		t.Fatalf("locator\n got %q\nwant %q", path, want)
	}
	if !f.has("lv/vm-data") {
		t.Fatalf("data disk not created: %v", f.calls)
	}
}

// A conf that names no monitors cannot be reached by a domain (only the
// default ceph.conf is read by qemu itself): refused before anything exists.
func TestCephCreateDisk_ConfWithoutMonitorsAllocatesNothing(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "custom.conf")
	if err := os.WriteFile(conf, []byte("[global]\nfsid = x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", opts: map[string]string{"conf": conf}, run: f.run}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "data", SizeBytes: 1 << 30}); err == nil || !strings.Contains(err.Error(), "mon_host") {
		t.Fatalf("got %v, want a refusal naming mon_host", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("refused create still ran rbd: %v", f.calls)
	}
}

func storeImage(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cirros.qcow2")
	if err := os.WriteFile(p, []byte("qcow2 image bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A root disk from an image: the image is imported into the pool ONCE (raw, a
// protected snapshot), and every VM's root disk is a copy-on-write clone of it,
// grown to the size asked for. A second VM on the same image imports nothing.
func TestCephCreateDisk_RootFromImageImportsOnceAndClones(t *testing.T) {
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run, scratch: t.TempDir()}
	img := storeImage(t)
	opts := DiskOptions{VMName: "a", DiskName: "root", SizeBytes: 2 << 30, SourceImage: img, SourceImageName: "cirros", SourceImageDigest: strings.Repeat("ab", 32)}
	path, err := d.CreateDisk(context.Background(), opts)
	if err != nil {
		t.Fatalf("CreateDisk: %v (calls %v)", err, f.calls)
	}
	if path != "rbd:lv/a-root" {
		t.Errorf("path = %q", path)
	}
	base := "lv/" + CephBaseImageName("cirros", opts.SourceImageDigest)
	if prot, ok := f.images[base]["base"]; !ok || !prot {
		t.Fatalf("base %s@base missing or unprotected: %v", base, f.images)
	}
	if f.called("clone "+base+"@base lv/a-root") != 1 {
		t.Errorf("root disk is not a clone of the base: %v", f.calls)
	}
	if f.called("resize lv/a-root") != 1 {
		t.Errorf("clone not grown to the requested size: %v", f.calls)
	}

	opts.VMName = "b"
	if _, err := d.CreateDisk(context.Background(), opts); err != nil {
		t.Fatalf("second CreateDisk: %v", err)
	}
	if n := f.called("import"); n != 1 {
		t.Errorf("image imported %d times, want once: %v", n, f.calls)
	}
	if f.called("clone "+base+"@base lv/b-root") != 1 {
		t.Errorf("second VM not cloned from the same base: %v", f.calls)
	}
	for ref := range f.images {
		if strings.Contains(ref, incomingMarker) {
			t.Errorf("import staging %s left behind", ref)
		}
	}
	// A smaller request than the image keeps the image's size: never shrunk.
	f.calls = nil
	f.sizes[base] = 4 << 30
	opts.VMName, opts.SizeBytes = "c", 1<<30
	if _, err := d.CreateDisk(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if f.called("resize") != 0 {
		t.Errorf("a clone was shrunk: %v", f.calls)
	}
}

// Two hosts import the same image at once: the one whose rename loses removes
// its own staging copy and clones the winner's base.
func TestCephEnsureBase_LosingTheRenameUsesTheWinner(t *testing.T) {
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run, scratch: t.TempDir()}
	digest := strings.Repeat("cd", 32)
	base := "lv/" + CephBaseImageName("cirros", digest)
	// The winner's base appears between this host's check and its rename.
	f.fail["rename"] = nil
	orig := f.run
	d.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "rbd" && len(args) > 0 && args[0] == "rename" && !f.has(base) {
			f.images[base] = map[string]bool{"base": true}
		}
		return orig(ctx, name, args...)
	}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "a", DiskName: "root", SourceImage: storeImage(t), SourceImageName: "cirros", SourceImageDigest: digest}); err != nil {
		t.Fatalf("CreateDisk: %v (calls %v)", err, f.calls)
	}
	for ref := range f.images {
		if strings.Contains(ref, incomingMarker) {
			t.Errorf("the losing import left %s behind: %v", ref, f.calls)
		}
	}
	if !f.has("lv/a-root") {
		t.Errorf("root disk not cloned from the winner's base: %v", f.calls)
	}
}

// A clone whose resize fails is removed: the create leaves no image behind.
func TestCephCreateDisk_FailedGrowRemovesTheClone(t *testing.T) {
	f := newFakeCeph()
	f.fail["resize"] = rbdExit(1)
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run, scratch: t.TempDir()}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "a", DiskName: "root", SizeBytes: 8 << 30, SourceImage: storeImage(t), SourceImageName: "cirros", SourceImageDigest: strings.Repeat("ef", 32)}); err == nil {
		t.Fatal("expected the resize failure")
	}
	for ref := range f.images {
		if !IsCephBaseImage(strings.TrimPrefix(ref, "lv/")) {
			t.Fatalf("%s left behind after a failed create: %v", ref, f.calls)
		}
	}
}

// A failed import leaves no staging image and no base.
func TestCephCreateDisk_FailedImportLeavesNothing(t *testing.T) {
	f := newFakeCeph()
	f.fail["snap protect"] = rbdExit(1)
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run, scratch: t.TempDir()}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "a", DiskName: "root", SourceImage: storeImage(t), SourceImageName: "cirros", SourceImageDigest: strings.Repeat("12", 32)}); err == nil {
		t.Fatal("expected the protect failure")
	}
	if len(f.images) != 0 {
		t.Fatalf("images left after a failed import: %v (calls %v)", f.images, f.calls)
	}
}

// Delete removes the disk's own image, never a base other disks are cloned
// from, never an image in another pool, and a disk already gone is fine.
func TestCephDeleteDisk_OnlyTheDisksOwnImage(t *testing.T) {
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	base := "lv/" + CephBaseImageName("cirros", strings.Repeat("ab", 32))
	// No snapshot here, so it is the name alone — not rbd's own refusal of an
	// image with snapshots — that must keep it.
	f.images[base] = map[string]bool{}
	f.images["lv/a-root"] = map[string]bool{}
	f.images["other/a-root"] = map[string]bool{}

	if err := d.DeleteDisk(context.Background(), `rbd:lv/a-root:id=litevirt:keyring=/k:mon_host=10.0.0.1\:6789`); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if f.has("lv/a-root") {
		t.Error("the disk's image was not removed")
	}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Errorf("a disk already gone: %v", err)
	}
	if err := d.DeleteDisk(context.Background(), "rbd:"+base); err == nil || !f.has(base) {
		t.Errorf("a base image was removed or not refused: err=%v", err)
	}
	if err := d.DeleteDisk(context.Background(), "rbd:other/a-root"); err == nil || !f.has("other/a-root") {
		t.Errorf("an image in another pool was removed or not refused: err=%v", err)
	}
	// One with snapshots (a clone may hang off one) is refused by rbd, and
	// the refusal is reported.
	f.images["lv/b-root"] = map[string]bool{"s1": true}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/b-root"); err == nil || !f.has("lv/b-root") {
		t.Errorf("an image with snapshots: err=%v", err)
	}
}

// A VM clone copies its disk inside the pool (rbd deep cp), never through the
// host; a copy that failed part-way is removed, an existing image never is.
func TestCephCloneDisk_DeepCopiesInsideThePool(t *testing.T) {
	conf, keyring, _ := labCephFiles(t)
	f := newFakeCeph()
	f.images["lv/src-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{"id": "litevirt", "keyring": keyring, "conf": conf}, run: f.run}
	p, err := d.CloneDisk(context.Background(), "rbd:lv/src-root:id=litevirt:keyring="+keyring, DiskOptions{VMName: "dst", DiskName: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "rbd:lv/dst-root:id=litevirt:keyring=") || f.called("deep cp lv/src-root lv/dst-root") != 1 {
		t.Fatalf("path %q calls %v", p, f.calls)
	}
	// The destination exists (another VM's): refused, and left alone.
	if _, err := d.CloneDisk(context.Background(), "rbd:lv/src-root", DiskOptions{VMName: "dst", DiskName: "root"}); err == nil || !f.has("lv/dst-root") {
		t.Fatalf("clone onto an existing image: err=%v, image kept=%v", err, f.has("lv/dst-root"))
	}
}

// C1. A clone whose copy fails before it creates anything — here the source
// image is gone — must never remove the destination name: that image is
// another VM's (VM "a" disk "b-root" is VM "a-b" disk "root").
func TestCephCloneDisk_NeverRemovesAnImageItDidNotCreate(t *testing.T) {
	f := newFakeCeph()
	f.images["lv/a-b-root"] = map[string]bool{} // VM a's data disk b-root
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{}, run: f.run}
	if _, err := d.CloneDisk(context.Background(), "rbd:lv/gone-root", DiskOptions{VMName: "a-b", DiskName: "root"}); err == nil {
		t.Fatal("clone of a missing source succeeded")
	}
	if !f.has("lv/a-b-root") {
		t.Fatalf("the clone's rollback removed another VM's image: %v", f.calls)
	}
}

// A copy that fails part-way leaves nothing: it went to a private staging
// name, which is all the rollback removes, and the destination name was
// never taken.
func TestCephCloneDisk_PartialCopyIsRemoved(t *testing.T) {
	f := newFakeCeph()
	f.partialCopy = true
	f.images["lv/src-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{}, run: f.run}
	if _, err := d.CloneDisk(context.Background(), "rbd:lv/src-root", DiskOptions{VMName: "dst", DiskName: "root"}); err == nil {
		t.Fatal("a failed copy reported success")
	}
	for ref := range f.images {
		if ref != "lv/src-root" {
			t.Errorf("left behind: %s (calls %v)", ref, f.calls)
		}
	}
	if f.called("deep cp lv/src-root lv/dst-root"+incomingMarker) != 1 {
		t.Errorf("the copy did not go to a staging name: %v", f.calls)
	}
}

// I3. rbd exits 2 (ENOENT) both for an image that is gone and for a keyring
// or conf it cannot find. Only the first is "already deleted": a delete that
// cannot reach the cluster must fail, not report success and orphan the image.
func TestCephDeleteDisk_UnreachableClusterIsNotGone(t *testing.T) {
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	keyringMissing := []byte("2026-10-10T10:00:00 auth: unable to find a keyring on /etc/ceph/ceph.client.x.keyring: (2) No such file or directory\nrbd: couldn't connect to the cluster!\n")
	f.failOut["status"] = struct {
		out []byte
		err error
	}{keyringMissing, rbdExit(2)}
	f.failOut["ls"] = f.failOut["status"]
	d := &cephDriver{pool: "lv", opts: map[string]string{"id": "x", "keyring": "/etc/ceph/ceph.client.x.keyring"}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err == nil {
		t.Fatal("a delete that could not reach the cluster reported success")
	}
}

// An image that really is gone (the cluster answers, the image does not
// exist) is deleted already.
func TestCephDeleteDisk_GoneImageIsDeleted(t *testing.T) {
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("an image already gone: %v", err)
	}
}

// I4. A create cancelled while it grows its fresh clone still removes the
// clone: rollback commands do not run on the cancelled request context.
func TestCephCreateDisk_CancelledGrowStillRemovesTheClone(t *testing.T) {
	f := newFakeCeph()
	f.installSleep(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.before["resize"] = cancel
	f.fail["resize"] = context.Canceled // the rbd resize is killed: its image keeps a watch
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run, scratch: t.TempDir()}
	if _, err := d.CreateDisk(ctx, DiskOptions{VMName: "a", DiskName: "root", SizeBytes: 8 << 30, SourceImage: storeImage(t), SourceImageName: "cirros", SourceImageDigest: strings.Repeat("34", 32)}); err == nil {
		t.Fatal("a cancelled create succeeded")
	}
	for ref := range f.images {
		if ref == "lv/a-root" || strings.Contains(ref, incomingMarker) {
			t.Fatalf("the cancelled create left %s (calls %v)", ref, f.calls)
		}
	}
	// N2: the clone is grown under a staging name, never under the VM's own.
	if f.called("resize lv/a-root"+incomingMarker) != 1 {
		t.Fatalf("the clone was not grown under a staging name: %v", f.calls)
	}
}

// I4. A stale staging import (a crash after `snap protect`) is removed by the
// next import's sweep: its protected snapshot is unprotected and purged first,
// or rbd refuses the rm and it leaks forever.
func TestCephSweepIncoming_RemovesAProtectedLeftover(t *testing.T) {
	f := newFakeCeph()
	stale := "lv/lvimage+cirros+0011" + incomingMarker + "1000-0123456789ab"
	f.images[stale] = map[string]bool{"base": true}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	f.listing = []string{strings.TrimPrefix(stale, "lv/")}
	d.sweepIncoming(context.Background(), "lv/lvimage+cirros+0011", time.Unix(1000, 0).Add(48*time.Hour))
	if f.has(stale) {
		t.Fatalf("a protected stale import was left: %v", f.calls)
	}
}

// M12 / M3. One escape-aware locator parser for every reader: a value with
// escaped ':' or ';' anywhere in the option list is read whole.
func TestParseCephLocator(t *testing.T) {
	l, ok := ParseCephLocator(`rbd:lv/ns/vm-root:mon_host=10.0.0.1\:6789\;10.0.0.2\:6789:id=litevirt:keyring=/k:lvpool=ceph`)
	if !ok {
		t.Fatal("not parsed")
	}
	if l.Spec != "lv/ns/vm-root" || l.Pool != "lv/ns" || l.Image != "vm-root" {
		t.Errorf("spec %q pool %q image %q", l.Spec, l.Pool, l.Image)
	}
	if l.Opts["id"] != "litevirt" || l.Opts["keyring"] != "/k" || l.Opts["lvpool"] != "ceph" || l.Opts["mon_host"] != "10.0.0.1:6789;10.0.0.2:6789" {
		t.Errorf("opts %v", l.Opts)
	}
	for _, bad := range []string{"vm-root", "rbd:noslash", "rbd:lv/", "rbd:/img"} {
		if _, ok := ParseCephLocator(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// M7. A root disk cloned from an image bigger than the size asked for is the
// image's size: the driver reports it, so the row records what exists.
func TestCephDiskSize_ReportsTheImagesSize(t *testing.T) {
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	f.sizes["lv/a-root"] = 4 << 30
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	got, err := d.DiskSize(context.Background(), "rbd:lv/a-root:id=x")
	if err != nil || got != 4<<30 {
		t.Fatalf("DiskSize = %d, %v; want 4 GiB", got, err)
	}
}

// A pool's own mon_host option is kept in the locator as the fallback for a
// host where the pool cannot be looked up; the pool's current value wins at
// define time.
func TestCephDiskLocator_PoolMonHostOptionIsAFallback(t *testing.T) {
	f := newFakeCeph()
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{"mon_host": "10.0.0.1:6789,10.0.0.2"}, run: f.run}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "data", SizeBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if want := `rbd:lv/vm-data:lvpool=ceph:mon_host=10.0.0.1\:6789\;10.0.0.2`; path != want {
		t.Fatalf("locator %q, want %q", path, want)
	}
}

// N2. A clone sweeps the stale staging copies a killed earlier clone left in
// its pool before it copies.
func TestCephCloneDisk_SweepsItsStaleStaging(t *testing.T) {
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/src-root"] = map[string]bool{}
	stale := "lv/dst-root" + incomingMarker + "1000-0123456789ab"
	f.images[stale] = map[string]bool{}
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{}, run: f.run}
	if _, err := d.CloneDisk(context.Background(), "rbd:lv/src-root", DiskOptions{VMName: "dst", DiskName: "root"}); err != nil {
		t.Fatal(err)
	}
	if f.has(stale) {
		t.Fatalf("a stale staging copy was left: %v", f.calls)
	}
}

// N2. A clone whose copy is killed leaves the dead client's watch on its
// staging image; the rollback retries the rm until the watch expires.
func TestCephCloneDisk_KilledCopyStagingIsRemovedAfterTheWatchExpires(t *testing.T) {
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/src-root"] = map[string]bool{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.before["deep cp"] = func() {
		// rbd created the staging image — with the source's snapshot, which
		// deep cp copies — then was killed.
		for _, c := range f.calls {
			if strings.HasPrefix(c, "deep cp ") {
				f.images[strings.Fields(c)[3]] = map[string]bool{"s1": false}
			}
		}
		cancel()
	}
	f.fail["deep cp"] = context.Canceled
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{}, run: f.run}
	if _, err := d.CloneDisk(ctx, "rbd:lv/src-root", DiskOptions{VMName: "dst", DiskName: "root"}); err == nil {
		t.Fatal("a killed copy succeeded")
	}
	for ref := range f.images {
		if ref != "lv/src-root" {
			t.Fatalf("left behind %s: %v", ref, f.calls)
		}
	}
}

// N4. The sweep removes only names the driver mints: a '+' marker (no VM,
// disk or image name can hold '+') and a 12-hex random suffix. A user's VM
// disk spelled like an old staging name is never touched.
func TestCephSweepIncoming_NeverMatchesAUserName(t *testing.T) {
	f := newFakeCeph()
	f.installSleep(t)
	user := "lv/web.litevirt-incoming-1-root" // VM "web.litevirt-incoming-1", disk "root"
	notOurs := "lv/x+litevirt-incoming-1000-notarandomid"
	ours := "lv/x+litevirt-incoming-1000-0123456789ab"
	for _, ref := range []string{user, notOurs, ours} {
		f.images[ref] = map[string]bool{}
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	d.sweepIncoming(context.Background(), "lv/x", time.Unix(1000, 0).Add(48*time.Hour))
	if !f.has(user) || !f.has(notOurs) {
		t.Fatalf("the sweep removed a name it did not mint: %v", f.calls)
	}
	if f.has(ours) {
		t.Fatalf("the sweep left its own stale staging: %v", f.calls)
	}
}

// N6. "Already gone" needs the pool to answer AND not list the image.
func TestCephDeleteDisk_ListedImageIsNotGone(t *testing.T) {
	f := newFakeCeph()
	f.failOut["status"] = struct {
		out []byte
		err error
	}{[]byte("rbd: error opening image a-root: (2) No such file or directory"), rbdExit(2)}
	f.listing = []string{"other", "a-root"}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err == nil {
		t.Fatal("an image the pool still lists was reported deleted")
	}
}

// N9. The rbd CLI uses the pool's mon_host option, as the domains do.
func TestRbdArgs_PassesThePoolsMonHost(t *testing.T) {
	d := &cephDriver{pool: "lv", opts: map[string]string{"id": "x", "mon_host": "[v2:10.0.0.1:3300/0,v1:10.0.0.1:6789/0] 10.0.0.2"}}
	got := strings.Join(d.rbdArgs("ls", "--", "lv"), " ")
	if !strings.Contains(got, "-m 10.0.0.1:6789,10.0.0.2 ") {
		t.Fatalf("rbd args %q, want -m with the pool's monitors", got)
	}
}

// N8. The zfs and lvm-thin drivers run their tools through the shared,
// overridable runner, so a caller's rollback can be tested.
func TestVolumeDrivers_RunThroughTheRunner(t *testing.T) {
	var calls []string
	defer OverrideVolumeRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	})()
	ctx := context.Background()
	z := &zfsDriver{dataset: "tank/lv", opts: map[string]string{}}
	p, err := z.CreateDisk(ctx, DiskOptions{VMName: "vm", DiskName: "data", SizeBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := z.DeleteDisk(ctx, p); err != nil {
		t.Fatal(err)
	}
	l := &lvmThinDriver{vg: "vg0", opts: map[string]string{"thinpool": "pool0"}}
	lp, err := l.CreateDisk(ctx, DiskOptions{VMName: "vm", DiskName: "data", SizeBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.DeleteDisk(ctx, lp); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(calls, "\n")
	for _, want := range []string{"zfs create -V 1073741824 -- tank/lv/vm-data", "zfs destroy -r -- tank/lv/vm-data", "lvcreate ", "lvremove -f -- vg0/vm-data"} {
		if !strings.Contains(got, want) {
			t.Errorf("runner calls lack %q:\n%s", want, got)
		}
	}
}

// probeRun answers `rbd info` with out/exit, and `rbd ls` per lsOK.
func probeRun(out string, exit int, lsOK bool, seen *[]string) cmdRunner {
	return func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		*seen = append(*seen, strings.Join(args, " "))
		for _, a := range args {
			switch a {
			case "info":
				if exit == -1 {
					return nil, context.DeadlineExceeded
				}
				return []byte(out), rbdExit(exit)
			case "ls":
				if lsOK {
					return []byte("other-image"), nil
				}
				return []byte("rbd: couldn't connect to the cluster!"), rbdExit(110)
			}
		}
		return nil, nil
	}
}

// I-R2-1. A start refuses for good (FailedPrecondition) only on a failure an
// operator must fix: a key the cluster denies (rbd exits 1 for EPERM — the
// same as a generic failure, so only rbd's "Operation not permitted" text
// counts — or 13 for EACCES), or an image that is not in a pool that answers.
// Anything else — a timeout, a killed rbd, a generic exit 1, an unreachable
// cluster — is transient, and the start is retried as on main.
func TestCephProbeDisk_ClassifiesPermanentAndTransient(t *testing.T) {
	keyring := "/etc/ceph/ceph.client.litevirt.keyring"
	for _, tc := range []struct {
		name      string
		out       string
		exit      int
		lsOK      bool
		permanent bool
	}{
		{"EPERM by its text", "rbd: error opening image x: (1) Operation not permitted", 1, true, true},
		{"generic exit 1", "rbd: unknown error", 1, true, false},
		{"EACCES", "rbd: error opening image x: (13) Permission denied", 13, true, true},
		{"ENOENT, pool answers", "rbd: error opening image x: (2) No such file or directory", 2, true, true},
		{"ENOENT, pool does not answer", "auth: unable to find a keyring: (2) No such file or directory", 2, false, false},
		{"ETIMEDOUT", "rbd: couldn't connect to the cluster!", 110, true, false},
		{"killed", "", -1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			d := &cephDriver{pool: "lv", opts: map[string]string{"id": "litevirt", "keyring": keyring}, run: probeRun(tc.out, tc.exit, tc.lsOK, &seen)}
			err := d.ProbeDisk(context.Background(), "rbd:lv/x:id=litevirt:keyring="+keyring+":lvpool=ceph")
			if err == nil {
				t.Fatal("no error")
			}
			if got := IsPermanentCephError(err); got != tc.permanent {
				t.Fatalf("permanent = %v, want %v (%v)", got, tc.permanent, err)
			}
			if tc.permanent && tc.exit != 2 && !strings.Contains(err.Error(), keyring) {
				t.Errorf("a key refusal must name the keyring the pool names: %v", err)
			}
		})
	}
}

// I-R2-1. The probe is bounded by rbd's own timeouts and by ProbeBound.
func TestCephProbeDisk_IsBounded(t *testing.T) {
	var seen []string
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: probeRun("", 0, true, &seen)}
	_ = d.ProbeDisk(context.Background(), "rbd:lv/x")
	if len(seen) != 1 || !strings.Contains(seen[0], "--client_mount_timeout") || !strings.Contains(seen[0], "--rados_osd_op_timeout") {
		t.Fatalf("rbd info args %q, want rbd's own timeouts", seen)
	}
}

// Lab 2: a killed client's watch makes rbd BLOCK about 30 s on the image's
// lock and then succeed. `rbd trash mv` takes that lock, so every move gets a
// context of its own that outlasts it, even when its caller's is shorter.
func TestCephTrashMove_PerCallTimeoutOutlastsABlockingWatch(t *testing.T) {
	resetCephPurges(t)
	var deadline time.Duration
	moved := false
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		switch strings.Join(args[:2], " ") {
		case "status --format":
			return []byte(`{"watchers":[]}`), nil
		case "info --format":
			return []byte(`{"size":1,"id":"abc123"}`), nil
		case "trash mv":
			moved = true
			if dl, ok := ctx.Deadline(); ok {
				deadline = time.Until(dl)
			}
		}
		return nil, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.DeleteDisk(ctx, "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	if !moved || deadline < 45*time.Second {
		t.Fatalf("rbd trash mv ran (%v) with %v left, want at least 45 s", moved, deadline)
	}
}

// m2. A user delete of an image another client has open waits out a dead
// client's watch (30 s), then refuses with "in use" and who holds it — it
// does not wait out the rollback budget, and never moves an image a live
// client has open into the trash.
func TestCephDeleteDisk_InUseRefusesQuickly(t *testing.T) {
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/a-root"] = map[string]bool{}
	f.watched = map[string]time.Duration{"lv/a-root": time.Hour}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	err := d.DeleteDisk(context.Background(), "rbd:lv/a-root")
	if err == nil || !strings.Contains(err.Error(), "in use") || !strings.Contains(err.Error(), "10.78.0.13") {
		t.Fatalf("got %v, want an 'in use' refusal naming the watcher", err)
	}
	if f.now > rbdBusyBudget-time.Second {
		t.Fatalf("a user delete waited %v", f.now)
	}
	if !f.has("lv/a-root") || f.called("trash mv") != 0 {
		t.Fatalf("an image a live client has open was removed or trashed: %v", f.calls)
	}
}
