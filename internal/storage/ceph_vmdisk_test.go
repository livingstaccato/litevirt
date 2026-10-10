package storage

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCeph models the rbd semantics the VM-disk paths turn on: images and
// their snapshots exist or not, clone/import/create/rename/deep cp refuse an
// existing destination, rm refuses an image with snapshots, a protected
// snapshot cannot be removed. Every call is recorded as "<sub> <positional…>".
type fakeCeph struct {
	images map[string]map[string]bool // "pool/image" → snapshot → protected
	sizes  map[string]int64
	calls  []string
	fail   map[string]error // subcommand → injected failure
}

func newFakeCeph() *fakeCeph {
	return &fakeCeph{images: map[string]map[string]bool{}, sizes: map[string]int64{}, fail: map[string]error{}}
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

func (f *fakeCeph) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "qemu-img" {
		f.calls = append(f.calls, "qemu-img "+strings.Join(args, " "))
		if err := f.fail["qemu-img"]; err != nil {
			return []byte("qemu-img: injected"), err
		}
		return nil, os.WriteFile(args[len(args)-1], []byte("raw"), 0o600)
	}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "--") {
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
	if sub == "snap" || sub == "deep" {
		sub += " " + words[1]
	}
	f.calls = append(f.calls, strings.TrimSpace(sub+" "+strings.Join(pos, " ")))
	if err := f.fail[sub]; err != nil {
		return []byte("rbd: injected failure"), err
	}
	exists := []byte("rbd: create error: (17) File exists")
	missing := []byte("rbd: error opening image: (2) No such file or directory")
	switch sub {
	case "ls", "import":
		if sub == "import" {
			dst := pos[1]
			if f.has(dst) {
				return exists, errors.New("exit 17")
			}
			f.images[dst] = map[string]bool{}
			f.sizes[dst] = 512 << 20
		}
		return nil, nil
	case "create":
		if f.has(pos[0]) {
			return exists, errors.New("exit 17")
		}
		f.images[pos[0]] = map[string]bool{}
		return nil, nil
	case "info":
		ref, snap, _ := strings.Cut(pos[0], "@")
		if !f.has(ref) {
			return missing, errors.New("exit 2")
		}
		if snap != "" {
			if _, ok := f.images[ref][snap]; !ok {
				return missing, errors.New("exit 2")
			}
		}
		return []byte(fmt.Sprintf(`{"size":%d}`, f.sizes[ref])), nil
	case "clone":
		ref, snap, _ := strings.Cut(pos[0], "@")
		if prot, ok := f.images[ref][snap]; !ok || !prot {
			return []byte("rbd: parent snapshot must be protected"), errors.New("exit 22")
		}
		if f.has(pos[1]) {
			return exists, errors.New("exit 17")
		}
		f.images[pos[1]] = map[string]bool{}
		f.sizes[pos[1]] = f.sizes[ref]
		return nil, nil
	case "deep cp":
		if !f.has(pos[0]) {
			return missing, errors.New("exit 2")
		}
		if f.has(pos[1]) {
			return exists, errors.New("exit 17")
		}
		f.images[pos[1]] = map[string]bool{}
		f.sizes[pos[1]] = f.sizes[pos[0]]
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
			return []byte("rbd: snapshot is protected"), errors.New("exit 16")
		}
		delete(f.images[ref], snap)
		return nil, nil
	case "rename":
		if f.has(pos[1]) {
			return exists, errors.New("exit 17")
		}
		f.images[pos[1]] = f.images[pos[0]]
		f.sizes[pos[1]] = f.sizes[pos[0]]
		delete(f.images, pos[0])
		return nil, nil
	case "rm":
		if !f.has(pos[0]) {
			return missing, errors.New("exit 2")
		}
		if f.snaps(pos[0]) > 0 {
			return []byte("rbd: image has snapshots - not removing"), errors.New("exit 39")
		}
		delete(f.images, pos[0])
		return nil, nil
	}
	return nil, nil
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
	d := &cephDriver{pool: "lv", opts: map[string]string{"id": "litevirt", "conf": conf, "keyring": keyring}, run: f.run}
	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "data", SizeBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	want := "rbd:lv/vm-data:id=litevirt:keyring=" + keyring + ":conf=" + conf + `:mon_host=10.78.0.22\:6789`
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
	f.fail["resize"] = errors.New("exit 1")
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run, scratch: t.TempDir()}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "a", DiskName: "root", SizeBytes: 8 << 30, SourceImage: storeImage(t), SourceImageName: "cirros", SourceImageDigest: strings.Repeat("ef", 32)}); err == nil {
		t.Fatal("expected the resize failure")
	}
	if f.has("lv/a-root") {
		t.Fatalf("clone left behind after a failed create: %v", f.calls)
	}
}

// A failed import leaves no staging image and no base.
func TestCephCreateDisk_FailedImportLeavesNothing(t *testing.T) {
	f := newFakeCeph()
	f.fail["snap protect"] = errors.New("exit 1")
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
