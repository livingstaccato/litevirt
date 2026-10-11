package grpcapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// cephWorld stands in for a ceph cluster behind the rbd CLI (and qemu-img's
// convert to raw): which images exist, their protected snapshots, and every
// command, as "<sub> <positional…>". Installed with storage.OverrideCephRunnerForTest.
type cephWorld struct {
	mu     sync.Mutex
	images map[string]map[string]bool // ref → snapshot → protected
	sizes  map[string]int64
	calls  []string
	// infoExit makes `rbd info` exit with that status (rbd exits with the
	// errno: EPERM 1, ENOENT 2, ETIMEDOUT 110 …), printing infoOut.
	infoExit int
	infoOut  string
	// infoDelay is how long each `rbd info` takes (outside the lock, so
	// concurrent probes overlap as they do against a cluster).
	infoDelay time.Duration
	// trash is the pools' trash ("pool/id" → image name); trashRmExit
	// makes `rbd trash rm` fail with that status.
	trash       map[string]string
	trashRmExit int
	ids         map[string]string
	// down: rbd pools whose cluster does not answer — a probe of one of
	// their images waits out its context, then fails as rbd does (110).
	down map[string]bool
	// watchers: images a live client has open (`rbd status` lists it).
	watchers map[string]bool
	// probeLeft: the time each probe's context had left when it ran.
	probeLeft []time.Duration
	// downImages: images whose probe gets no answer (an inactive PG under
	// them), while the rest of their pool answers.
	downImages map[string]bool
	// trashMvExit / trashLsExit make `rbd trash mv` / `rbd trash ls` fail
	// with that status.
	trashMvExit, trashLsExit int
}

// cephExit is a failed rbd command as exec reports it (rbd exits with the errno).
type cephExit int

func (e cephExit) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e cephExit) ExitCode() int { return int(e) }

func installCephWorld(t *testing.T) *cephWorld {
	t.Helper()
	w := &cephWorld{images: map[string]map[string]bool{}, sizes: map[string]int64{}, trash: map[string]string{}, ids: map[string]string{}}
	t.Cleanup(storage.OverrideCephRunnerForTest(w.run))
	// Purges run only when a test runs them (storage.RunCephPurgesOnceForTest).
	t.Cleanup(storage.OverrideCephPurgeLoopForTest())
	return w
}

func (w *cephWorld) has(ref string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.images[ref]
	return ok
}

func (w *cephWorld) count(prefix string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, c := range w.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (w *cephWorld) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if slices.Contains(args, "info") && slices.Contains(args, "--client_mount_timeout") {
		w.mu.Lock()
		if dl, ok := ctx.Deadline(); ok {
			w.probeLeft = append(w.probeLeft, time.Until(dl))
		}
		down := false
		for _, a := range args {
			if p, _, ok := strings.Cut(a, "/"); ok && w.down[p] {
				down = true
			}
			if w.downImages[a] {
				w.calls = append(w.calls, "info (no answer)")
				w.mu.Unlock()
				return []byte("rbd: error opening image: (110) Connection timed out"), cephExit(110)
			}
		}
		w.mu.Unlock()
		if down {
			<-ctx.Done()
			w.mu.Lock()
			w.calls = append(w.calls, "info (no answer)")
			w.mu.Unlock()
			return []byte("rbd: couldn't connect to the cluster!"), cephExit(110)
		}
	}
	if w.infoDelay > 0 && slices.Contains(args, "info") && slices.Contains(args, "--client_mount_timeout") {
		time.Sleep(w.infoDelay)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if name == "rados" {
		// listwatchers of a trashed image's header: nobody has it open.
		w.calls = append(w.calls, "rados "+strings.Join(args, " "))
		return nil, nil
	}
	if name == "qemu-img" {
		w.calls = append(w.calls, "qemu-img convert")
		return nil, os.WriteFile(args[len(args)-1], []byte("raw"), 0o600)
	}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "--" {
		i += 2
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
	w.calls = append(w.calls, strings.TrimSpace(sub+" "+strings.Join(pos, " ")))
	missing := []byte("(2) No such file or directory")
	switch sub {
	case "create", "import", "clone", "deep cp":
		dst := pos[len(pos)-1]
		if _, ok := w.images[dst]; ok {
			return []byte("(17) File exists"), cephExit(17)
		}
		w.images[dst] = map[string]bool{}
		switch sub {
		case "import":
			w.sizes[dst] = 4 << 30 // the image's virtual size
		case "clone", "deep cp":
			src, _, _ := strings.Cut(pos[0], "@")
			w.sizes[dst] = w.sizes[src]
		default:
			w.sizes[dst] = 1 << 30
		}
	case "info":
		if w.infoExit != 0 {
			return []byte(w.infoOut), cephExit(w.infoExit)
		}
		ref, snap, _ := strings.Cut(pos[0], "@")
		s, ok := w.images[ref]
		if !ok {
			return missing, cephExit(2)
		}
		if _, ok := s[snap]; snap != "" && !ok {
			return missing, cephExit(2)
		}
		if w.ids[ref] == "" {
			w.ids[ref] = fmt.Sprintf("1%011x", len(w.ids)+len(w.trash)+1)
		}
		return []byte(fmt.Sprintf(`{"size":%d,"id":"%s","snapshot_count":%d}`, w.sizes[ref], w.ids[ref], len(s))), nil
	case "status":
		if _, ok := w.images[pos[0]]; !ok {
			return missing, cephExit(2)
		}
		if w.watchers[pos[0]] {
			return []byte(`{"watchers":[{"address":"10.78.0.11:0/719770507","client":14688,"cookie":133234583145840}]}`), nil
		}
		return []byte(`{"watchers":[]}`), nil
	case "trash mv":
		if w.trashMvExit != 0 {
			return []byte("rbd: injected trash mv failure"), cephExit(w.trashMvExit)
		}
		if _, ok := w.images[pos[0]]; !ok {
			return missing, cephExit(2)
		}
		pool, img, _ := strings.Cut(pos[0], "/")
		w.trash[pool+"/"+w.ids[pos[0]]] = img
		delete(w.images, pos[0])
		delete(w.ids, pos[0])
	case "trash rm":
		if w.trashRmExit == 16 {
			// Lab 2, verbatim: a client still has the trashed image open.
			return []byte("rbd: error: image still has watchers\nimage has watchers - not removing"), cephExit(16)
		}
		if w.trashRmExit != 0 {
			return []byte("rbd: error: (110) Connection timed out"), cephExit(w.trashRmExit)
		}
		if _, ok := w.trash[pos[0]]; !ok {
			return missing, cephExit(2)
		}
		delete(w.trash, pos[0])
	case "trash ls":
		if w.trashLsExit != 0 {
			return []byte("rbd: injected trash ls failure"), cephExit(w.trashLsExit)
		}
		// 19.2.3: `source` only with --long.
		long := slices.Contains(words, "--long")
		var entries []string
		for k, name := range w.trash {
			if p, id, _ := strings.Cut(k, "/"); p == pos[0] {
				if long {
					entries = append(entries, fmt.Sprintf(`{"id":"%s","name":"%s","source":"USER","deleted_at":"Fri Oct 10 22:56:08 2026","status":"expired at Fri Oct 10 22:56:08 2026"}`, id, name))
				} else {
					entries = append(entries, fmt.Sprintf(`{"id":"%s","name":"%s"}`, id, name))
				}
			}
		}
		slices.Sort(entries)
		return []byte("[" + strings.Join(entries, ",") + "]"), nil
	case "snap create", "snap protect":
		ref, snap, _ := strings.Cut(pos[0], "@")
		w.images[ref][snap] = sub == "snap protect"
	case "rename":
		if _, ok := w.images[pos[1]]; ok {
			return []byte("(17) File exists"), cephExit(17)
		}
		w.images[pos[1]] = w.images[pos[0]]
		w.sizes[pos[1]] = w.sizes[pos[0]]
		delete(w.images, pos[0])
	case "resize":
		w.sizes[pos[0]] = 1 // asserted from the call
	case "rm":
		if _, ok := w.images[pos[0]]; !ok {
			return missing, cephExit(2)
		}
		delete(w.images, pos[0])
	}
	return nil, nil
}

// cephPoolFixture: a ceph pool "ceph" on test-host over rbd pool "lv", whose
// nodes hold only a restricted client key (client.litevirt) — no admin key.
type cephPoolFixture struct {
	s       *Server
	fake    *libvirtfake.Fake
	world   *cephWorld
	keyring string
	key     []byte
	secret  string
}

func writeKeyring(t *testing.T, path string, key []byte) {
	t.Helper()
	body := "[client.litevirt]\n\tkey = " + base64.StdEncoding.EncodeToString(key) + "\n\tcaps osd = \"profile rbd pool=lv\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newCephPoolFixture(t *testing.T) *cephPoolFixture {
	t.Helper()
	s, fake := provableCreateServer(t)
	f := &cephPoolFixture{s: s, fake: fake, world: installCephWorld(t)}
	dir := t.TempDir()
	conf := filepath.Join(dir, "ceph.conf")
	if err := os.WriteFile(conf, []byte("[global]\nmon_host = [v2:10.78.0.22:3300/0,v1:10.78.0.22:6789/0]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.keyring = filepath.Join(dir, "ceph.client.litevirt.keyring")
	f.key = []byte("restricted-client-key-bytes!")
	writeKeyring(t, f.keyring, f.key)
	// I2: the secret is the POOL's (pool name + client), whatever path a
	// host keeps the keyring at.
	f.secret = lv.CephSecretUUID("ceph", "litevirt")
	opts := map[string]string{"id": "litevirt", "conf": conf, "keyring": f.keyring}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: "test-host", Name: "ceph", Driver: "ceph", Source: "lv", Options: opts, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.addStoragePoolRef("ceph", StoragePoolRef{Driver: "ceph", Source: "lv", Options: opts})
	return f
}

func (f *cephPoolFixture) requireSecretValue(t *testing.T, want []byte) {
	t.Helper()
	client, val, ok := f.fake.CephSecret(f.secret)
	if !ok {
		t.Fatalf("ceph secret %s is not defined", f.secret)
	}
	if client != "litevirt" || !bytes.Equal(val, want) {
		t.Fatalf("ceph secret holds client %q value %q, want client litevirt value %q", client, val, want)
	}
}

// The secret's whole life on one host: defined from the pool's keyring,
// put back after libvirtd drops it, re-set when the keyring is rotated, and
// removed with the pool — unless a disk on this host still uses it.
func TestCephSecret_Lifecycle(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()

	f.s.ReconcileCephSecrets(ctx)
	f.requireSecretValue(t, f.key)

	f.fake.DropSecrets() // a libvirtd restart: the secrets are ephemeral
	f.s.ReconcileCephSecrets(ctx)
	f.requireSecretValue(t, f.key)

	rotated := []byte("a-rotated-client-key-value!!")
	writeKeyring(t, f.keyring, rotated)
	f.s.ReconcileCephSecrets(ctx)
	f.requireSecretValue(t, rotated)

	// A disk on this host uses it: deleting the pool keeps the secret.
	if err := corrosion.InsertDisk(ctx, f.s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/vm1-data:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "ceph", Force: true}); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	if ok, _ := f.fake.HasSecret(f.secret); !ok {
		t.Fatal("the secret of a disk still on this host was removed with its pool")
	}
	// Once nothing uses it, it goes.
	if err := corrosion.SoftDeleteDisk(ctx, f.s.db, "vm1", "data"); err != nil {
		t.Fatal(err)
	}
	f.s.ReconcileCephSecrets(ctx)
	if ok, _ := f.fake.HasSecret(f.secret); ok {
		t.Fatal("a secret no pool or disk uses was kept")
	}
}

// A pool create defines its secret at once.
func TestCephSecret_DefinedByPoolCreate(t *testing.T) {
	f := newCephPoolFixture(t)
	if _, err := f.s.ensureCephSecret(storage.Config{Name: "ceph", Driver: "ceph", Source: "lv", Options: map[string]string{"id": "litevirt", "keyring": f.keyring}}); err != nil {
		t.Fatal(err)
	}
	f.requireSecretValue(t, f.key)
	// The value is never in the fake's event log.
	for _, e := range f.fake.EventLog() {
		if strings.Contains(e.Note, string(f.key)) || strings.Contains(e.Note, base64.StdEncoding.EncodeToString(f.key)) {
			t.Fatalf("event %+v carries the key", e)
		}
	}
}

func cephCreateRequest(name string, disks ...*pb.DiskSpec) *pb.CreateVMRequest {
	req := disklessCreateRequest(name)
	req.Spec.Disks = disks
	return req
}

// Lab 2 B6 attempt 2: a data disk on a ceph pool with a restricted key. The
// domain authenticates as client.litevirt through the pool's secret and finds
// the monitors from the pool's ceph.conf.
func TestCreateVM_CephDataDiskAuthenticatesWithTheRestrictedKey(t *testing.T) {
	f := newCephPoolFixture(t)
	if _, err := f.s.CreateVM(adminCtx(), cephCreateRequest("cephm", &pb.DiskSpec{Name: "data", Size: "1G", Storage: "ceph"})); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if !f.world.has("lv/cephm-data") {
		t.Fatalf("rbd image not created: %v", f.world.calls)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "cephm")
	if len(disks) != 1 || !strings.Contains(disks[0].Path, ":lvpool=ceph") || strings.Contains(disks[0].Path, "mon_host") {
		t.Fatalf("disk locator %+v: want the pool named and no monitors fixed in it", disks)
	}
	f.requireSecretValue(t, f.key)
	x, _ := f.fake.DumpXML("cephm")
	for _, want := range []string{
		`<source protocol="rbd" name="lv/cephm-data">`,
		`<host name="10.78.0.22" port="6789"></host>`,
		`<auth username="litevirt">`,
		`<secret type="ceph" uuid="` + f.secret + `"></secret>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("domain lacks %s:\n%s", want, x)
		}
	}
}

// Lab 2 B6 side effect: the failed create left lv/cephm-data behind. Every
// rbd image a failed create made is removed.
func TestCreateVM_FailedCreateRemovesItsCephImages(t *testing.T) {
	f := newCephPoolFixture(t)
	f.fake.FailDefineDomain = func(string) error { return errors.New("define fails") }
	_, err := f.s.CreateVM(adminCtx(), cephCreateRequest("cephm",
		&pb.DiskSpec{Name: "data", Size: "1G", Storage: "ceph"},
		&pb.DiskSpec{Name: "logs", Size: "1G", Storage: "ceph"}))
	if err == nil {
		t.Fatal("CreateVM succeeded with a failing define")
	}
	for _, ref := range []string{"lv/cephm-data", "lv/cephm-logs"} {
		if f.world.has(ref) {
			t.Errorf("failed create left %s behind (calls %v)", ref, f.world.calls)
		}
	}
}

// A second disk on a pool that does not resolve fails the create after the
// first disk exists: that one is removed too.
func TestCreateVM_UnknownSecondPoolRemovesTheFirstCephImage(t *testing.T) {
	f := newCephPoolFixture(t)
	_, err := f.s.CreateVM(adminCtx(), cephCreateRequest("cephm",
		&pb.DiskSpec{Name: "data", Size: "1G", Storage: "ceph"},
		&pb.DiskSpec{Name: "more", Size: "1G", Storage: "no-such-pool"}))
	if err == nil {
		t.Fatal("CreateVM succeeded with an unknown pool")
	}
	if f.world.has("lv/cephm-data") {
		t.Fatalf("the first disk's image was left behind: %v", f.world.calls)
	}
}

// Lab 2 B6 attempt 1: a root disk on ceph from an image. The image (pulled
// into the store by name, like any other) is imported into the pool once and
// the root disk is a clone of its protected snapshot.
func TestCreateVM_CephRootDiskFromImage(t *testing.T) {
	f := newCephPoolFixture(t)
	if err := qcow2.Create(f.s.images.ImagePath("cirros"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	req := cephCreateRequest("web", &pb.DiskSpec{Name: "root", Size: "1G", Storage: "ceph"})
	req.Spec.Image = "cirros"
	if _, err := f.s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM: %v (calls %v)", err, f.world.calls)
	}
	if f.world.count("import") != 1 || f.world.count("clone lv/lvimage+cirros+") != 1 || !f.world.has("lv/web-root") {
		t.Fatalf("root disk not cloned from an imported base: %v", f.world.calls)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	if len(disks) != 1 || !strings.HasPrefix(disks[0].Path, "rbd:lv/web-root:id=litevirt:") || disks[0].StorageType != "ceph" {
		t.Fatalf("disk rows %+v", disks)
	}
	// M7: a clone of a 4 GiB image asked for at 1G IS 4 GiB, and the row says so.
	if disks[0].SizeBytes != 4<<30 {
		t.Fatalf("root disk row size %d, want the clone's real 4 GiB", disks[0].SizeBytes)
	}
	// No backing image is recorded: a peer that cannot see the rbd disk as a
	// file (an older build, on a failover) must refuse, not rebuild it as a
	// blank local overlay of the image.
	if disks[0].BackingImage != "" {
		t.Fatalf("an rbd root disk records backing image %q", disks[0].BackingImage)
	}
}

// A VM clone on ceph copies inside the pool (rbd deep cp), and the clone's
// disk is a ceph disk on the same pool, authenticating the same way.
func TestCloneVM_CephDisksAreCopiedInThePool(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := adminCtx()
	src := "rbd:lv/tpl-root:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph"
	f.world.images["lv/tpl-root"] = map[string]bool{}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, f.s.db, corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: src, SizeBytes: 1 << 30, StorageType: "ceph", StorageVolume: "ceph"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "copy", Mode: "linked"}); err == nil {
		t.Fatal("a linked clone of a ceph disk was accepted")
	}
	if _, err := f.s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "copy"}); err != nil {
		t.Fatalf("CloneVM: %v (calls %v)", err, f.world.calls)
	}
	if f.world.count("deep cp lv/tpl-root lv/copy-root") != 1 {
		t.Fatalf("not copied in the pool: %v", f.world.calls)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "copy")
	if len(disks) != 1 || disks[0].StorageType != "ceph" || disks[0].StorageVolume != "ceph" || !strings.HasPrefix(disks[0].Path, "rbd:lv/copy-root:") {
		t.Fatalf("clone disk rows %+v", disks)
	}
	x, _ := f.fake.DumpXML("copy")
	if !strings.Contains(x, fmt.Sprintf(`<secret type="ceph" uuid="%s">`, f.secret)) {
		t.Fatalf("clone domain does not authenticate through the pool's secret:\n%s", x)
	}
}

// A clone whose define fails removes the rbd copy it made.
func TestCloneVM_FailedCephCloneRemovesTheCopy(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := adminCtx()
	f.world.images["lv/tpl-root"] = map[string]bool{}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, f.s.db, corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: "rbd:lv/tpl-root", SizeBytes: 1 << 30, StorageType: "ceph", StorageVolume: "ceph"}}); err != nil {
		t.Fatal(err)
	}
	f.fake.FailDefineDomain = func(string) error { return errors.New("define fails") }
	if _, err := f.s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "copy"}); err == nil {
		t.Fatal("clone succeeded with a failing define")
	}
	if f.world.has("lv/copy-root") {
		t.Fatalf("failed clone left lv/copy-root behind: %v", f.world.calls)
	}
	if !f.world.has("lv/tpl-root") {
		t.Fatal("the source's image was removed")
	}
}

// Every start path puts the secret back first (PrepareHardwareForStart).
func TestPrepareHardwareForStart_DefinesTheCephSecret(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	vm := corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"}
	f.world.images["lv/vm1-data"] = map[string]bool{}
	if err := corrosion.InsertVM(ctx, f.s.db, vm, nil, []corrosion.DiskRecord{{
		VMName: "vm1", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/vm1-data:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph",
	}}); err != nil {
		t.Fatal(err)
	}
	f.fake.DropSecrets()
	if _, err := f.s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("PrepareHardwareForStart: %v", err)
	}
	f.requireSecretValue(t, f.key)
}

// A ceph disk deleted after its pool left this host's pool list is removed as
// the identity its locator names — never as client.admin, which a node with
// only the restricted key cannot be.
func TestDeleteRecordedVMDiskVolumes_CephDiskWithoutItsPool(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := context.Background()
	var rmArgs []string
	t.Cleanup(storage.OverrideCephPurgeLoopForTest())
	t.Cleanup(storage.OverrideCephRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch {
		case slices.Contains(args, "status"):
			return []byte(`{"watchers":[]}`), nil
		case slices.Contains(args, "info"):
			return []byte(`{"id":"1abc"}`), nil
		case slices.Contains(args, "mv"):
			rmArgs = args
		}
		return nil, nil
	}))
	insertTestVM(t, ctx, s.db, "vm1", "test-host", "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "gone",
		Path: "rbd:lv/vm1-data:id=litevirt:keyring=/etc/ceph/ceph.client.litevirt.keyring", DeleteWithVM: true,
	}); err != nil {
		t.Fatal(err)
	}
	s.deleteRecordedVMDiskVolumes(ctx, "vm1")
	got := strings.Join(rmArgs, " ")
	if !strings.Contains(got, "--id litevirt") || !strings.Contains(got, "--keyring /etc/ceph/ceph.client.litevirt.keyring") || !strings.HasSuffix(got, "trash mv -- lv/vm1-data") {
		t.Fatalf("rbd trash mv args = %q, want the locator's identity and lv/vm1-data", got)
	}
}

// insertCephVM records a stopped VM on host with one rbd data disk of the
// fixture's pool.
func (f *cephPoolFixture) insertCephVM(t *testing.T, name, host string) corrosion.VMRecord {
	t.Helper()
	f.world.mu.Lock()
	f.world.images["lv/"+name+"-data"] = map[string]bool{}
	f.world.mu.Unlock()
	vm := corrosion.VMRecord{Name: name, HostName: host, State: "stopped", Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(context.Background(), f.s.db, vm, nil, []corrosion.DiskRecord{{
		VMName: name, DiskName: "data", HostName: host, StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/" + name + "-data:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph", DeleteWithVM: true,
	}}); err != nil {
		t.Fatal(err)
	}
	return vm
}

// peerPoolRow records host's row of the ceph pool, with a key fingerprint.
func (f *cephPoolFixture) peerPoolRow(t *testing.T, host, fp string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: host, Name: "ceph", Driver: "ceph", Source: "lv", State: "active",
		Options: map[string]string{"id": "litevirt", "keyring": "/elsewhere/k", storage.CephKeyFPOption: fp},
	}); err != nil {
		t.Fatal(err)
	}
}

// I1. A live migration's target defines the secrets of the VM's ceph disks
// when the source prepares it (EnsureDisks), whatever libvirtd lost.
func TestEnsureDisks_DefinesTheCephSecretOnTheTarget(t *testing.T) {
	f := newCephPoolFixture(t)
	f.insertCephVM(t, "mig", "src-host")
	f.fake.DropSecrets()
	if _, err := f.s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig"}); err != nil {
		t.Fatalf("EnsureDisks: %v", err)
	}
	f.requireSecretValue(t, f.key)
}

// I1. A target that cannot define the secret refuses the migration up front,
// with the reason — not an opaque qemu failure at the incoming phase.
func TestEnsureDisks_RefusesWhenTheSecretCannotBeDefined(t *testing.T) {
	f := newCephPoolFixture(t)
	f.insertCephVM(t, "mig", "src-host")
	f.fake.DropSecrets()
	if err := os.Remove(f.keyring); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ceph") {
		t.Fatalf("got %v, want FailedPrecondition naming ceph", err)
	}
}

// I2. A target whose keyring holds a different key than the source's (the
// pool rows' recorded fingerprints) refuses the migration with that reason.
func TestEnsureDisks_RefusesAKeyThatDiffersFromTheSource(t *testing.T) {
	f := newCephPoolFixture(t)
	f.peerPoolRow(t, "src-host", "0123456789abcdef")
	f.insertCephVM(t, "mig", "src-host")
	_, err := f.s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "keyring") || !strings.Contains(err.Error(), "test-host") {
		t.Fatalf("got %v, want FailedPrecondition naming the keyring and this host", err)
	}
}

// I2. Each host records its key's fingerprint on its own pool row; a host
// whose key differs from the others' raises a degraded condition naming it,
// and refuses to start (a failover onto it) with the reason. Once the keys
// agree the condition resolves and starts go ahead.
func TestCephKeyFingerprint_MismatchRaisesAConditionAndRefusesStarts(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	f.s.ReconcileCephSecrets(ctx)
	own, found, err := corrosion.GetStoragePool(ctx, f.s.db, "test-host", "ceph")
	if err != nil || !found || own.Options[storage.CephKeyFPOption] != storage.CephKeyFingerprint(f.key) {
		t.Fatalf("own row %+v, %v, %v: want the key's fingerprint recorded", own.Options, found, err)
	}

	f.peerPoolRow(t, "host-b", "0123456789abcdef")
	f.peerPoolRow(t, "host-c", "0123456789abcdef")
	f.s.ReconcileCephSecrets(ctx)
	c, ok, err := corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephKeyringMismatch, "host", "ceph@test-host")
	if err != nil || !ok || c.Lifecycle == corrosion.ConditionResolved || c.Severity != corrosion.SeverityWarning ||
		!strings.Contains(c.Evidence, "test-host") || len(c.Hosts) == 0 || c.Hosts[0] != "test-host" {
		t.Fatalf("condition %+v, %v, %v; want an open warning naming test-host", c, ok, err)
	}
	// N3: the fingerprints are a diagnostic only — a host in the minority (a
	// key rotation in progress, or rows of hosts that are down or gone) still
	// starts what its own key can open; rbd itself is the proof.
	vm := f.insertCephVM(t, "fo", "test-host")
	if _, err := f.s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("start on the minority host whose key opens the disk: %v", err)
	}

	f.peerPoolRow(t, "host-b", storage.CephKeyFingerprint(f.key))
	f.peerPoolRow(t, "host-c", storage.CephKeyFingerprint(f.key))
	f.s.ReconcileCephSecrets(ctx)
	if c, _, _ := corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephKeyringMismatch, "host", "ceph@test-host"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v once the keys agree, want resolved", c)
	}
	if _, err := f.s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("start once the keys agree: %v", err)
	}
}

// M4. A disk whose pool left this host keeps its secret — and after a
// libvirtd restart the secret is defined again from the disk's own locator.
func TestCephSecret_DiskWithoutItsPoolIsRedefinedFromItsLocator(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	f.insertCephVM(t, "orphan", "test-host")
	f.s.removeStoragePoolRef("ceph")
	if err := corrosion.MarkStoragePoolDeleted(ctx, f.s.db, "test-host", "ceph"); err != nil {
		t.Fatal(err)
	}
	f.fake.DropSecrets()
	f.s.ReconcileCephSecrets(ctx)
	f.requireSecretValue(t, f.key)
}

// M2. A delete does not free an rbd image another VM's row names, even when
// the two locators carry different options.
func TestDeleteRecordedVMDiskVolumes_RBDReferenceBySpec(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	f.world.images["lv/shared"] = map[string]bool{}
	for vm, path := range map[string]string{
		"one": "rbd:lv/shared:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph",
		"two": "rbd:lv/shared:lvpool=ceph",
	} {
		insertTestVM(t, ctx, f.s.db, vm, "test-host", "stopped")
		if err := corrosion.InsertDisk(ctx, f.s.db, corrosion.DiskRecord{
			VMName: vm, DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph", Path: path, DeleteWithVM: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.s.deleteRecordedVMDiskVolumes(ctx, "one")
	if !f.world.has("lv/shared") {
		t.Fatalf("an image VM two still names was removed: %v", f.world.calls)
	}
}

// M6. Resize and snapshot of a ceph disk are refused up front with the
// reason, not with an error about a file that does not exist.
func TestCephDisk_ResizeAndSnapshotAreRefusedClearly(t *testing.T) {
	f := newCephPoolFixture(t)
	f.insertCephVM(t, "rs", "test-host")
	_, err := f.s.ResizeDisk(adminCtx(), &pb.ResizeDiskRequest{VmName: "rs", DiskName: "data", Size: "2G"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ceph") {
		t.Fatalf("resize: got %v, want FailedPrecondition naming ceph", err)
	}
	_, err = f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "rs", Name: "s1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ceph") {
		t.Fatalf("snapshot: got %v, want FailedPrecondition naming ceph", err)
	}
}

// N3 / I-R2-1. Every start proves this host's own key opens the disk (rbd
// info with the pool's credentials). It refuses for good (FailedPrecondition,
// naming the host and the keyring) only when rbd is unambiguous that an
// operator must act; anything else is Unavailable, which every start path
// retries — as main retried a start that failed in qemu.
func TestPrepareHardwareForStart_ProvesTheKeyWithRBD(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit int
		out  string
		code codes.Code
		want string
	}{
		{"EPERM (lab 2: caps denial exits 1)", 1, "rbd: error opening image pk-data: (1) Operation not permitted", codes.FailedPrecondition, "permission"},
		{"EACCES", 13, "rbd: error opening image pk-data: (13) Permission denied", codes.FailedPrecondition, "permission"},
		{"ENOENT, the pool answers", 2, "rbd: error opening image pk-data: (2) No such file or directory", codes.FailedPrecondition, "not in the cluster"},
		{"generic exit 1", 1, "rbd: something unexpected", codes.Unavailable, "retried"},
		{"ETIMEDOUT", 110, "rbd: couldn't connect to the cluster!", codes.Unavailable, "retried"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCephPoolFixture(t)
			vm := f.insertCephVM(t, "pk", "test-host")
			f.world.infoExit, f.world.infoOut = tc.exit, tc.out
			_, err := f.s.PrepareHardwareForStart(context.Background(), &vm)
			if status.Code(err) != tc.code || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "test-host") {
				t.Fatalf("got %v, want %v naming %q and the host", err, tc.code, tc.want)
			}
			if tc.code == codes.FailedPrecondition && tc.want == "permission" && !strings.Contains(err.Error(), f.keyring) {
				t.Fatalf("a key refusal must name the keyring path: %v", err)
			}
		})
	}
}

// I-R2-1 / m4 (N7). A failure to READ this host's pools is not "no such
// pool": it neither falls back to the locator nor refuses for good — the
// start is Unavailable and retried.
func TestPrepareHardwareForStart_PoolReadErrorIsRetried(t *testing.T) {
	f := newCephPoolFixture(t)
	vm := f.insertCephVM(t, "rd", "test-host")
	f.s.removeStoragePoolRef("ceph") // not cached: the table is read
	if err := f.s.db.Execute(context.Background(), `ALTER TABLE storage_pools RENAME TO storage_pools_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.resolveVolume(context.Background(), "", "ceph"); err == nil || errors.Is(err, errStorageNotFound) {
		t.Fatalf("resolveVolume on an unreadable pool table: %v, want an error that is not errStorageNotFound", err)
	}
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &vm); status.Code(err) != codes.Unavailable {
		t.Fatalf("start with an unreadable pool table: %v, want Unavailable", err)
	}
}

// m1. The pool-less paths (delete, the start/migration fallback) reach a
// cluster the locator names only by its mon_host.
func TestRBDPathOptions_CarriesMonHost(t *testing.T) {
	o := rbdPathOptions(`rbd:lv/x:id=litevirt:keyring=/k:lvpool=ceph:mon_host=10.0.0.1\:6789\;10.0.0.2`)
	if o["mon_host"] != "10.0.0.1:6789;10.0.0.2" || o["id"] != "litevirt" || o["keyring"] != "/k" {
		t.Fatalf("rbdPathOptions = %v", o)
	}
}

// Lab 2: a restart did not re-resolve monitors. A start re-resolves each rbd
// disk's <host> list into the domain's persistent definition, so a monitor
// that was removed does not stay in it.
func TestPrepareHardwareForStart_RefreshesMonitorsInThePersistentXML(t *testing.T) {
	f := newCephPoolFixture(t)
	defer lv.SetCephMonitorResolver(f.s.CephMonitorsForPool)()
	vm := f.insertCephVM(t, "mr", "test-host")
	stale := `<domain type="kvm"><name>mr</name><devices><disk type="network" device="disk"><driver name="qemu" type="raw"></driver><source protocol="rbd" name="lv/mr-data"><host name="10.0.0.99" port="6789"></host><auth username="litevirt"><secret type="ceph" uuid="` + f.secret + `"></secret></auth></source><target dev="vda" bus="virtio"></target></disk></devices></domain>`
	if err := f.fake.DefineDomain(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatal(err)
	}
	x, _ := f.fake.DumpXMLInactive("mr")
	if strings.Contains(x, "10.0.0.99") || !strings.Contains(x, "10.78.0.22") || !strings.Contains(x, f.secret) {
		t.Fatalf("persistent definition after a start:\n%s", x)
	}
}

// N7. Only a pool this host definitely does not have falls back to the
// locator's own keyring; storage that resolves to something else is refused.
func TestCephSecretsForVM_RefusesStorageThatIsNotTheDisksPool(t *testing.T) {
	f := newCephPoolFixture(t)
	vm := f.insertCephVM(t, "nv", "test-host")
	// The disk's storage name now resolves to a dir pool here.
	f.s.addStoragePoolRef("ceph", StoragePoolRef{Driver: "dir", Target: t.TempDir()})
	_, err := f.s.PrepareHardwareForStart(context.Background(), &vm)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "is a dir pool") {
		t.Fatalf("got %v, want a refusal saying the storage is a dir pool here", err)
	}
}

// N1. A promote builds its domain from the replica (a local file); the VM's
// rbd disks are not part of it, so their pool or keyring being absent here
// never refuses a disaster-recovery promote.
func TestPromoteReplica_IgnoresTheVMsRBDDisks(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{
			{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"},
			{VMName: "vm1", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
				Path: "rbd:lv/vm1-data:id=litevirt:keyring=/nonexistent/k:lvpool=ceph", SizeBytes: 1 << 30},
		},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, stream); err != nil {
		t.Fatalf("PromoteReplica of a VM with an rbd data disk on a host without its pool: %v", err)
	}
}

// N8 / M1. A failed create rolls a zvol back with the zfs driver (`zfs
// destroy` of the zvol it made), never an unlink of its /dev symlink; and a
// create refused at `zfs create` (the name exists) destroys nothing.
func TestCreateVM_FailedCreateDestroysItsZvol(t *testing.T) {
	for _, tc := range []struct {
		name        string
		createFails bool
	}{{"define fails", false}, {"zfs create refused", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			var calls []string
			t.Cleanup(storage.OverrideVolumeRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				if tc.createFails && len(args) > 0 && args[0] == "create" {
					return []byte("cannot create 'tank/lv/z1-data': dataset already exists"), errors.New("exit status 1")
				}
				return nil, nil
			}))
			s.addStoragePoolRef("tank", StoragePoolRef{Driver: "zfs", Source: "tank/lv"})
			fake.FailDefineDomain = func(string) error { return errors.New("define fails") }
			if _, err := s.CreateVM(adminCtx(), cephCreateRequest("z1", &pb.DiskSpec{Name: "data", Size: "1G", Storage: "tank"})); err == nil {
				t.Fatal("create succeeded")
			}
			destroyed := strings.Contains(strings.Join(calls, "\n"), "zfs destroy -r -- tank/lv/z1-data")
			if destroyed == tc.createFails {
				t.Fatalf("zfs destroy of the zvol: %v, want %v (calls %v)", destroyed, !tc.createFails, calls)
			}
		})
	}
}
