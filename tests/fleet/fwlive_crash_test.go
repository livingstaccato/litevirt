package fleet

// A daemon killed mid-move, for the crash scenarios of fwlive_restart_test.go
// and fwlive_cleanup_hold_test.go.
//
// The daemon's goroutine stops at the crash point inside a libvirt call (a
// fake's hook calls freeze). The scenario then kills the daemon (die,
// killWithin):
//
//  1. Every channel the daemon has to the world is fenced, before anything of
//     it can react. Silent fences first: its libvirt connection (libvirtfake
//     FenceDaemon), its database client (corrosion FenceWritesForTests, which
//     takes the client's lock and refuses nothing) and the network both ways
//     (the node's life gate, node_life.go). A call on a silent fence waits
//     where it is, with no answer and no error. Then its files: the node's
//     tree made read-only, and every descriptor the process holds open for
//     writing into it pointed at /dev/null, as a process's descriptors go
//     with it. A goroutine refused a file write now can only react through a
//     channel already fenced. Only once every fence is in place is the kill
//     on record (died).
//  2. The calls admitted before the fence run to their end: libvirt's (but
//     the frozen call; a call of the Fake's on the goroutine of an admitted
//     one is part of it), the client's (its lock taken) and the peers'
//     handlers of the node's calls. A commit that got past the client's lock
//     meanwhile (a raw write) fails the kill.
//  3. What the world holds is taken: libvirt's whole state, the node's files,
//     its replicated entries, its calls past each link. This is the moment of
//     the death.
//  4. The daemon dies: the gates kill every waiting and later call (libvirt:
//     runtime.Goexit; network: Unavailable; database: every commit refused),
//     links block everything, and the frozen goroutine ends where it stands
//     (the libvirt call never returns; its deferred calls run, and whatever
//     they ask is refused or ends them in turn).
//  5. kill waits for the frozen goroutine and the move's own handler, takes the
//     daemon down (downNode), and waits for every goroutine of the old server's
//     generation to be gone (server_labels.go: its loops, recovery workers,
//     handlers, adopters and whatever they started).
//
// A step that fails or runs out (each is bounded) does not stop the kill: the
// daemon still dies, behind every fence, and its goroutines are still waited
// for; the failure is reported, and the fences stay in place for good. die
// lifts them, for the replacement, only after a kill with no failure:
// libvirtd, the database and the files are one and cannot be given to the
// new daemon apart from the old, so they reopen only once no goroutine of the
// old is left. A wait running out is never taken as an end.
//
// Limits: the libvirt gate is per Fake, so a scenario must not kill a node
// whose Fake a live daemon's goroutine still calls (the landing of a migration
// is libvirtd's own, LandFirmwareLive and LandMigrated*, and is not gated).
// Goroutines that carry no generation are not waited for: one a scenario
// starts by calling into the server on its own goroutine; one a timer or a
// context callback of the daemon starts (time.AfterFunc, context.AfterFunc),
// which carries the labels of whatever fires it; and the replicator's loops,
// started by the scenario, which downNode's replicator stop joins. No fwlive
// scenario has the first two in flight at a death.
// A descriptor is revoked by number after checking it is still the file its
// path names; one closed and reused for the same file in that instant would
// be revoked with it.
// File modes do not refuse root, so the kill refuses to run as root. A
// cluster with SharedDataDir cannot be killed this way.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fwliveCrash is one daemon's death at a crash point.
type fwliveCrash struct {
	t *testing.T
	c *Cluster
	n *Node
	// reached is closed when a daemon goroutine is at the crash point; kill
	// ends it there.
	reached, kill chan struct{}
	reachOnce     sync.Once
	killOnce      sync.Once
	// goid is the frozen goroutine's id; frozen counts the goroutines at
	// the crash point (their libvirt calls never return).
	goid   atomic.Uint64
	frozen atomic.Int32
	// moveDone is closed when n's MigrateVM handler for the move returned
	// (trackMove); nil when no handler is tracked.
	moveDone chan struct{}
	// died: kill was asked; ended: every goroutine of the dead daemon is
	// gone, and only then may the fences lift.
	died, ended bool
	downed      bool
	gen, root   string
	db          *corrosion.WriteFence
	filesUnlock func()
	netUnblock  func()
	// What the world held at the death.
	virt0, files0 string
	log0          int
	passed0       map[string]int
}

// fwliveNewCrash prepares n's daemon to die at a crash point. A scenario
// that ends without killing it (one that failed first) has it killed, fenced,
// at its end, so no goroutine of it outlives the scenario unfenced.
func fwliveNewCrash(t *testing.T, c *Cluster, n *Node) *fwliveCrash {
	t.Helper()
	k := &fwliveCrash{t: t, c: c, n: n, reached: make(chan struct{}), kill: make(chan struct{})}
	t.Cleanup(func() {
		if !k.died {
			k.die(false)
		}
	})
	return k
}

// trackMove makes kill wait for n's next MigrateVM handler to return; armed
// before the move starts.
func (k *fwliveCrash) trackMove() {
	k.moveDone = make(chan struct{})
	done := k.moveDone
	k.n.HookStream("MigrateVM", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		defer close(done)
		return h(srv, ss)
	})
}

// freeze is the crash point, called on the daemon's goroutine: it waits for
// the kill and ends the goroutine there.
func (k *fwliveCrash) freeze() {
	k.goid.Store(fwliveGoid())
	k.frozen.Add(1)
	k.reachOnce.Do(func() { close(k.reached) })
	<-k.kill
	runtime.Goexit()
}

// die kills the daemon at its crash point, checks that nothing of it acted
// after its death when check is set, and lifts the fences for its
// replacement. A failure leaves every fence in place and fails the scenario.
func (k *fwliveCrash) die(check bool) {
	t := k.t
	t.Helper()
	if err := k.killWithin(time.Minute); err != nil {
		if check {
			t.Fatal(err)
		}
		t.Error(err)
		return
	}
	if check {
		k.check()
	}
	k.revive()
}

// killWithin is steps 1 to 5 above, each bounded by d. An error leaves every
// fence in place; the daemon has still been killed behind them, and its
// goroutines waited for.
func (k *fwliveCrash) killWithin(d time.Duration) error {
	t, c, n := k.t, k.c, k.n
	t.Helper()
	if c.opts.SharedDataDir {
		return fmt.Errorf("%s's data dir is shared: its daemon cannot be killed with its files fenced", n.Name)
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("running as root: file modes would not fence %s's files", n.Name)
	}
	k.root = filepath.Join(c.tmpRoot, n.Name)
	k.gen = n.serverGeneration()

	// 1. Fence every channel: the silent ones, then the files. The database
	// fence holds only once it has the client's lock, which waits for the
	// client's calls admitted before it: the files are fenced after that, so
	// a goroutine refused a file write cannot reach the database instead.
	var failed []error
	n.fenceLife()
	n.Virt.FenceDaemon()
	k.db = n.DB.FenceWritesForTests()
	select {
	case <-k.db.Held():
	case <-time.After(d):
		failed = append(failed, fmt.Errorf("%s's daemon: database calls admitted before the fence did not end within %v", n.Name, d))
	}
	k.filesUnlock = fwliveReadOnly(t, k.root)
	revoked, err := fwliveRevokeWriters(k.root)
	if err != nil {
		t.Errorf("%s's files: %v", n.Name, err)
	}
	if len(revoked) > 0 {
		t.Logf("%s's daemon: descriptors open for writing, pointed at /dev/null: %v", n.Name, revoked)
	}
	k.netUnblock = fwliveIsolate(c, n)
	k.died = true

	// 2. What was admitted before the fence runs to its end.
	if !fwliveUntil(d, func() bool { return n.Virt.DaemonInFlight() <= int(k.frozen.Load()) }) {
		failed = append(failed, fmt.Errorf("%s's daemon: %d libvirt calls admitted before the fence did not end within %v",
			n.Name, n.Virt.DaemonInFlight()-int(k.frozen.Load()), d))
	}
	if !fwliveUntil(d, func() bool { return n.inFlightFrom() == 0 }) {
		failed = append(failed, fmt.Errorf("%s's daemon: %d calls a peer serves it did not end within %v", n.Name, n.inFlightFrom(), d))
	}

	// 3. What the world holds at the death.
	k.virt0 = n.Virt.Fingerprint()
	k.files0 = fwliveTreeDigest(t, k.root)
	k.log0 = fwliveOriginEntries(t, n)
	k.passed0 = fwlivePassed(c, n)

	// 4. The death.
	if past := k.db.PastTheLock(); past != 0 {
		failed = append(failed, fmt.Errorf("%s's daemon: %d commits got past its database client's lock while fenced", n.Name, past))
	}
	n.Virt.KillDaemon()
	n.killLife()
	k.db.Kill()
	k.killOnce.Do(func() { close(k.kill) })

	// 5. Every goroutine of the dead daemon ends.
	if err := k.awaitEnd(d); err != nil {
		failed = append(failed, err)
	}
	if len(failed) > 0 {
		k.ended = false
		return errors.Join(failed...)
	}
	return nil
}

// awaitEnd is step 5: the frozen goroutine, the move's handler, downNode and
// the old server's generation, each within d.
func (k *fwliveCrash) awaitEnd(d time.Duration) error {
	n := k.n
	if id := k.goid.Load(); id != 0 {
		if !fwliveUntil(d, func() bool { return !fwliveGoroutineAlive(id) }) {
			return fmt.Errorf("%s's frozen goroutine %d did not end within %v of the kill", n.Name, id, d)
		}
	}
	if k.moveDone != nil && k.frozen.Load() > 0 {
		select {
		case <-k.moveDone:
		case <-time.After(d):
			return fmt.Errorf("%s's MigrateVM handler did not return within %v of the kill", n.Name, d)
		}
	}
	if !k.downed {
		down := make(chan struct{})
		go func() {
			defer close(down)
			downNode(n)
		}()
		select {
		case <-down:
			k.downed = true
		case <-time.After(d):
			return fmt.Errorf("%s's daemon was not taken down within %v of the kill", n.Name, d)
		}
	}
	if !fwliveUntil(d, func() bool { live, _ := serverGoroutines(k.gen); return live == 0 }) {
		live, stacks := serverGoroutines(k.gen)
		return fmt.Errorf("%d goroutines of %s's dead daemon (%s) did not end within %v of the kill:\n%s",
			live, n.Name, k.gen, d, stacks)
	}
	k.ended = true
	return nil
}

// check asserts that nothing the dead daemon did reached libvirt, its files,
// the database or a peer after its death.
func (k *fwliveCrash) check() {
	t, c, n := k.t, k.c, k.n
	t.Helper()
	if v := n.Virt.Fingerprint(); v != k.virt0 {
		t.Errorf("%s's dead daemon changed libvirt after its death", n.Name)
	}
	if f := fwliveTreeDigest(t, k.root); f != k.files0 {
		t.Errorf("%s's dead daemon changed its files after its death", n.Name)
	}
	if l := fwliveOriginEntries(t, n); l != k.log0 {
		t.Errorf("%s's dead daemon wrote %d replicated entries after its death", n.Name, l-k.log0)
	}
	for name, p := range fwlivePassed(c, n) {
		if p != k.passed0[name] {
			t.Errorf("%s's dead daemon reached %s with %d calls after its death", n.Name, name, p-k.passed0[name])
		}
	}
}

// revive lifts the fences for the replacement daemon, once the dead one has
// ended (never before).
func (k *fwliveCrash) revive() {
	t, n := k.t, k.n
	t.Helper()
	if !k.ended {
		return
	}
	calls := n.Virt.ReviveDaemon()
	n.reviveLife()
	refused, landed := k.db.Lift()
	k.filesUnlock()
	k.netUnblock()
	t.Logf("%s's dead daemon: libvirt calls ended %v, commits refused %d", n.Name, calls, refused)
	if landed != 0 {
		t.Errorf("%s's dead daemon committed %d rows after its death", n.Name, landed)
	}
}

// A goroutine of the dead daemon that outlives both the frozen call and the
// move's handler (here a call it was serving, which acts 3 s after the kill:
// a recovery worker retrying a peer is one such) is still the dead daemon's.
// die waits for it, severed, before the replacement starts, so whatever it
// does next is refused; nothing it does reaches libvirt after the restart.
//
// Mutation: die lifts the severs once the frozen goroutine and the handler
// are gone, without waiting for the old server's generation — the worker
// defines its domain next to the replacement daemon, red.
func TestFleet_FwLiveCrash_AnOldWorkerCannotActAfterTheRestart(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	const oldWorkerVM = "fwlive-old-worker"
	in, ended := make(chan struct{}), make(chan struct{})
	var acted atomic.Bool
	virt := src.Virt // the libvirt the old daemon talks to, and the new one
	src.HookUnary("Ping", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		defer close(ended)
		close(in)
		time.Sleep(3 * time.Second)
		_ = virt.DefineDomain("<domain><name>" + oldWorkerVM + "</name><uuid>8a1b2c3d-0000-4000-8000-0000000000aa</uuid></domain>")
		acted.Store(true)
		return h(ctx, req)
	})
	go func() { _, _ = c.SelfClient(src).Ping(context.Background(), &pb.PingRequest{}) }()
	<-in

	k.die(true)
	fwliveRestartUp(t, c, src)
	select {
	case <-ended:
	case <-time.After(time.Minute):
		t.Fatal("the old worker did not end within a minute")
	}
	if acted.Load() {
		t.Error("the dead daemon's worker went on past its libvirt call")
	}
	if st, ok := virt.RawState(oldWorkerVM); ok {
		t.Errorf("the dead daemon's worker defined %s (%s) after the restart", oldWorkerVM, st)
	}
}

// A goroutine of the dead daemon held past the kill's bound is not an end:
// the kill fails, and every fence stays where it is, so the held goroutine,
// once it goes on, reaches none of libvirt, the database, the files or a
// peer (Codex review I2). The fixture ends only when it is gone.
//
// Mutation: a kill that runs out lifts the fences (revive as if ended) — the
// held goroutine's file, row and domain land, red.
func TestFleet_FwLiveCrash_AnOwnerHeldPastTheBoundKeepsEveryFence(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	if _, err := src.DB.DB().ExecContext(ctx, `CREATE TABLE fwlive_held_probe (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	const heldVM = "fwlive-held-owner"
	probe := filepath.Join(src.FW.DataDir, "fwlive-held-probe")
	db, virt := src.DB, src.Virt
	in, hold, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var letGo sync.Once
	t.Cleanup(func() { letGo.Do(func() { close(hold) }) })
	// The daemon's connection to the peer, made while it lives.
	peer := c.PeerClient(src, dst)
	if _, err := peer.Ping(ctx, &pb.PingRequest{}); err != nil {
		t.Fatalf("fixture: the peer's Ping: %v", err)
	}
	src.HookUnary("Ping", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		defer close(ended)
		close(in)
		<-hold
		_ = os.WriteFile(probe, []byte("written by a held owner"), 0o600)
		_, _ = db.DB().ExecContext(context.Background(), `INSERT INTO fwlive_held_probe (k) VALUES ('held')`)
		_ = virt.DefineDomain("<domain><name>" + heldVM + "</name><uuid>8a1b2c3d-0000-4000-8000-0000000000cc</uuid></domain>")
		return h(ctx, req)
	})
	go func() { _, _ = c.SelfClient(src).Ping(ctx, &pb.PingRequest{}) }()
	<-in

	if err := k.killWithin(2 * time.Second); err == nil {
		t.Fatal("a goroutine of the dead daemon held past the bound was taken as an end")
	}
	if g := src.Virt.DaemonGate(); g != "dead" {
		t.Errorf("libvirt's gate is %s after a failed kill, want dead", g)
	}
	if err := src.DB.Execute(ctx, `INSERT INTO fwlive_held_probe (k) VALUES ('after')`); err == nil {
		t.Error("the dead daemon's database client commits after a failed kill")
	}
	if err := os.WriteFile(filepath.Join(src.FW.DataDir, "fwlive-held-after"), nil, 0o600); err == nil && os.Geteuid() != 0 {
		t.Error("the dead daemon's files take a write after a failed kill")
	}
	if _, err := peer.Ping(ctx, &pb.PingRequest{}); err == nil {
		t.Error("the dead daemon reaches a peer after a failed kill")
	}

	letGo.Do(func() { close(hold) })
	select {
	case <-ended:
	case <-time.After(time.Minute):
		t.Fatal("the held goroutine did not end once let go")
	}
	if _, err := os.Stat(probe); err == nil {
		t.Error("the held goroutine's file write landed")
	}
	var rows int
	if err := src.DB.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM fwlive_held_probe`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("the held goroutine's rows: %d (%v)", rows, err)
	}
	if _, ok := src.Virt.RawState(heldVM); ok {
		t.Error("the held goroutine defined its domain")
	}
	if err := k.awaitEnd(time.Minute); err != nil {
		t.Fatal(err)
	}
	k.check()
	k.revive()
	fwliveRestartUp(t, c, src)
}

// fwliveGoid is the calling goroutine's id.
func fwliveGoid() uint64 {
	var b [64]byte
	s := b[:runtime.Stack(b[:], false)]
	s = bytes.TrimPrefix(s, []byte("goroutine "))
	if i := bytes.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	id, err := strconv.ParseUint(string(s), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("fwliveGoid: %q", b[:]))
	}
	return id
}

// fwliveGoroutineAlive reports whether the goroutine id still exists.
func fwliveGoroutineAlive(id uint64) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	return bytes.Contains(buf, []byte(fmt.Sprintf("goroutine %d [", id)))
}

// fwliveUntil polls cond until it holds (true) or d runs out (false).
func fwliveUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fwliveReadOnly takes write permission from everything under root, as the
// dead daemon's open of any file there is refused; restore gives back each
// one's mode. A process running as root is not refused by modes: the digest
// die compares still catches anything written.
func fwliveReadOnly(t *testing.T, root string) (restore func()) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Logf("running as root: file modes do not refuse %s's dead daemon; the file digest still checks it", root)
	}
	modes := map[string]fs.FileMode{}
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		modes[p] = info.Mode().Perm()
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, p := range paths {
		if err := os.Chmod(p, modes[p]&^0o222); err != nil {
			t.Fatalf("make %s read-only: %v", p, err)
		}
	}
	return func() {
		for _, p := range paths {
			if err := os.Chmod(p, modes[p]); err != nil {
				t.Errorf("give %s its mode back: %v", p, err)
			}
		}
	}
}

// fwliveRevokeWriters points every descriptor this process holds open for
// writing into a file under root at /dev/null, as a killed process's
// descriptors go with it: a write through one reaches nothing. It returns
// the paths it revoked.
func fwliveRevokeWriters(root string) ([]string, error) {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer null.Close()
	prefix := root + string(filepath.Separator)
	var revoked []string
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		path, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil || !strings.HasPrefix(path, prefix) {
			continue
		}
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", e.Name()))
		if err != nil {
			continue
		}
		flags, ok := fwliveFDFlags(string(info))
		if !ok || flags&syscall.O_ACCMODE == syscall.O_RDONLY {
			continue
		}
		// The number is still the descriptor of that file: the same file
		// as the path names, just before it is replaced.
		var byFD, byPath syscall.Stat_t
		if syscall.Fstat(fd, &byFD) != nil || syscall.Stat(path, &byPath) != nil ||
			byFD.Dev != byPath.Dev || byFD.Ino != byPath.Ino {
			continue
		}
		if err := syscall.Dup3(int(null.Fd()), fd, syscall.O_CLOEXEC); err != nil {
			return revoked, fmt.Errorf("revoke the descriptor of %s: %w", path, err)
		}
		revoked = append(revoked, path)
	}
	return revoked, nil
}

// fwliveFDFlags reads the open flags of a /proc/self/fdinfo entry.
func fwliveFDFlags(info string) (int, bool) {
	for _, line := range strings.Split(info, "\n") {
		if v, ok := strings.CutPrefix(line, "flags:"); ok {
			f, err := strconv.ParseInt(strings.TrimSpace(v), 8, 64)
			return int(f), err == nil
		}
	}
	return 0, false
}

// fwliveTreeDigest digests every name, file content and link under root.
func fwliveTreeDigest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			lines = append(lines, "L "+rel+" "+target)
		case d.IsDir():
			lines = append(lines, "D "+rel)
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			lines = append(lines, "F "+rel+" "+hex.EncodeToString(sum[:]))
		default:
			lines = append(lines, "O "+rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("digest %s: %v", root, err)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(fmt.Sprint(lines)))
	return hex.EncodeToString(sum[:])
}

// fwliveOriginEntries counts the replicated entries n wrote, read past the
// client's lock (a fence holds it).
func fwliveOriginEntries(t *testing.T, n *Node) int {
	t.Helper()
	var count int
	if err := n.DB.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM mutation_log WHERE origin = ?`, n.Name).Scan(&count); err != nil {
		t.Fatalf("count %s's replicated entries: %v", n.Name, err)
	}
	return count
}

// fwliveIsolate refuses every RPC between n and each other node, both ways
// (BlockAll on each link, on top of what the link already does); restore puts
// each link's fault back.
func fwliveIsolate(c *Cluster, n *Node) (restore func()) {
	type link struct {
		from, to *Node
		fault    LinkFault
	}
	var links []link
	for _, o := range c.Nodes {
		if o == n {
			continue
		}
		for _, l := range []link{{from: n, to: o}, {from: o, to: n}} {
			l.fault = c.LinkFaultOf(l.from, l.to)
			links = append(links, l)
			f := l.fault
			f.BlockAll = true
			c.SetLinkFault(l.from, l.to, f)
		}
	}
	return func() {
		for _, l := range links {
			c.SetLinkFault(l.from, l.to, l.fault)
		}
	}
}

// fwlivePassed is, per other node, how many of n's calls its links let past
// BlockAll.
func fwlivePassed(c *Cluster, n *Node) map[string]int {
	out := map[string]int{}
	for _, o := range c.Nodes {
		if o != n {
			out[o.Name] = c.LinkStats(n, o).Passed
		}
	}
	return out
}
