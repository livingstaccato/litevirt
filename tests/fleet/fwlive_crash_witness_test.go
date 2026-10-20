package fleet

// Witnesses of the killed-daemon fixture (fwlive_crash_test.go): the
// schedules of Codex's independent review of the first version
// (resume-incoming-fwlive-crash-independent-review.md, I1 to I4), each a
// scenario the fixture must get right. They use only the fixture's
// scenario-facing surface (fwliveNewCrash, fwliveRestartFreeze, die), so the
// same file runs against the first version, where each goes red.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// fwliveWitnessStacks reports whether a live goroutine runs a frame whose
// function name contains fn.
func fwliveWitnessStacks(fn string) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		// The goroutine's own frames, not the line naming its creator.
		for _, line := range strings.Split(string(g), "\n") {
			if strings.HasPrefix(line, "created by ") {
				break
			}
			if strings.Contains(line, fn) {
				return true
			}
		}
	}
	return false
}

// I1. The request is cancelled while the source's migration call is frozen:
// the move's parent hands it to an adopter and returns. The kill ends the
// frozen call without its answer; the adopter, waiting on that answer, must
// end too, not wait out its one-hour ceiling past the daemon's death.
//
// On the first version: die returns with the adopter still waiting, red.
func TestFleet_FwLiveCrash_TheCancelledMovesAdopterEnds(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	k := fwliveRestartFreeze(t, c, src, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := c.SelfClient(src).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: fwwVM, TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := st.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	fwliveRestartReach(t, k.reached, done, "the migration call")
	cancel()
	if !fwliveUntil(30*time.Second, func() bool { return fwliveWitnessStacks("adoptAbandonedMigration") }) {
		t.Fatal("fixture: the cancelled move's parent did not hand it to an adopter")
	}
	k.die(true)
	if fwliveWitnessStacks("adoptAbandonedMigration") {
		t.Error("the dead daemon's adopter still waits after its death")
	}
	fwliveRestartUp(t, c, src)
}

// I2. The scenario ends, as a failed one does, while the move is inside its
// migration call but has not reached the crash point; the call reaches it
// during the scenario's cleanup. The daemon must still die fenced, and
// nothing of the move may go on.
//
// On the first version: the cleanup only releases the crash point, so the
// late call ends unfenced and the move's handler polls libvirt for good, red.
func TestFleet_FwLiveCrash_ACrashPointReachedAfterTheScenarioEndedIsKilled(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	late := make(chan struct{})
	t.Run("ends_before_the_crash_point", func(t *testing.T) {
		k := fwliveNewCrash(t, c, src)
		k.trackMove()
		src.Virt.OnMigrateToTarget = func(string, string, lv.MigrateParams) error {
			<-late
			k.freeze()
			return errors.New("unreachable: the daemon died in this call")
		}
		_ = fwliveMigrate(t, c, src, dst)
		if !fwliveUntil(time.Minute, func() bool { return fwliveDid(src, "migrate") }) {
			t.Fatal("fixture: the move did not reach its migration call")
		}
		// The crash point is reached only during the cleanup.
		time.AfterFunc(2*time.Second, func() { close(late) })
	})
	<-late
	if !fwliveUntil(time.Minute, func() bool { return !fwliveWitnessStacks("(*Server).MigrateVM") }) {
		t.Error("the move's handler went on after the daemon's death")
	}
}

// I3. A goroutine of the daemon polls libvirt, as the move's parent does on
// its tick; dying there runs its deferred work: a file written, a row
// committed, a peer called. None of it may land, whatever moment the fences
// go up in: dying is what the death does, after every fence. (die's own
// check covers the call past the link, and libvirt.)
//
// On the first version: libvirt is severed first, the goroutine dies at once,
// and its deferred file write lands before the files are fenced, red.
func TestFleet_FwLiveCrash_DeathWorkRunsOnlyBehindEveryFence(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	if _, err := src.DB.DB().ExecContext(ctx, `CREATE TABLE fwlive_death_probe (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	probe := filepath.Join(src.FW.DataDir, "fwlive-death-probe")
	db, virt := src.DB, src.Virt
	// The daemon's connection to the peer, made while it lives (a connection
	// the dying goroutine made itself would be its own, and end with it).
	peer := c.PeerClient(src, dst)
	if _, err := peer.Ping(ctx, &pb.PingRequest{}); err != nil {
		t.Fatalf("fixture: the peer's Ping: %v", err)
	}
	polling := make(chan struct{})
	src.HookUnary("Ping", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		defer func() {
			_ = os.WriteFile(probe, []byte("written by a dying daemon"), 0o600)
			_, _ = db.DB().ExecContext(context.Background(), `INSERT INTO fwlive_death_probe (k) VALUES ('dying')`)
			_, _ = peer.Ping(context.Background(), &pb.PingRequest{})
		}()
		close(polling)
		for {
			_ = virt.DomainExists(fwwVM)
		}
	})
	go func() { _, _ = c.SelfClient(src).Ping(ctx, &pb.PingRequest{}) }()
	<-polling

	k.die(true)
	if _, err := os.Stat(probe); err == nil {
		t.Error("the dying goroutine's file write landed")
	}
	var rows int
	if err := src.DB.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM fwlive_death_probe`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("the dying goroutine's row: %d rows (%v)", rows, err)
	}
	fwliveRestartUp(t, c, src)
}

// I4. A libvirt call of the daemon, admitted before the kill, has its effect
// a moment later (here an undefine whose call waits half a second inside
// libvirt). Its effect belongs to the living daemon: the death comes after
// it, and the world taken at the death holds it, so nothing changes after.
//
// On the first version: the state is taken at once, the undefine lands after,
// and die reports libvirt changed after the death, red.
func TestFleet_FwLiveCrash_AnAdmittedLibvirtCallLandsBeforeTheDeath(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	const admittedVM = "fwlive-admitted"
	src.Virt.DefineStoppedDomain(admittedVM, "52:54:00:aa:bb:cc")
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	inside, release := make(chan struct{}), make(chan struct{})
	src.Virt.FailUndefinePreserv = func(name string) error {
		if name == admittedVM {
			close(inside)
			<-release
		}
		return nil
	}
	virt := src.Virt
	returned := make(chan error, 1)
	src.HookUnary("Ping", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		returned <- virt.UndefineDomainPreservingState(admittedVM)
		return h(ctx, req)
	})
	go func() { _, _ = c.SelfClient(src).Ping(ctx, &pb.PingRequest{}) }()
	<-inside
	time.AfterFunc(500*time.Millisecond, func() { close(release) })

	k.die(true)
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("the admitted undefine: %v", err)
		}
	default:
		t.Error("the admitted undefine had not returned by the end of the death")
	}
	if _, ok := src.Virt.RawState(admittedVM); ok {
		t.Errorf("%s is still defined: the admitted undefine did not land", admittedVM)
	}
	fwliveRestartUp(t, c, src)
}

// The schedules of Codex's review of the first fix
// (resume-incoming-fwlive-crash-fix1-independent-review.md, I2 to I5). Like
// the ones above, they use only the fixture's surface, here including
// killWithin, awaitEnd and revive, so they run against the first fix too.

// fwliveWitnessPings arms n's next Ping calls with hooks, in order, and makes
// one call for each; each hook runs on a goroutine of n's daemon.
func fwliveWitnessPings(t *testing.T, c *Cluster, n *Node, hooks ...func()) {
	t.Helper()
	for _, h := range hooks {
		h := h
		n.HookUnary("Ping", func(ctx context.Context, req any, next grpc.UnaryHandler) (any, error) {
			h()
			return next(ctx, req)
		})
	}
	for range hooks {
		go func() { _, _ = c.SelfClient(n).Ping(context.Background(), &pb.PingRequest{}) }()
	}
}

// fwliveWitnessUntilGate waits for n's libvirt gate to be in state.
func fwliveWitnessUntilGate(n *Node, state string) {
	virt := n.Virt
	fwliveUntil(time.Minute, func() bool { return virt.DaemonGate() == state })
}

// fix1 I2. A libvirt call admitted before the fence is held past the kill's
// bound, so the drain runs out; another goroutine of the daemon, held before
// a file write, goes on once the kill has returned. The files are fenced all
// the same: a drain that runs out leaves no fence out, and the daemon's
// goroutines are still waited for.
//
// On the first fix: the kill returns at the drain, before the files are
// fenced, and the write lands, red.
func TestFleet_FwLiveCrash_ADrainThatRunsOutLeavesNoFenceOut(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	const admittedVM = "fwlive-admitted"
	src.Virt.DefineStoppedDomain(admittedVM, "52:54:00:aa:bb:01")
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	virt := src.Virt
	probe := filepath.Join(src.FW.DataDir, "fwlive-drain-probe")
	holdCall, holdWrite := make(chan struct{}), make(chan struct{})
	inCall, inWrite, wrote := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		for _, ch := range []chan struct{}{holdCall, holdWrite} {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	})
	virt.FailUndefinePreserv = func(name string) error {
		if name == admittedVM {
			close(inCall)
			<-holdCall
		}
		return nil
	}
	fwliveWitnessPings(t, c, src,
		func() { _ = virt.UndefineDomainPreservingState(admittedVM) },
		func() {
			close(inWrite)
			<-holdWrite
			_ = os.WriteFile(probe, []byte("written after the kill gave up"), 0o600)
			close(wrote)
			_ = virt.DomainExists(fwwVM)
		})
	<-inCall
	<-inWrite

	if err := k.killWithin(2 * time.Second); err == nil {
		t.Fatal("the kill succeeded with an admitted call held past its bound")
	}
	close(holdWrite)
	<-wrote
	if _, err := os.Stat(probe); err == nil {
		t.Error("a goroutine of the daemon wrote its file after the kill gave up")
	}
	close(holdCall)
	if err := k.awaitEnd(time.Minute); err != nil {
		t.Fatal(err)
	}
	k.revive()
	fwliveRestartUp(t, c, src)
}

// fix1 I3. A database write of the daemon's is in its transaction when the
// fence goes up; its goroutine writes a file once the write returns. The
// write commits as it would have (the database fence tells it nothing). The
// files are fenced only once the database fence holds, after that write:
// the file write is the living daemon's, landing before the death or
// refused, and either way nothing changes after the death (die's check).
//
// On the first fix: the database fence refuses the commit at once, before
// the files are fenced, red.
func TestFleet_FwLiveCrash_AnAdmittedDatabaseWriteLearnsNothing(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	if _, err := src.DB.DB().ExecContext(ctx, `CREATE TABLE fwlive_admitted_probe (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	db, virt := src.DB, src.Virt
	probe := filepath.Join(src.FW.DataDir, "fwlive-admitted-probe")
	inTx := make(chan struct{})
	committed := make(chan error, 1)
	fwliveWitnessPings(t, c, src, func() {
		_, err := db.ExecuteBatchGuarded(context.Background(), func(*sql.Tx) (bool, error) {
			close(inTx)
			fwliveWitnessUntilGate(src, "fenced")
			time.Sleep(200 * time.Millisecond)
			return true, nil
		}, []corrosion.Statement{{SQL: `INSERT INTO fwlive_admitted_probe (k) VALUES ('admitted')`}})
		committed <- err
		_ = os.WriteFile(probe, []byte("written once the write returned"), 0o600)
		_ = virt.DomainExists(fwwVM)
	})
	<-inTx

	k.die(true)
	if err := <-committed; err != nil {
		t.Errorf("the admitted write learned of the fence: %v", err)
	}
	fwliveRestartUp(t, c, src)
}

// fix1 I4, files; fix2 I6. A goroutine of the daemon opens one of its files
// for writing while it lives, and after the death writes through that
// descriptor and puts the bytes back. The fixture does not take the
// descriptor from it (its number is not the fixture's to rewrite), so the
// write is caught: the file's change time moved after the death.
//
// On the second fix: the descriptor is pointed at /dev/null, the write is
// lost unseen, and nothing is reported, red.
func TestFleet_FwLiveCrash_AWriteThroughADescriptorOpenedBeforeTheDeathIsCaught(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	path := filepath.Join(src.FW.DataDir, "fwlive-open-probe")
	hlWrite(t, path, []byte("as the daemon left it"))
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	virt := src.Virt
	opened, wrote := make(chan struct{}), make(chan struct{})
	fwliveWitnessPings(t, c, src, func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Errorf("open %s: %v", path, err)
			close(opened)
			return
		}
		close(opened)
		fwliveWitnessUntilGate(src, "dead")
		// The same length: the bytes put back leave the content as it was.
		_, _ = f.WriteAt(bytes.Repeat([]byte("x"), len("as the daemon left it")), 0)
		_, _ = f.WriteAt([]byte("as the daemon left it"), 0)
		_ = f.Close()
		close(wrote)
		_ = virt.DomainExists(fwwVM)
	})
	<-opened

	if err := k.killWithin(time.Minute); err != nil {
		t.Fatal(err)
	}
	<-wrote
	caught := false
	for _, l := range fwliveWitnessLeaks(k) {
		if strings.Contains(l, "changed its files") {
			caught = true
		}
	}
	if !caught {
		t.Error("a write after the death through a descriptor opened before it went unseen")
	}
	k.revive()
	fwliveRestartUp(t, c, src)
}

// fix2 I6. A descriptor the scenario itself holds open for writing into the
// killed node's files is not the daemon's: the kill leaves it as it is, and
// what the scenario writes through it once the daemon is replaced lands.
//
// On the second fix: the kill points every such descriptor at /dev/null,
// whoever owns it, and the scenario's write is lost, red.
func TestFleet_FwLiveCrash_TheKillTouchesNoDescriptorItDoesNotOwn(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	path := filepath.Join(src.FW.DataDir, "fwlive-scenario-log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	k.die(true)
	fwliveRestartUp(t, c, src)
	if _, err := f.WriteAt([]byte("the scenario's own line"), 0); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "the scenario's own line" {
		t.Errorf("the scenario's write through its own descriptor reached %q, want it in %s", b, path)
	}
}

// fix2 I2. A libvirt call admitted before the fence holds libvirt's lock past
// the kill's bound (a definition's fill hook that does not return). The drain
// runs out; the kill must still come, and report, within its bounds: it does
// not read libvirt's state under that lock.
//
// On the second fix: the state is taken after a failed drain, the read waits
// on the held lock, and the kill never comes, red.
func TestFleet_FwLiveCrash_ACallHoldingLibvirtsLockDoesNotStopTheKill(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	virt := src.Virt
	in, release := make(chan struct{}), make(chan struct{})
	var letGo sync.Once
	t.Cleanup(func() { letGo.Do(func() { close(release) }) })
	virt.FillDefine = func(x string) string {
		if strings.Contains(x, "fwlive-filled") {
			close(in)
			<-release
		}
		return x
	}
	fwliveWitnessPings(t, c, src, func() {
		_ = virt.DefineDomain("<domain><name>fwlive-filled</name><uuid>8a1b2c3d-0000-4000-8000-0000000000dd</uuid></domain>")
	})
	<-in

	killed := make(chan error, 1)
	go func() { killed <- k.killWithin(2 * time.Second) }()
	select {
	case err := <-killed:
		if err == nil {
			t.Error("the kill succeeded with a call holding libvirt's lock past its bound")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the kill did not come within its bounds with a call holding libvirt's lock")
	}
	letGo.Do(func() { close(release) })
	if err := k.awaitEnd(time.Minute); err != nil {
		t.Fatal(err)
	}
	k.revive()
	fwliveRestartUp(t, c, src)
}

// fix1 I4, raw database writes. A goroutine of the daemon writes the database
// past its client (a raw statement on the pool) while the fence holds the
// client's lock. The kill reports it rather than taking a world the write may
// or may not be in.
//
// On the first fix: the raw write is refused unnoticed and the kill reports
// nothing, red.
func TestFleet_FwLiveCrash_ARawDatabaseWriteDuringTheFenceFailsTheKill(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	if _, err := src.DB.DB().ExecContext(ctx, `CREATE TABLE fwlive_raw_probe (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	const admittedVM = "fwlive-admitted"
	src.Virt.DefineStoppedDomain(admittedVM, "52:54:00:aa:bb:02")
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	db, virt := src.DB, src.Virt
	holdCall, rawDone, inCall := make(chan struct{}), make(chan struct{}), make(chan struct{})
	virt.FailUndefinePreserv = func(name string) error {
		if name == admittedVM {
			close(inCall)
			<-holdCall
		}
		return nil
	}
	fwliveWitnessPings(t, c, src,
		// Holds the drain until the raw write is in.
		func() { _ = virt.UndefineDomainPreservingState(admittedVM) },
		func() {
			fwliveWitnessUntilGate(src, "fenced")
			time.Sleep(300 * time.Millisecond)
			_, _ = db.DB().ExecContext(context.Background(), `INSERT INTO fwlive_raw_probe (k) VALUES ('raw')`)
			close(rawDone)
			_ = virt.DomainExists(fwwVM)
		})
	<-inCall
	go func() {
		<-rawDone
		close(holdCall)
	}()

	err := k.killWithin(time.Minute)
	if err == nil || !strings.Contains(err.Error(), "got past") {
		t.Fatalf("the kill returned %v, want it to report the write past the client's lock", err)
	}
	if err := k.awaitEnd(time.Minute); err != nil {
		t.Fatal(err)
	}
	k.revive()
	fwliveRestartUp(t, c, src)
}

// fix1 I5. A libvirt call admitted before the fence asks libvirt again on its
// own goroutine once the fence is up (a hook of the call, as DomainState
// asks its connection). That is the same call: it passes, ends, and the
// kill goes on.
//
// On the first fix: the nested call waits at the fence, its admitted call
// never ends, and the kill runs out at the drain, red.
func TestFleet_FwLiveCrash_ANestedLibvirtCallDoesNotStopTheDeath(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	const admittedVM = "fwlive-admitted"
	src.Virt.DefineStoppedDomain(admittedVM, "52:54:00:aa:bb:03")
	k := fwliveRestartFreeze(t, c, src, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, k.reached, done, "the migration call")

	virt := src.Virt
	inCall := make(chan struct{})
	virt.FailUndefinePreserv = func(name string) error {
		if name == admittedVM {
			close(inCall)
			fwliveWitnessUntilGate(src, "fenced")
			_ = virt.DomainExists(fwwVM)
		}
		return nil
	}
	fwliveWitnessPings(t, c, src, func() { _ = virt.UndefineDomainPreservingState(admittedVM) })
	<-inCall

	k.die(true)
	fwliveRestartUp(t, c, src)
}

// The probes of our review of the second fix (fwlivefix-r2-review.md, I-1
// and I-2). Each schedule races the fence it probes, so it runs several
// times: one run in which the effect lands is a failure.
const fwliveWitnessRuns = 8

// r2 I-1. A goroutine of the daemon is in a database transaction when the
// fence goes up; once its write returns it writes a file and, refused,
// records its failure in the database instead. That record must not land:
// the database is fenced before the files are, so the reaction waits at the
// client's lock and is refused at the death.
//
// On the second fix: the files are fenced while the database fence's own
// take of the lock may still be pending, and the reaction sometimes commits
// into the state taken at the death, red.
func TestFleet_FwLiveCrash_AReactionToTheFileFenceDoesNotReachTheDatabase(t *testing.T) {
	for i := 0; i < fwliveWitnessRuns; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ctx := context.Background()
			c, src, dst, _ := fwliveCluster(t)
			if _, err := src.DB.DB().ExecContext(ctx, `CREATE TABLE fwlive_reaction_probe (k TEXT PRIMARY KEY)`); err != nil {
				t.Fatal(err)
			}
			k := fwliveRestartFreeze(t, c, src, nil)
			done := fwliveMigrate(t, c, src, dst)
			fwliveRestartReach(t, k.reached, done, "the migration call")

			db, virt := src.DB, src.Virt
			probe := filepath.Join(src.FW.DataDir, "fwlive-reaction-probe")
			inTx := make(chan struct{})
			fwliveWitnessPings(t, c, src, func() {
				_, _ = db.ExecuteBatchGuarded(context.Background(), func(*sql.Tx) (bool, error) {
					close(inTx)
					fwliveWitnessUntilGate(src, "fenced")
					time.Sleep(200 * time.Millisecond)
					return true, nil
				}, []corrosion.Statement{{SQL: `INSERT INTO fwlive_reaction_probe (k) VALUES ('admitted')`}})
				if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
					_ = db.Execute(context.Background(), `INSERT INTO fwlive_reaction_probe (k) VALUES ('reaction')`)
				}
				_ = virt.DomainExists(fwwVM)
			})
			<-inTx

			k.die(true)
			var rows int
			if err := src.DB.DB().QueryRowContext(ctx,
				`SELECT COUNT(*) FROM fwlive_reaction_probe WHERE k = 'reaction'`).Scan(&rows); err != nil || rows != 0 {
				t.Errorf("the reaction to the file fence reached the database: %d rows (%v)", rows, err)
			}
			fwliveRestartUp(t, c, src)
		})
	}
}

// r2 I-2. A peer's call the daemon admitted while it lived is answered by
// its handler after the death. The peer must get no answer from the dead
// daemon: Unavailable, as from a dead process.
//
// On the second fix: only admission is gated, and the peer sometimes gets the
// dead daemon's successful answer, red.
func TestFleet_FwLiveCrash_APeerGetsNoAnswerAfterTheDeath(t *testing.T) {
	for i := 0; i < fwliveWitnessRuns; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			c, src, dst, _ := fwliveCluster(t)
			k := fwliveRestartFreeze(t, c, src, nil)
			done := fwliveMigrate(t, c, src, dst)
			fwliveRestartReach(t, k.reached, done, "the migration call")

			peer := c.PeerClient(dst, src)
			if _, err := peer.Ping(context.Background(), &pb.PingRequest{}); err != nil {
				t.Fatalf("fixture: dst's Ping of src: %v", err)
			}
			in := make(chan struct{})
			src.HookUnary("Ping", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
				close(in)
				fwliveWitnessUntilGate(src, "dead")
				return h(ctx, req)
			})
			answered := make(chan error, 1)
			go func() {
				_, err := peer.Ping(context.Background(), &pb.PingRequest{})
				answered <- err
			}()
			<-in

			k.die(true)
			select {
			case err := <-answered:
				if err == nil {
					t.Error("the peer got the dead daemon's answer")
				}
			case <-time.After(time.Minute):
				t.Fatal("the peer's call did not end")
			}
			fwliveRestartUp(t, c, src)
		})
	}
}

// fwliveWitnessLeaks is what the kill's check finds, on a fixture that can
// list it (nothing on one that cannot).
func fwliveWitnessLeaks(k any) []string {
	if l, ok := k.(interface{ leaks() []string }); ok {
		return l.leaks()
	}
	return nil
}
