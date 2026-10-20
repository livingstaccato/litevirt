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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
