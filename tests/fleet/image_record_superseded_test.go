package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Re-review 2, I-1: a newer live record of an image that lands while an
// operation on it runs is not a delete, and fails nothing.

type recordArrival struct {
	clock   string
	release chan struct{}
}

func waitArrival(t *testing.T, ch <-chan recordArrival) recordArrival {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(convergeTimeout):
		t.Fatal("no copy reached its record")
		return recordArrival{}
	}
}

// Two auto-pulls of one image onto one host — two VM creates there, both
// finding no local file — each copy the image from the peer that holds it.
// The copy begun second records first; the one begun first then records too,
// and both succeed.
func TestFleet_ImageAutoPull_TwoConcurrentOntoOneHostBothSucceed(t *testing.T) {
	c, n0 := liveImageCluster(t, "imgc")
	n2 := c.Nodes[2]
	ctx := context.Background()
	arrivals := make(chan recordArrival, 2)
	n2.Server.SetImageRecordClockHookForTest(func(name, clock string) {
		if name != "imgc" {
			return
		}
		a := recordArrival{clock: clock, release: make(chan struct{})}
		arrivals <- a
		<-a.release
	})
	t.Cleanup(func() { n2.Server.SetImageRecordClockHookForTest(nil) })

	errs := make(chan error, 2)
	pull := func() { errs <- n2.Server.AutoPullFromPeerForTest(ctx, "imgc", n0.Name) }
	go pull()
	first := waitArrival(t, arrivals) // published, record not yet written
	go pull()                         // begins after the first's clocks were reserved
	second := waitArrival(t, arrivals)

	close(second.release)
	eventually(t, convergeTimeout, "the copy begun second to record", func() bool {
		rows, err := n2.DB.Query(ctx, `SELECT updated_at FROM images WHERE name = 'imgc'`)
		return err == nil && len(rows) == 1 && rows[0].String("updated_at") == second.clock
	})
	close(first.release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("an auto-pull of imgc onto %s: %v, want both to succeed", n2.Name, err)
		}
	}
	rows, err := n2.DB.Query(ctx, `SELECT status FROM image_hosts WHERE image_name = 'imgc' AND host_name = ? AND deleted_at IS NULL`, n2.Name)
	if err != nil || len(rows) != 1 || rows[0].String("status") != "ready" {
		t.Fatalf("%s's record of its copy: %v (err %v), want one ready row", n2.Name, rows, err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if img := listedImage(t, c, n, "imgc"); img == nil {
			t.Errorf("%s does not list imgc", n.Name)
		}
	}
}

// lv image pull of new content under a live image's name, on node-0, while a
// VM create on node-1 copies the old content from node-2: node-1's copy begins
// after the pull and records first, and its record reaches node-0 before the
// pull's. The pull still records, and every host ends with its checksum.
func TestFleet_ImagePull_RacingACopyLeavesThePullsChecksum(t *testing.T) {
	src := filepath.Join(t.TempDir(), "new.qcow2")
	if err := qcow2.Create(src, 96<<20, nil); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(src)
	sum := sha256.Sum256(body)
	newChecksum := "sha256:" + hex.EncodeToString(sum[:])
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)

	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	importImageSizedOn(t, c, n2, "imgp", 64<<20)
	c.WaitConverged(t, convergeTimeout)
	old, _ := corrosion.GetImage(ctx, n2.DB, "imgp")
	if old == nil || old.Checksum == "" || old.Checksum == newChecksum {
		t.Fatalf("precondition: imgp's old record %+v", old)
	}

	// The pull's second record is its record of the downloaded copy.
	var calls atomic.Int32
	n0.Server.SetImageRecordHookForTest(func(n string) {
		if n != "imgp" || calls.Add(1) != 2 {
			return
		}
		if err := n1.Server.AutoPullImage(ctx, "imgp"); err != nil {
			t.Errorf("node-1's auto-pull of imgp: %v", err)
			return
		}
		// The hook runs on the pull's goroutine: no t.Fatal here.
		for deadline := time.Now().Add(convergeTimeout); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if img, err := corrosion.GetImage(ctx, n0.DB, "imgp"); err == nil && img != nil && img.Checksum == old.Checksum {
				return
			}
		}
		t.Errorf("node-1's record of the old content never reached node-0")
	})
	t.Cleanup(func() { n0.Server.SetImageRecordHookForTest(nil) })

	stream, err := c.SelfClient(n0).PullImage(ctx, &pb.PullImageRequest{Name: "imgp", SourceUrl: ts.URL + "/new.qcow2", Format: "qcow2"})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("pull: %v", err)
		}
	}
	eventually(t, convergeTimeout, "the pull to record its copy", func() bool {
		if calls.Load() < 2 {
			return false
		}
		rows, err := n0.DB.Query(ctx, `SELECT status FROM image_hosts WHERE image_name = 'imgp' AND host_name = ?`, n0.Name)
		return err == nil && len(rows) == 1 && rows[0].String("status") != "pulling"
	})
	rows, _ := n0.DB.Query(ctx, `SELECT status FROM image_hosts WHERE image_name = 'imgp' AND host_name = ?`, n0.Name)
	if len(rows) != 1 || rows[0].String("status") != "ready" {
		t.Fatalf("node-0's record of the pull: %v, want ready", rows)
	}
	// Before the release token latches, node-0's record of its copy is the
	// plain INSERT OR REPLACE: here it resets progress_pct, while a peer
	// applies it column-preserving and keeps the pull's 100. Both rows carry
	// one updated_at, and only anti-entropy's tie resolution settles them. It
	// does so only once the record has reached the peer: a pass run before
	// then finds node-0's row newer and leaves the split to the next pass.
	eventually(t, convergeTimeout, "node-0's record of its copy to reach every host", func() bool {
		return imageHostRowEverywhere(ctx, c, "imgp", n0)
	})
	antiEntropyEverywhere(t, c)
	c.WaitConverged(t, convergeTimeout)
	antiEntropyEverywhere(t, c)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		img, err := corrosion.GetImage(ctx, n.DB, "imgp")
		if err != nil || img == nil || img.Checksum != newChecksum {
			t.Errorf("%s: imgp's record %+v (err %v), want the pull's checksum %s", n.Name, img, err, newChecksum)
		}
	}
}

// Re-review 3, m-2: a VM create on node-1 copies imgo's old content from
// node-2 while lv image pull of new content runs on node-0, begun after the
// copy; the pull's record reaches node-1 before the copy records. The copy is
// older content than the image's record: it fails, retryably, node-1 records
// no ready copy of it, and node-1 builds no new disk on it (it is not the
// image's current file there).
func TestFleet_ImageAutoPull_OvertakenByARefreshPullIsNotReady(t *testing.T) {
	src := filepath.Join(t.TempDir(), "new.qcow2")
	if err := qcow2.Create(src, 96<<20, nil); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(src)
	sum := sha256.Sum256(body)
	newChecksum := "sha256:" + hex.EncodeToString(sum[:])
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)

	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	importImageSizedOn(t, c, n2, "imgo", 64<<20)
	c.WaitConverged(t, convergeTimeout)
	old, _ := corrosion.GetImage(ctx, n2.DB, "imgo")
	if old == nil || old.Checksum == "" || old.Checksum == newChecksum {
		t.Fatalf("precondition: imgo's old record %+v", old)
	}

	arrivals := make(chan recordArrival, 1)
	n1.Server.SetImageRecordClockHookForTest(func(name, clock string) {
		if name != "imgo" {
			return
		}
		a := recordArrival{clock: clock, release: make(chan struct{})}
		arrivals <- a
		<-a.release
	})
	t.Cleanup(func() { n1.Server.SetImageRecordClockHookForTest(nil) })
	errs := make(chan error, 1)
	go func() { errs <- n1.Server.AutoPullFromPeerForTest(ctx, "imgo", n2.Name) }()
	copying := waitArrival(t, arrivals) // published on node-1, not recorded

	stream, err := c.SelfClient(n0).PullImage(ctx, &pb.PullImageRequest{Name: "imgo", SourceUrl: ts.URL + "/new.qcow2", Format: "qcow2"})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("pull: %v", err)
		}
	}
	eventually(t, convergeTimeout, "the pull's record to reach node-1", func() bool {
		img, err := corrosion.GetImage(ctx, n1.DB, "imgo")
		return err == nil && img != nil && img.Checksum == newChecksum
	})
	close(copying.release)

	if err := <-errs; err == nil || !strings.Contains(err.Error(), "older content than the image's newer record") {
		t.Fatalf("node-1's copy of the old content: %v, want it refused as older content", err)
	}
	rows, err := n1.DB.Query(ctx, `SELECT status FROM image_hosts WHERE image_name = 'imgo' AND host_name = ? AND deleted_at IS NULL`, n1.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.String("status") == "ready" {
			t.Fatalf("node-1 records a ready copy of imgo holding the old content: %v", rows)
		}
	}
	if cur := n1.Server.ImagePathForTests("imgo"); fileExists(cur) {
		b, _ := os.ReadFile(cur)
		got := sha256.Sum256(b)
		if "sha256:"+hex.EncodeToString(got[:]) == old.Checksum {
			t.Fatalf("node-1's current file of imgo (%s) is the old content: new disks there would be built on it", cur)
		}
	}
	if img, _ := corrosion.GetImage(ctx, n1.DB, "imgo"); img == nil || img.Checksum != newChecksum {
		t.Fatalf("node-1's catalog row of imgo: %+v, want the pull's", img)
	}
}

// imageHostRowEverywhere reports whether every node holds holder's image_hosts
// row of image at the updated_at holder's own replica has.
func imageHostRowEverywhere(ctx context.Context, c *Cluster, image string, holder *Node) bool {
	const q = `SELECT updated_at FROM image_hosts WHERE image_name = ? AND host_name = ?`
	own, err := holder.DB.Query(ctx, q, image, holder.Name)
	if err != nil || len(own) != 1 {
		return false
	}
	for _, n := range c.Nodes {
		rows, err := n.DB.Query(ctx, q, image, holder.Name)
		if err != nil || len(rows) != 1 || rows[0].String("updated_at") != own[0].String("updated_at") {
			return false
		}
	}
	return true
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
