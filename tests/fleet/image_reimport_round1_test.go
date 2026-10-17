package fleet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Review rounds 1 and 2 of the F-1 fix. Only an operator's own request — lv
// image import, pull, build, a compose download — may bring a deleted image's
// name back; a copy from a peer (lv image push, an auto-pull or heal) never
// does, and any operation whose row is deleted while it runs records nothing
// (I-1, as round 2 corrected it). Once the release token has latched, an import
// on a host the delete has not reached yet is listed on every host (I-2). A
// deleted image's file published within the clock-skew margin of the delete
// is kept (I-3).

// rmDuringRecord deletes image name through via's catalog when on's call
// number at of recordImage begins (the operation's copy is published, its
// record not yet written), and waits until on reads the delete. It returns how
// many record calls on has seen.
func rmDuringRecord(t *testing.T, on, via *Node, name string, at int32) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	on.Server.SetImageRecordHookForTest(func(n string) {
		if n != name || calls.Add(1) != at {
			return
		}
		ctx := context.Background()
		if err := corrosion.DeleteImage(ctx, via.DB, name); err != nil {
			t.Errorf("lv image rm %s on %s: %v", name, via.Name, err)
			return
		}
		deadline := time.Now().Add(convergeTimeout)
		for time.Now().Before(deadline) {
			if d, err := corrosion.ImageDeletedAt(ctx, on.DB, name); err == nil && d != "" {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Errorf("%s never applied the delete of %s", on.Name, name)
	})
	t.Cleanup(func() { on.Server.SetImageRecordHookForTest(nil) })
	return &calls
}

// deletedEverywhere: after replication and anti-entropy, no host lists image
// name and every host's row reads deleted.
func deletedEverywhere(t *testing.T, c *Cluster, name string) {
	t.Helper()
	// Anti-entropy first: a bulk image_hosts tombstone expands over each
	// replica's own rows, so replicas that held different rows can stay
	// apart until a pass reconciles them.
	settleByAntiEntropy(t, c)
	for _, n := range c.Nodes {
		if img := listedImage(t, c, n, name); img != nil {
			t.Errorf("%s lists %s again after lv image rm: %+v", n.Name, name, img)
		}
		if d, err := corrosion.ImageDeletedAt(context.Background(), n.DB, name); err != nil || d == "" {
			t.Errorf("%s: %s's row reads live (err %v)", n.Name, name, err)
		}
	}
}

// settleByAntiEntropy runs anti-entropy passes on every node, as the
// daemons' schedule does, until the replicas agree. Only a pass settles a
// tie; the push loops carry nothing that does. After an lv image rm that
// raced a record, three replicas can each hold a different row at the
// delete's one stamp (it rewrote only some columns of each), and one pass
// per node in turn does not always settle three: a node that pulled before
// its peers settled keeps a row they then move past, and only the next pass
// takes it there.
func settleByAntiEntropy(t *testing.T, c *Cluster) {
	t.Helper()
	deadline := time.Now().Add(convergeTimeout)
	for {
		antiEntropyEverywhere(t, c)
		settle := time.Now().Add(2 * time.Second)
		for {
			apart, err := divergence(c.Nodes)
			if err != nil {
				t.Fatalf("divergence: %v", err)
			}
			if len(apart) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("replicas did not converge within %s of anti-entropy passes; tables apart: %s",
					convergeTimeout, strings.Join(apart, ", "))
			}
			if time.Now().After(settle) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func liveImageCluster(t *testing.T, name string) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0 := c.Nodes[0]
	importImageSizedOn(t, c, n0, name, 64<<20)
	c.WaitConverged(t, convergeTimeout)
	return c, n0
}

// An operator's import whose row is deleted while it runs records nothing.
func TestFleet_ImageRm_DuringAnImportKeepsTheImageDeleted(t *testing.T) {
	c, n0 := liveImageCluster(t, "imgx")
	rmDuringRecord(t, n0, c.Nodes[1], "imgx", 1)

	src := filepath.Join(t.TempDir(), "img.qcow2")
	if err := qcow2.Create(src, 96<<20, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(src)
	stream, err := c.SelfClient(n0).ImportImage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.ImportImageRequest{Name: "imgx", Format: "qcow2", Chunk: b}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CloseAndRecv(); status.Code(err) != codes.Aborted {
		t.Fatalf("an import lv image rm landed in: %v, want Aborted", err)
	}
	deletedEverywhere(t, c, "imgx")
}

// A peer's push (lv image push) whose row is deleted on the target while it
// runs records nothing there; a push of a name the target reads deleted is
// refused.
func TestFleet_ImageRm_DuringAPushKeepsTheImageDeleted(t *testing.T) {
	c, n0 := liveImageCluster(t, "imgx")
	n2 := c.Nodes[2]
	rmDuringRecord(t, n2, c.Nodes[1], "imgx", 1)

	push := func() error {
		stream, err := c.SelfClient(n0).PushImage(context.Background(), &pb.PushImageRequest{Name: "imgx", TargetHost: n2.Name})
		if err != nil {
			return err
		}
		for {
			if _, err := stream.Recv(); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
	if err := push(); status.Code(err) != codes.Aborted {
		t.Fatalf("a push lv image rm landed in: %v, want Aborted", err)
	}
	deletedEverywhere(t, c, "imgx")
	if err := push(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a push of a deleted name: %v, want FailedPrecondition", err)
	}
	deletedEverywhere(t, c, "imgx")
}

// An auto-pull — what a VM create and the reconciler's heal run — whose row is
// deleted while it runs records nothing.
func TestFleet_ImageRm_DuringAnAutoPullOrHealKeepsTheImageDeleted(t *testing.T) {
	c, _ := liveImageCluster(t, "imgx")
	n2 := c.Nodes[2]
	rmDuringRecord(t, n2, c.Nodes[1], "imgx", 1)
	if err := n2.Server.AutoPullImage(context.Background(), "imgx"); err == nil {
		t.Fatal("an auto-pull lv image rm landed in succeeded")
	}
	deletedEverywhere(t, c, "imgx")
	// node-1 holds no copy: its auto-pull of the deleted name finds nothing
	// to pull and records nothing. (node-2's copy is left for lv image prune;
	// an auto-pull there uses the local file and writes no record either.)
	if err := c.Nodes[1].Server.AutoPullImage(context.Background(), "imgx"); err == nil {
		t.Fatal("an auto-pull of a deleted name succeeded")
	}
	deletedEverywhere(t, c, "imgx")
}

// lv image pull: one whose row is deleted while it downloads records nothing,
// and a pull of a deleted name brings it back on every host, as on main.
func TestFleet_ImageRm_DuringAPullKeepsTheImageDeletedAndAPullAfterRevives(t *testing.T) {
	src := filepath.Join(t.TempDir(), "img.qcow2")
	if err := qcow2.Create(src, 64<<20, nil); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(src)
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)

	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0 := c.Nodes[0]
	pull := func() error {
		stream, err := c.SelfClient(n0).PullImage(context.Background(), &pb.PullImageRequest{Name: "imgp", SourceUrl: ts.URL + "/img.qcow2", Format: "qcow2"})
		if err != nil {
			return err
		}
		for {
			if _, err := stream.Recv(); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
	// The first record call is the pull's "pulling" row as it begins; the
	// second is its record of the downloaded copy.
	calls := rmDuringRecord(t, n0, c.Nodes[1], "imgp", 2)
	if err := pull(); err != nil {
		t.Fatalf("pull: %v", err)
	}
	eventually(t, convergeTimeout, "the pull to try to record its copy", func() bool {
		if calls.Load() < 2 {
			return false
		}
		hosts, err := n0.DB.Query(context.Background(), `SELECT status FROM image_hosts WHERE image_name = 'imgp' AND host_name = ?`, n0.Name)
		return err == nil && len(hosts) == 1 && hosts[0].String("status") == "error"
	})
	deletedEverywhere(t, c, "imgp")

	n0.Server.SetImageRecordHookForTest(nil)
	before := hits.Load()
	if err := pull(); err != nil {
		t.Fatalf("a pull of a deleted name: %v, want it to bring the image back", err)
	}
	if hits.Load() == before {
		t.Fatal("a pull of a deleted name did not download it")
	}
	eventually(t, convergeTimeout, "the pull to record its copy", func() bool {
		hosts, err := n0.DB.Query(context.Background(), `SELECT status FROM image_hosts WHERE image_name = 'imgp' AND host_name = ?`, n0.Name)
		return err == nil && len(hosts) == 1 && hosts[0].String("status") == "ready"
	})
	// The revived copy's record ties with the delete's rows as the delete
	// raced the record above: settled as deletedEverywhere settles it (8 of
	// 24 runs under load stayed apart on image_hosts after one pass each).
	settleByAntiEntropy(t, c)
	for _, n := range c.Nodes {
		if img := listedImage(t, c, n, "imgp"); img == nil {
			t.Errorf("%s does not list imgp after a pull brought it back", n.Name)
		}
	}
}

// I-2: with the release token latched, an operator re-imports on node-0
// before lv image rm on node-1 has reached it. node-0's own row reads live,
// yet its copy is listed on every host once replication and anti-entropy
// run.
func TestFleet_ImageReimport_BeforeTheDeleteArrivesIsListedEverywhere(t *testing.T) {
	c, gates := latchedFleet(t, 3, 0)
	latchReleaseToken(t, c, gates)
	imageRmFleet(c)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	importImageSizedOn(t, c, n0, "imgz", 64<<20)
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFault(n1, n0, LinkFault{Block: true})
	c.SetLinkFault(n2, n0, LinkFault{Block: true})
	if err := corrosion.DeleteImage(ctx, n1.DB, "imgz"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "node-2 to apply the delete", func() bool {
		d, err := corrosion.ImageDeletedAt(ctx, n2.DB, "imgz")
		return err == nil && d != ""
	})
	if d, _ := corrosion.ImageDeletedAt(ctx, n0.DB, "imgz"); d != "" {
		t.Fatal("precondition: node-0 applied the delete through a blocked link")
	}
	f := importImageSizedOn(t, c, n0, "imgz", 96<<20)
	digest, _ := image.RecordedDigest(f)
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	antiEntropyEverywhere(t, c)
	c.WaitConverged(t, convergeTimeout)
	antiEntropyEverywhere(t, c)

	for _, n := range c.Nodes {
		img := listedImage(t, c, n, "imgz")
		if img == nil {
			t.Errorf("%s does not list the re-import", n.Name)
			continue
		}
		if img.GetChecksum() != "sha256:"+digest {
			t.Errorf("%s lists checksum %s, want the re-import's", n.Name, img.GetChecksum())
		}
		if !slices.Contains(img.GetHosts(), n0.Name) {
			t.Errorf("%s lists imgz on hosts %v, want %s, which holds the re-import", n.Name, img.GetHosts(), n0.Name)
		}
	}
}

// I-3: with the default margin, lv image rm moments after an import keeps the
// file — it may belong to an import after the delete, as far as two hosts'
// clocks can tell — and says when lv image rm again removes it.
func TestFleet_ImageRm_KeepsAFilePublishedWithinTheMarginOfTheDelete(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0 := c.Nodes[0]
	n0.Server.SetImageDeleteMarginForTest(0) // the default: the clock-skew floor
	f := importImageSizedOn(t, c, n0, "imgm", 64<<20)
	resp, err := c.SelfClient(n0).RemoveImage(context.Background(), &pb.RemoveImageRequest{Name: "imgm"})
	if err != nil {
		t.Fatal(err)
	}
	if r := keptReason(resp, n0.Name, f); !strings.Contains(r, "within 5m0s of its image's delete") || !strings.Contains(r, "lv image rm imgm again after") {
		t.Errorf("%s reported %v; want the file kept within the margin of the delete", n0.Name, hostResult(resp, n0.Name))
	}
	if !fileThere(f) {
		t.Fatal("the file published moments before the delete is gone")
	}
}

// An operator's own lv image push is still a copy at the target: relayed with
// forwarded identity, the target authenticates the operator, and only the
// push's mark says it is not an import. A push of a name the target reads
// deleted is refused, and the name stays deleted.
func TestFleet_ImageRm_AnOperatorsPushOfADeletedNameIsACopy(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	latchForwardedIdentity(t, c)
	n0, n2 := c.Nodes[0], c.Nodes[2]
	tok := userOn(t, c, n0, "pusher", "operator")
	importImageSizedOn(t, c, n0, "imgx", 64<<20)
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.DeleteImage(context.Background(), c.Nodes[1].DB, "imgx"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	stream, err := c.bearerClient(n0, tok).PushImage(context.Background(), &pb.PushImageRequest{Name: "imgx", TargetHost: n2.Name})
	if err == nil {
		for {
			if _, err = stream.Recv(); err != nil {
				break
			}
		}
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an operator's push of a deleted name: %v, want FailedPrecondition", err)
	}
	deletedEverywhere(t, c, "imgx")
}

// Re-review 1, R-m2, a rolling upgrade: an operator's lv image push from a
// source on an earlier build carries no copy mark, and under forwarded
// identity the target authenticates the operator. It is still a copy: it came
// over a peer's transport. A push of a name the target reads deleted is
// refused, and the name stays deleted.
func TestFleet_ImageRm_AnUnmarkedPushFromAnEarlierBuildIsACopy(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	latchForwardedIdentity(t, c)
	n0, n2 := c.Nodes[0], c.Nodes[2]
	n0.Server.SetImagePushUnmarkedForTest(true)
	tok := userOn(t, c, n0, "pusher", "operator")
	importImageSizedOn(t, c, n0, "imgx", 64<<20)
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.DeleteImage(context.Background(), c.Nodes[1].DB, "imgx"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	stream, err := c.bearerClient(n0, tok).PushImage(context.Background(), &pb.PushImageRequest{Name: "imgx", TargetHost: n2.Name})
	if err == nil {
		for {
			if _, err = stream.Recv(); err != nil {
				break
			}
		}
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an unmarked push of a deleted name under forwarded identity: %v, want FailedPrecondition", err)
	}
	deletedEverywhere(t, c, "imgx")
}

// Re-review 1, R-m1: lv image rm on node-1, stamped after an import on node-0
// began, reaches node-0 only after the import has recorded (the links into
// node-0 are blocked, and nothing waits for the delete). The record was
// written at clocks reserved as the import began, so the delete is newer and
// wins on every host once the links heal — for node-0's own image_hosts row
// too (re-review 2, m-1), in either form of that row.
func TestFleet_ImageRm_StampedAfterAnImportBeganWinsThoughItArrivesLate(t *testing.T) {
	t.Run("plain host row", func(t *testing.T) {
		c, n0 := liveImageCluster(t, "imgx")
		rmStampedAfterAnImportBegan(t, c, n0)
	})
	t.Run("reviving host row (release latched)", func(t *testing.T) {
		c, gates := latchedFleet(t, 3, 0)
		latchReleaseToken(t, c, gates)
		imageRmFleet(c)
		n0 := c.Nodes[0]
		importImageSizedOn(t, c, n0, "imgx", 64<<20)
		c.WaitConverged(t, convergeTimeout)
		rmStampedAfterAnImportBegan(t, c, n0)
	})
}

func rmStampedAfterAnImportBegan(t *testing.T, c *Cluster, n0 *Node) {
	t.Helper()
	n1, n2 := c.Nodes[1], c.Nodes[2]
	c.SetLinkFault(n1, n0, LinkFault{Block: true})
	c.SetLinkFault(n2, n0, LinkFault{Block: true})
	var deleted atomic.Bool
	n0.Server.SetImageRecordHookForTest(func(n string) {
		if n == "imgx" && deleted.CompareAndSwap(false, true) {
			if err := corrosion.DeleteImage(context.Background(), n1.DB, "imgx"); err != nil {
				t.Errorf("lv image rm on %s: %v", n1.Name, err)
			}
		}
	})
	t.Cleanup(func() { n0.Server.SetImageRecordHookForTest(nil) })

	importImageSizedOn(t, c, n0, "imgx", 96<<20)
	if !deleted.Load() {
		t.Fatal("the import never reached its record")
	}
	if d, _ := corrosion.ImageDeletedAt(context.Background(), n0.DB, "imgx"); d != "" {
		t.Fatal("precondition: node-0 applied the delete through a blocked link before the import recorded")
	}
	c.ClearLinkFaults()
	deletedEverywhere(t, c, "imgx")
	for _, n := range c.Nodes {
		rows, err := n.DB.Query(context.Background(),
			`SELECT host_name FROM image_hosts WHERE image_name = 'imgx' AND deleted_at IS NULL`)
		if err != nil || len(rows) != 0 {
			t.Errorf("%s: imgx's image_hosts rows read live after the delete: %v (err %v)", n.Name, rows, err)
		}
	}
}
