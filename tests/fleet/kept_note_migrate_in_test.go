package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Files a delete kept on dst, noted in dst's kept-disk note, survive the
// delete there of a later VM of the same name that came to dst by a cold
// migration, with disk names that do not collide: a kept chain (its overlay
// noted as a kept disk, the base under it as a file it backs on) and a kept
// disk on its own. The delete's debris sweep used to take every one of them
// (re-review 2, F1; pre-existing on 4b13deaf1).
//
// Red on dc4cad50d. Mutation: drop the note from the sweep's keep set: red.
func TestFleet_KeptFilesSurviveTheDeleteOfAMigratedInVMOfTheName(t *testing.T) {
	ctx := context.Background()
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 2, SharedCRDT: true, SharedDataDir: true})
	dst := sc.dst
	dir := filepath.Join(dst.Server.DataDir(), "disks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "os1-data.qcow2")
	ov := filepath.Join(dir, "os1-data.s1")
	top := filepath.Join(dir, "os1-scratch.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	appendTo(t, base, "OLD-BASE-DATA")
	if err := qcow2.CreateWithBackingFormat(ov, base, "qcow2", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(top, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	appendTo(t, top, "OLD-KEPT-TOP")
	if err := health.NoteKeptDisks(dst.Server.DataDir(), "os1", []string{ov, top}); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptBackingFiles(dst.Server.DataDir(), "os1", []string{base}); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{base: readFileT(t, base), ov: readFileT(t, ov), top: readFileT(t, top)}

	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold migrate os1 to %s: %v", dst.Name, err)
	}
	if _, err := sc.c.SelfClient(dst).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "os1", Force: true}); err != nil {
		t.Fatalf("lv rm os1 on %s: %v", dst.Name, err)
	}
	for p, b := range files {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, b) {
			t.Errorf("kept file %s changed or went after the migrated-in os1's delete (err=%v)", filepath.Base(p), err)
		}
	}
}
