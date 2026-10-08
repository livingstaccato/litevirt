package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// m-new-5: an incoming image a crashed full copy left (older than a day) is
// removed before the next copy into the pool; a fresh one, and any other
// image, is never touched.
func TestCephSweepIncoming_RemovesOnlyStaleIncomingImages(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	old := fmt.Sprintf("vm1-root-copy-a%s%d-abc", incomingMarker, now.Add(-48*time.Hour).Unix())
	fresh := fmt.Sprintf("vm1-root-copy-b%s%d-def", incomingMarker, now.Add(-time.Hour).Unix())
	listing := strings.Join([]string{"vm1-root", old, fresh, "db-root"}, "\n")
	run, calls := stubRunner(func(sub string) ([]byte, error) {
		if sub == "ls" {
			return []byte(listing), nil
		}
		return nil, nil
	})
	d := &cephDriver{pool: "copies", run: run}
	d.sweepIncoming(context.Background(), "copies/vm1-root-copy-c", now)
	var removed []string
	for _, c := range *calls {
		if len(c.args) > 0 && c.args[0] == "rm" {
			removed = append(removed, c.args[len(c.args)-1])
		}
	}
	if len(removed) != 1 || removed[0] != "copies/"+old {
		t.Errorf("removed %v, want only the stale incoming copies/%s", removed, old)
	}
}
