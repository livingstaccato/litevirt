package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// A container relocated off a failed host leaves its own rootfs there.
//
// The relocation recreates the container from its image (or restores it from
// a backup) on another host. Its own container directory, with whatever the
// container wrote since that image or backup, stays on the failed host:
// relocation tombstones the source row, the returning host's sweep acts only
// on rows naming it, the orphan report never destroys anything, a create
// refuses an existing container, and a relocation back onto that host adopts
// it (recreateRelocated). So nothing deletes it — but nothing said so either.
//
// Surface only, as for a VM's host-local disk (stranded_disk.go):
//
//   - the coordinator records it when it relocates the container: condition
//     ct_rootfs_stranded (evaluator ct_rootfs, subject container/<name>@<host>,
//     a warning), a ct.failover.rootfs_stranded event and audit row, and a
//     ct.rootfs.stranded notification; `lv ct inspect` shows it;
//   - the host, once back, records the rootfs path (tendStrandedRootfs), or
//     clears the record when no container of that name is there any more;
//   - a relocation back onto that host that adopts the old rootfs says so
//     (ct.relocate.adopted audit row and event) and clears the record.
//
// Nothing is moved, renamed or deleted by any of it.

const (
	CTRootfsEvaluator    = "ct_rootfs"
	CondCTRootfsStranded = "ct_rootfs_stranded"
)

// StrandedRootfs is the evidence of one ct_rootfs_stranded condition.
type StrandedRootfs struct {
	Container string `json:"container"`
	Host      string `json:"host"`
	MovedTo   string `json:"moved_to,omitempty"`
	How       string `json:"how"`            // image-recreate | backup-restore
	Path      string `json:"path,omitempty"` // filled in by Host once it is back
	Since     string `json:"since"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix"`
}

func (e StrandedRootfs) detail() string {
	where := "on " + e.Host
	if e.Path != "" {
		where += " at " + e.Path
	}
	return fmt.Sprintf("container %s was relocated to %s (%s) without its own rootfs: that, with what the container wrote, "+
		"is still %s", e.Container, e.MovedTo, e.How, where)
}

func rootfsFix(name, host string) string {
	return fmt.Sprintf("nothing removes it. To keep its data, copy what you need out of it on %[2]s; "+
		"a later relocation of %[1]s back onto %[2]s adopts it as the container", name, host)
}

func writeStrandedRootfs(ctx context.Context, db *corrosion.Client, reporter string, row corrosion.HealthCondition, had, resolve bool, ev StrandedRootfs, now time.Time) error {
	ts := now.UTC().Format(time.RFC3339)
	if !had || row.Lifecycle == corrosion.ConditionResolved {
		if resolve {
			return nil
		}
		row = corrosion.HealthCondition{
			Evaluator: CTRootfsEvaluator, Code: CondCTRootfsStranded, SubjectKind: "container",
			SubjectID: strandedSubject(ev.Container, ev.Host), FirstSeen: ts, ConfirmedAt: ts,
		}
	}
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityWarning, []string{ev.Host}, ts, reporter
	if resolve {
		row.Lifecycle, row.ResolvedAt, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, ts, 0, 1
	} else {
		ev.Detail, ev.Fix = ev.detail(), rootfsFix(ev.Container, ev.Host)
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		row.Evidence, row.Lifecycle, row.ResolvedAt = string(b), corrosion.ConditionConfirmed, ""
		row.ObserveCount++
		row.CleanCount = 0
	}
	return corrosion.UpsertHealthCondition(ctx, db, row)
}

func readStrandedRootfs(ctx context.Context, db *corrosion.Client, name, host string) (corrosion.HealthCondition, StrandedRootfs, bool, error) {
	row, had, err := corrosion.GetHealthCondition(ctx, db, CTRootfsEvaluator, CondCTRootfsStranded, "container", strandedSubject(name, host))
	if err != nil || !had {
		return row, StrandedRootfs{}, false, err
	}
	var ev StrandedRootfs
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		return row, StrandedRootfs{}, true, err
	}
	return row, ev, true, nil
}

// RecordStrandedRootfs records that container name was relocated off host to
// movedTo (how), leaving its own rootfs on host, and returns the detail for
// the caller's event, audit row and notification.
func RecordStrandedRootfs(ctx context.Context, db *corrosion.Client, reporter, name, host, movedTo, how string, now time.Time) (string, error) {
	row, _, had, err := readStrandedRootfs(ctx, db, name, host)
	if err != nil {
		return "", err
	}
	ev := StrandedRootfs{Container: name, Host: host, MovedTo: movedTo, How: how, Since: now.UTC().Format(time.RFC3339)}
	if err := writeStrandedRootfs(ctx, db, reporter, row, had, false, ev, now); err != nil {
		return "", err
	}
	return ev.detail(), nil
}

// StrandedRootfsOf returns the open ct_rootfs_stranded records of container
// name, for `lv ct inspect`.
func StrandedRootfsOf(ctx context.Context, db *corrosion.Client, name string) ([]StrandedRootfs, error) {
	open, err := corrosion.ListHealthConditions(ctx, db, false)
	if err != nil {
		return nil, err
	}
	var out []StrandedRootfs
	for _, row := range open {
		if row.Evaluator != CTRootfsEvaluator || row.Code != CondCTRootfsStranded || !strings.HasPrefix(row.SubjectID, name+"@") {
			continue
		}
		var ev StrandedRootfs
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.Container != name {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

// tendStrandedRootfs acts on this host's ct_rootfs_stranded records: it names
// the rootfs path while a container of that name is here, and clears the
// record once none is, or once a live row names it here again. It touches no
// container.
func (c *ContainerChecker) tendStrandedRootfs(ctx context.Context, local map[string]bool) {
	// Not from a replica still catching up: a row it has not received yet
	// (the relocation) reads as the container still here.
	if ok, _ := corrosion.ReplicaTrusted(ctx, c.db, c.hostName, c.replicaCaughtUp); !ok {
		return
	}
	open, err := corrosion.ListHealthConditions(ctx, c.db, false)
	if err != nil {
		return
	}
	suffix := "@" + c.hostName
	for _, row := range open {
		if row.Evaluator != CTRootfsEvaluator || row.Code != CondCTRootfsStranded {
			continue
		}
		var ev StrandedRootfs
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			continue
		}
		if !strings.HasSuffix(row.SubjectID, suffix) {
			c.resolveRootfsOnRemovedHost(ctx, row, ev)
			continue
		}
		live, err := corrosion.GetContainer(ctx, c.db, c.hostName, ev.Container)
		if err != nil {
			continue
		}
		switch {
		case live != nil && !strings.HasPrefix(live.StateDetail, "relocate"):
			// Back here as a live container: the adopt (or an operator) made
			// it the container again.
			_ = writeStrandedRootfs(ctx, c.db, c.hostName, row, true, true, ev, time.Now())
		case !local[ev.Container]:
			slog.Info("containercheck: the rootfs a relocation left here is gone; clearing its record", "container", ev.Container)
			_ = writeStrandedRootfs(ctx, c.db, c.hostName, row, true, true, ev, time.Now())
		case ev.Path == "":
			store := c.lxcStore
			if store == "" {
				store = "/var/lib/lxc"
			}
			ev.Path = lxc.RootfsPath(store, ev.Container)
			if err := writeStrandedRootfs(ctx, c.db, c.hostName, row, true, false, ev, time.Now()); err != nil {
				slog.Warn("containercheck: could not record the rootfs path a relocation left here", "container", ev.Container, "error", err)
				continue
			}
			slog.Warn("containercheck: a relocation left this container's own rootfs here; it is kept", "container", ev.Container, "path", ev.Path)
			c.publish("ct.rootfs.stranded", ev.Container, ev.detail())
		}
	}
}

// noteAdoptedRootfs says that a relocation onto this host adopted a container
// already here which a relocation off this host had left behind: the
// container now runs on that old rootfs, not on a fresh image. It clears the
// record. A container this relocation created itself on an earlier pass has
// no record, so nothing is said.
func (c *ContainerChecker) noteAdoptedRootfs(ctx context.Context, name string) {
	row, ev, had, err := readStrandedRootfs(ctx, c.db, name, c.hostName)
	if err != nil || !had || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	detail := fmt.Sprintf("relocation onto %s adopted container %s's own rootfs, left here when it was relocated to %s: "+
		"the container runs on that data, not on a fresh %s", c.hostName, name, ev.MovedTo, ev.How)
	if err := c.auditContainer(ctx, "ct.relocate.adopted", name, detail); err != nil {
		slog.Warn("containercheck: record the adopted rootfs", "container", name, "error", err)
	}
	c.publish("ct.relocate.adopted", name, detail)
	slog.Warn("containercheck: relocation adopted the container's own rootfs left here earlier", "container", name)
	_ = writeStrandedRootfs(ctx, c.db, c.hostName, row, true, true, ev, time.Now())
}

// resolveRootfsOnRemovedHost clears another host's record once nothing can act
// on it: that host was removed from the cluster (or is unknown) and no live
// container of that name is left anywhere. The host itself clears its own.
func (c *ContainerChecker) resolveRootfsOnRemovedHost(ctx context.Context, row corrosion.HealthCondition, ev StrandedRootfs) {
	if ev.Container == "" || ev.Host == "" {
		return
	}
	if h, err := corrosion.GetHost(ctx, c.db, ev.Host); err != nil || (h != nil && h.State != "removed") {
		return
	}
	live, err := c.db.Query(ctx, `SELECT 1 FROM containers WHERE name = ? AND deleted_at IS NULL LIMIT 1`, ev.Container)
	if err != nil || len(live) > 0 {
		return
	}
	_ = writeStrandedRootfs(ctx, c.db, c.hostName, row, true, true, ev, time.Now())
}
