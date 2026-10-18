package health

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A deleted VM's shut-off definition on a host a failover moved it off.
//
// The reconciler's leftover cleanup (selfFence) undefines a shut-off domain
// whose LIVE row names another host. A VM deleted before its old host's first
// pass after a rejoin has no live row there, so that cleanup skips it, the
// delete's leftover request declines while the domain is defined, and the
// orphan report only reports it.
//
// Such a domain is undefined here, by the reconciler (on the second
// consecutive sighting, as the orphan report) and by the delete's leftover
// request, only when every one of these holds:
//
//   - no live row of the name on this host's replica, and the replica is
//     trusted (the caller checks);
//   - the name's row is tombstoned and names ANOTHER host;
//   - the domain carries litevirt's owner-epoch element, and the row's owner
//     epoch is STRICTLY greater than it: the record moved past this copy
//     before it was deleted;
//   - the host-local owner-epoch marker is absent or below the row's epoch;
//     an unreadable one keeps the domain;
//   - the domain is shut off: cleanableLeftover, or a shut-off with an unknown
//     reason and no managed-save image.
//
// Undefine only: no destroy, no disk touched, and the UEFI vars and TPM state
// kept (UndefineDomainPreservingState), since no replicated record says
// whether the delete was `lv rm --keep-disks`. The domain's identity (its
// uuid and owner epoch) is read again right before the undefine, so a domain
// a create of the name defined meanwhile is never the one undefined. Then,
// once the domain is gone and the name still has no live row, the
// owner-epoch marker goes, and each UEFI vars file the definition named, and
// the name-keyed one (<data_dir>/nvram/<vm>_VARS.fd), is renamed to
// <path>.superseded-<time>: its bytes stay, `lv host superseded-disks` lists
// it (ListSupersededVars), and a create of the name is not refused for vars
// already there. The TPM state is UUID-keyed, so a new VM never meets it, and
// it is left where it is. A running or paused domain, an equal or older row
// epoch, a managed-stamp-only domain and anything unreadable stay
// report-only.

// SupersededLeftoverVirt is the libvirt surface the rule needs.
type SupersededLeftoverVirt interface {
	DomainExists(name string) bool
	DomainStateReason(name string) (lv.DomainStatus, error)
	HasManagedSaveImage(name string) (bool, error)
	GetDomainOwnerEpoch(name string) (int64, bool, error)
	DumpXMLInactive(name string) (string, error)
	UndefineDomainPreservingState(name string) error
}

// SupersededLeftover is a shut-off domain the rule admits.
type SupersededLeftover struct {
	Name          string
	RowHost       string
	RowOwnerEpoch int64
	MarkerEpoch   int64
	Reason        string   // the shut-off reason
	UUID          string   // the definition's uuid, "" when it names none
	Vars          []string // the UEFI vars files to set aside once it is gone
}

// supersededStoppedLeftover applies the rule to name. ok=false carries why.
func supersededStoppedLeftover(ctx context.Context, db *corrosion.Client, virt SupersededLeftoverVirt,
	dataDir, self, name string) (SupersededLeftover, bool, string) {
	lo := SupersededLeftover{Name: name}
	if vm, err := corrosion.GetVM(ctx, db, name); err != nil {
		return lo, false, "the record cannot be read: " + err.Error()
	} else if vm != nil {
		return lo, false, "the name has a live record"
	}
	trace, err := corrosion.LookupVMRowAnyState(ctx, db, name)
	if err != nil {
		return lo, false, "the deleted record cannot be read: " + err.Error()
	}
	if trace == nil || trace.DeletedAt == "" {
		return lo, false, "no deleted record of the name"
	}
	lo.RowHost, lo.RowOwnerEpoch = trace.HostName, trace.OwnerEpoch
	if trace.HostName == "" || trace.HostName == self {
		return lo, false, "the deleted record names this host"
	}
	epoch, marked, err := virt.GetDomainOwnerEpoch(name)
	if err != nil {
		return lo, false, "the domain's owner epoch cannot be read: " + err.Error()
	}
	if !marked || epoch < 1 {
		return lo, false, "the domain carries no owner epoch"
	}
	lo.MarkerEpoch = epoch
	if trace.OwnerEpoch <= epoch {
		return lo, false, fmt.Sprintf("the deleted record's owner epoch %d is not newer than the domain's %d", trace.OwnerEpoch, epoch)
	}
	if fileEpoch, has, err := ReadVMOwnerEpochMarker(dataDir, name); err != nil {
		return lo, false, "the owner-epoch marker cannot be read: " + err.Error()
	} else if has && fileEpoch >= trace.OwnerEpoch {
		return lo, false, fmt.Sprintf("the owner-epoch marker %d is not older than the deleted record's %d", fileEpoch, trace.OwnerEpoch)
	}
	xml, err := virt.DumpXMLInactive(name)
	if err != nil {
		return lo, false, "the domain's definition cannot be read: " + err.Error()
	}
	lo.UUID = lv.UUIDFromXML(xml)
	for _, p := range []string{lv.NvramPathFromXML(xml), lv.NvramPath(dataDir, name)} {
		if p != "" && !slices.Contains(lo.Vars, filepath.Clean(p)) {
			lo.Vars = append(lo.Vars, filepath.Clean(p))
		}
	}
	st, err := virt.DomainStateReason(name)
	if err != nil {
		return lo, false, "the domain's state cannot be read: " + err.Error()
	}
	lo.Reason = st.Reason
	if cleanableLeftover(st) {
		return lo, true, ""
	}
	if !unknownShutoff(st) {
		return lo, false, fmt.Sprintf("the domain is not shut off (state %s, reason %s)", st.State, st.Reason)
	}
	saved, err := virt.HasManagedSaveImage(name)
	if err != nil {
		return lo, false, "whether the domain has a managed-save image cannot be read: " + err.Error()
	}
	if saved {
		return lo, false, "the domain has a managed-save image (saved RAM)"
	}
	return lo, true, ""
}

// ReapSupersededStoppedLeftover undefines name here when the rule above
// admits it, then removes its owner-epoch marker, and records a VM event. by
// names the caller for the log. It returns whether it undefined the domain,
// and otherwise why not. The caller has checked the replica is trusted.
func ReapSupersededStoppedLeftover(ctx context.Context, db *corrosion.Client, virt SupersededLeftoverVirt,
	dataDir, self, name, by string) (bool, string) {
	lo, ok, why := supersededStoppedLeftover(ctx, db, virt, dataDir, self, name)
	if !ok {
		return false, why
	}
	// The same definition as the rule judged: a create of the name on this
	// host undefines a stopped leftover and defines its own domain, which
	// carries no owner epoch until it runs.
	if epoch, marked, err := virt.GetDomainOwnerEpoch(name); err != nil || !marked || epoch != lo.MarkerEpoch {
		return false, "the domain changed since it was judged (owner epoch)"
	}
	if xml, err := virt.DumpXMLInactive(name); err != nil || lv.UUIDFromXML(xml) != lo.UUID {
		return false, "the domain changed since it was judged (uuid)"
	}
	if err := virt.UndefineDomainPreservingState(name); err != nil {
		if !virt.DomainExists(name) {
			return false, "the domain is already gone"
		}
		slog.Warn(by+": could not undefine a deleted VM's superseded shut-off domain; kept",
			"vm", name, "error", err)
		return false, "undefine failed: " + err.Error()
	}
	if virt.DomainExists(name) {
		// It started between the check and the undefine: it survives as a
		// transient domain, running, and is left to the orphan report.
		slog.Warn(by+": a deleted VM's superseded domain was running at its undefine; left to the orphan report",
			"vm", name)
		return false, "the domain was running at its undefine"
	}
	marker := "removed"
	if vm, err := corrosion.GetVM(ctx, db, name); err != nil || vm != nil {
		marker = "kept (the name has a live record again, or it cannot be read)"
	} else if err := RemoveVMOwnerEpochMarker(dataDir, name); err != nil {
		marker = "not removed: " + err.Error()
	}
	// Re-checked right before each rename: a same-name create may have
	// defined its domain, or its record arrived, since the undefine.
	vars := setAsideSupersededVars(lo.Vars, time.Now(), func() string {
		if virt.DomainExists(name) {
			return "a domain of the name is defined again"
		}
		if vm, err := corrosion.GetVM(ctx, db, name); err != nil || vm != nil {
			return "the name has a live record again, or it cannot be read"
		}
		return ""
	})
	detail := fmt.Sprintf("%s undefined its shut-off definition of deleted VM %s: the deleted record names %s at owner epoch %d, "+
		"newer than this copy's %d; disks and TPM state kept; UEFI vars %s; owner-epoch marker %s",
		self, name, lo.RowHost, lo.RowOwnerEpoch, lo.MarkerEpoch, vars, marker)
	slog.Warn(by+": undefined a deleted VM's superseded shut-off domain",
		"vm", name, "host", self, "row_host", lo.RowHost, "row_owner_epoch", lo.RowOwnerEpoch,
		"marker_epoch", lo.MarkerEpoch, "reason", lo.Reason, "owner_epoch_marker", marker, "uefi_vars", vars)
	if err := corrosion.InsertVMEvent(ctx, db, corrosion.VMEventRecord{
		VMName: name, HostName: self, Type: "vm.leftover.undefined", Result: "ok", Severity: "info",
		Detail: detail, Username: by,
	}); err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn(by+": record the undefine's event", "vm", name, "error", err)
	}
	return true, ""
}

// setAsideSupersededVars renames each of paths that is a regular file to
// <path>.superseded-<at>, and says what became of them, for the event.
// keep, called right before each rename, names why the file must stay, or
// returns "".
func setAsideSupersededVars(paths []string, at time.Time, keep func() string) string {
	var done []string
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			done = append(done, fmt.Sprintf("%s left in place (not a readable regular file: %v)", p, err))
			continue
		}
		if why := keep(); why != "" {
			done = append(done, fmt.Sprintf("%s left in place (%s)", p, why))
			continue
		}
		to := supersededName(p, at)
		if err := os.Rename(p, to); err != nil {
			slog.Warn("could not set aside a deleted VM's superseded UEFI vars; left in place", "path", p, "error", err)
			done = append(done, fmt.Sprintf("%s left in place (%v)", p, err))
			continue
		}
		done = append(done, p+" set aside as "+to)
	}
	if len(done) == 0 {
		return "none"
	}
	return strings.Join(done, ", ")
}

// LibvirtNvramDir is libvirt's own UEFI vars directory, where a plain UEFI
// domain's vars live (a Secure Boot or vTPM one's are under
// <data_dir>/nvram). A variable so a test can point it elsewhere.
var LibvirtNvramDir = "/var/lib/libvirt/qemu/nvram"

// SupersededVars is a UEFI vars file a superseded leftover's undefine set
// aside (<dir>/<vm>_VARS.fd.superseded-<time>). Nothing on the host removes
// it.
type SupersededVars struct {
	Path       string    // the file
	VarsPath   string    // the path it was moved from
	VM         string    // the VM it was, by its file name
	SetAsideAt time.Time // when
	SizeBytes  int64
}

// ListSupersededVars lists the set-aside UEFI vars in <data_dir>/nvram and
// LibvirtNvramDir, oldest first. A directory that does not exist has none.
func ListSupersededVars(dataDir string) ([]SupersededVars, error) {
	var out []SupersededVars
	for _, dir := range []string{filepath.Join(dataDir, "nvram"), LibvirtNvramDir} {
		matches, err := filepath.Glob(filepath.Join(dir, "*_VARS.fd"+supersededInfix+"*"))
		if err != nil {
			return nil, err
		}
		for _, p := range matches {
			varsPath, at, ok := parseSupersededName(p)
			if !ok {
				continue
			}
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			out = append(out, SupersededVars{Path: p, VarsPath: varsPath, SetAsideAt: at, SizeBytes: fi.Size(),
				VM: strings.TrimSuffix(filepath.Base(varsPath), "_VARS.fd")})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].SetAsideAt.Equal(out[j].SetAsideAt) {
			return out[i].SetAsideAt.Before(out[j].SetAsideAt)
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}
