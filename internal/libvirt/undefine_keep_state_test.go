package libvirt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// snapRefusingAPI is fwFakeAPI with libvirt's undefine refusal for a domain
// holding snapshot metadata (qemuDomainUndefineFlags): a shut-off domain
// with snapshots is refused unless SNAPSHOTS_METADATA is passed.
type snapRefusingAPI struct {
	*fwFakeAPI
	snapshots int
}

func (f *snapRefusingAPI) DomainUndefineFlags(dom golibvirt.Domain, flags golibvirt.DomainUndefineFlagsValues) error {
	if d, ok := f.doms[dom.Name]; ok && d.state == golibvirt.DomainShutoff && f.snapshots > 0 &&
		flags&golibvirt.DomainUndefineSnapshotsMetadata == 0 {
		f.undefFlags = append(f.undefFlags, flags)
		return golibvirt.Error{Code: uint32(golibvirt.ErrOperationInvalid),
			Message: fmt.Sprintf("Requested operation is not valid: cannot delete inactive domain with %d snapshots", f.snapshots)}
	}
	return f.fwFakeAPI.DomainUndefineFlags(dom, flags)
}

// The keep-state undefine never drops snapshot metadata. Its redefine-class
// callers (snapshot revert, UpdateVM, cutover rename, the reconciler's
// redefines) define the domain again, which keeps its snapshots; for `lv rm
// --keep-disks` libvirt's refusal is the backstop behind the refusal of a VM
// with snapshot records (keepDisksSnapshotRefusal). On a shut-off domain
// with a snapshot libvirt therefore refuses it.
//
// Mutation: add SNAPSHOTS_METADATA to keepStateUndefineFlags: red.
func TestUndefineDomainPreservingState_KeepsSnapshotMetadata(t *testing.T) {
	api := &snapRefusingAPI{fwFakeAPI: newFWFakeAPI(golibvirt.DomainShutoff), snapshots: 1}
	g := NewFirmwareMoveGuard(fwLookup(fwState{name: "none"}))
	err := undefineDomainPreservingState(api, g, fwTestVM)
	var le golibvirt.Error
	if !errors.As(err, &le) || !strings.Contains(err.Error(), "with 1 snapshots") {
		t.Fatalf("keep-state undefine of a domain with a snapshot = %v; want libvirt's refusal", err)
	}
	if _, ok := api.doms[fwTestVM]; !ok {
		t.Fatal("the domain was undefined")
	}
	for _, f := range api.undefFlags {
		if f&(golibvirt.DomainUndefineSnapshotsMetadata|golibvirt.DomainUndefineCheckpointsMetadata) != 0 {
			t.Errorf("redefine-class undefine passed %#x, which drops snapshot/checkpoint metadata", f)
		}
	}
}
