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

// The undefine of `lv rm --keep-disks` takes libvirt's snapshot and
// checkpoint metadata with the domain, and keeps NVRAM and swtpm state: it
// passes KEEP_NVRAM|KEEP_TPM, never NVRAM, TPM or MANAGED_SAVE.
//
// Mutation: drop SNAPSHOTS_METADATA from keptDiskDeleteUndefineFlags: red.
func TestUndefineDeletedDomainKeepingState_DropsSnapshotMetadataOnly(t *testing.T) {
	api := &snapRefusingAPI{fwFakeAPI: newFWFakeAPI(golibvirt.DomainShutoff), snapshots: 1}
	g := NewFirmwareMoveGuard(fwLookup(fwState{name: "none"}))
	if err := undefineDeletedDomainKeepingState(api, g, fwTestVM); err != nil {
		t.Fatalf("undefine of a deleted VM's domain with a snapshot: %v", err)
	}
	if _, ok := api.doms[fwTestVM]; ok {
		t.Fatal("the domain is still defined")
	}
	if len(api.undefFlags) != 1 {
		t.Fatalf("undefine calls = %v, want one", api.undefFlags)
	}
	f := api.undefFlags[0]
	for _, want := range []golibvirt.DomainUndefineFlagsValues{
		golibvirt.DomainUndefineKeepNvram, golibvirt.DomainUndefineKeepTpm,
		golibvirt.DomainUndefineSnapshotsMetadata, golibvirt.DomainUndefineCheckpointsMetadata,
	} {
		if f&want == 0 {
			t.Errorf("flags %#x lack %#x", f, want)
		}
	}
	for _, never := range []golibvirt.DomainUndefineFlagsValues{
		golibvirt.DomainUndefineNvram, golibvirt.DomainUndefineTpm, golibvirt.DomainUndefineManagedSave,
	} {
		if f&never != 0 {
			t.Errorf("flags %#x carry %#x, which removes state a kept disk needs", f, never)
		}
	}
}

// The redefine-class keep-state undefine (snapshot revert, UpdateVM, cutover
// rename, the reconciler's redefines) never drops snapshot metadata: a
// domain it is about to define again keeps its snapshots. On a shut-off
// domain with a snapshot libvirt therefore refuses it.
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
