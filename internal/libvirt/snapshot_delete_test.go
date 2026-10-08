package libvirt

import (
	"errors"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

type recordingSnapshotAPI struct {
	lookupErr error
	flags     []golibvirt.DomainSnapshotDeleteFlags
}

func (r *recordingSnapshotAPI) DomainLookupByName(name string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: name}, nil
}

func (r *recordingSnapshotAPI) DomainSnapshotLookupByName(dom golibvirt.Domain, name string, _ uint32) (golibvirt.DomainSnapshot, error) {
	if r.lookupErr != nil {
		return golibvirt.DomainSnapshot{}, r.lookupErr
	}
	return golibvirt.DomainSnapshot{Name: name, Dom: dom}, nil
}

func (r *recordingSnapshotAPI) DomainSnapshotDelete(_ golibvirt.DomainSnapshot, flags golibvirt.DomainSnapshotDeleteFlags) error {
	r.flags = append(r.flags, flags)
	return nil
}

// Deleting a snapshot removes libvirt's record of it and nothing else.
// litevirt's snapshots are external and litevirt manages their files (the
// reverts reset overlays in place and re-register the metadata without
// libvirt's current/parent links). Asked to delete with no flags, libvirt
// >= 9 judges such a snapshot a "leaf non-active" one and UNLINKS the disk
// the snapshot's domain was on — the snapshot's base, which the VM's later
// layers still back on — and for a current one block-commits and unlinks
// the overlay, which a linked clone may back on. Either destroys a VM's
// data (lab-recheck-5, lines 81 and 82).
func TestDeleteSnapshot_IsMetadataOnly(t *testing.T) {
	api := &recordingSnapshotAPI{}
	if err := deleteSnapshotMetadata(api, "vm", "m1"); err != nil {
		t.Fatalf("deleteSnapshotMetadata: %v", err)
	}
	if len(api.flags) != 1 {
		t.Fatalf("DomainSnapshotDelete called %d times, want 1", len(api.flags))
	}
	if api.flags[0] != golibvirt.DomainSnapshotDeleteMetadataOnly {
		t.Fatalf("DomainSnapshotDelete flags = %#x, want metadata-only (%#x): libvirt would delete or merge the snapshot's disk files",
			api.flags[0], golibvirt.DomainSnapshotDeleteMetadataOnly)
	}
}

func TestDeleteSnapshot_MissingSnapshotIsReported(t *testing.T) {
	api := &recordingSnapshotAPI{lookupErr: errors.New("no domain snapshot with matching name")}
	if err := deleteSnapshotMetadata(api, "vm", "gone"); err == nil {
		t.Fatal("a missing snapshot must be reported")
	}
	if len(api.flags) != 0 {
		t.Fatal("nothing may be deleted for a snapshot that was not found")
	}
}
