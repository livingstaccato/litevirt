package libvirt

import "testing"

// newDiskSources is what a snapshot made: the top files that are new after it.
// A disk the snapshot did not touch is never in it, so its file is never
// narrowed (no backfill).
func TestNewDiskSources_OnlyTheFilesTheSnapshotMade(t *testing.T) {
	before := pitDomXML(map[string]string{"vda": "/p/a.qcow2", "vdb": "/p/b.qcow2"}, nil)
	after := pitDomXML(map[string]string{"vda": "/p/a.s1", "vdb": "/p/b.qcow2"}, nil)
	got := newDiskSources(before, after)
	if len(got) != 1 || got[0] != "/p/a.s1" {
		t.Errorf("newDiskSources = %v, want [/p/a.s1]", got)
	}
	// Without a readable before, nothing counts as new: every disk the
	// domain has would otherwise be narrowed, old ones included.
	//
	// Mutation: drop the empty-before guard — this goes red.
	if got := newDiskSources("", after); len(got) != 0 {
		t.Errorf("newDiskSources with no before = %v, want none", got)
	}
}
