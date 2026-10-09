package lxc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A convert interrupted partway is finished by the next one, to the range the
// interrupted one recorded — whatever range the next one asks for — so every
// file ends in one range and the container starts.
func TestConvert_ResumesToTheRecordedRange(t *testing.T) {
	r, _ := secRunner(t)
	mkLegacyCT(t, r, "c")
	owners := UseOwnershipOverlayForTest(t)
	const b1, b2 = int64(1_000_000_000), int64(1_000_065_536)

	failAfter := 2
	owners.FailAfter(failAfter, errors.New("interrupted"))
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: b1, Size: IDMapSize}, Confinement: ConfinementDefault}); err == nil {
		t.Fatal("the interrupted convert succeeded")
	}
	owners.FailAfter(-1, nil)
	if sec, _ := r.Security("c"); !sec.Converting || sec.ConvertTo == nil || sec.ConvertTo.IDMap == nil || sec.ConvertTo.IDMap.Base != b1 {
		t.Fatalf("after the interruption Security = %+v, want converting to %d", sec, b1)
	}
	// The re-run asks for a different range (a fresh allocation): it must
	// still finish to b1.
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: b2, Size: IDMapSize}}); err != nil {
		t.Fatalf("resumed convert: %v", err)
	}
	rootfs := filepath.Join(r.Lxcpath, "c", "rootfs")
	n := 0
	_ = filepath.WalkDir(rootfs, func(p string, d os.DirEntry, err error) error {
		uid, gid := owners.Of(p)
		if int64(uid) < b1 || int64(uid) >= b1+IDMapSize || int64(gid) < b1 || int64(gid) >= b1+IDMapSize {
			t.Errorf("%s owned %d:%d, outside the one range %d", p, uid, gid, b1)
		}
		n++
		return nil
	})
	if n < 4 {
		t.Fatalf("walked %d entries", n)
	}
	sec, _ := r.Security("c")
	if sec.Converting || sec.IDMap == nil || sec.IDMap.Base != b1 {
		t.Fatalf("after resume Security = %+v", sec)
	}
	if err := r.prepareStart("c"); err != nil {
		t.Fatalf("start after resume: %v", err)
	}
}

// A snapshot revert onto a converted container marks the copy with the
// container's mode before it is swapped into place: a crash before the
// convert leaves a container that refuses to start and names lv ct convert,
// and the convert finishes it.
func TestRevertConverting_MarksBeforeTheSwap(t *testing.T) {
	r, _ := secRunner(t)
	mkLegacyCT(t, r, "c")
	UseOwnershipOverlayForTest(t)
	var snap strings.Builder
	if err := r.ExportContainer(context.Background(), "c", &snap); err != nil {
		t.Fatal(err)
	}
	to := ConvertOpts{IDMap: &IDMap{Base: 1_000_131_072, Size: IDMapSize}, Confinement: ConfinementDefault}
	if err := r.Convert(context.Background(), "c", to); err != nil {
		t.Fatal(err)
	}
	// The revert lays the privileged snapshot down; "crash" before the convert.
	if err := r.RevertContainerConverting(context.Background(), "c", strings.NewReader(snap.String()), to); err != nil {
		t.Fatal(err)
	}
	if err := r.prepareStart("c"); err == nil || !strings.Contains(err.Error(), "lv ct convert") {
		t.Fatalf("start of the unconverted revert: %v", err)
	}
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: 1_999_999_999 - 65535, Size: IDMapSize}}); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Security("c")
	if sec.Converting || sec.IDMap == nil || sec.IDMap.Base != to.IDMap.Base || sec.Confinement != ConfinementDefault {
		t.Fatalf("after the convert Security = %+v", sec)
	}
}

// An N2 resume whose second stage (the range the marker did not record) is
// itself interrupted leaves a marker naming that range; the next run finishes
// there, not in yet another range.
func TestConvert_InterruptedSecondStageResumesToItsRange(t *testing.T) {
	r, _ := secRunner(t)
	mkLegacyCT(t, r, "c")
	owners := UseOwnershipOverlayForTest(t)
	dir := filepath.Join(r.Lxcpath, "c")
	if err := os.WriteFile(filepath.Join(dir, convertMarkerFile), []byte(`{"Confinement":"default"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const b2, b3 = int64(1_000_196_608), int64(1_000_262_144)
	owners.FailAfter(2, errors.New("interrupted"))
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: b2, Size: IDMapSize}}); err == nil {
		t.Fatal("interrupted second stage succeeded")
	}
	owners.FailAfter(-1, nil)
	if sec, _ := r.Security("c"); sec.ConvertTo == nil || sec.ConvertTo.IDMap == nil || sec.ConvertTo.IDMap.Base != b2 {
		t.Fatalf("marker after the interrupted second stage: %+v", sec.ConvertTo)
	}
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: b3, Size: IDMapSize}}); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(filepath.Join(dir, "rootfs"), func(p string, d os.DirEntry, err error) error {
		if uid, _ := owners.Of(p); int64(uid) < b2 || int64(uid) >= b2+IDMapSize {
			t.Errorf("%s owned by %d, outside %d", p, uid, b2)
		}
		return nil
	})
	if sec, _ := r.Security("c"); sec.Converting || sec.IDMap == nil || sec.IDMap.Base != b2 || sec.Confinement != ConfinementDefault {
		t.Fatalf("Security = %+v", sec)
	}
}

// The marker messages name only the exact command that finishes the recorded
// target — lv ct convert <name>, which any caller who may convert can run —
// never a snapshot revert (which would roll the rootfs back) and never a
// flag the caller might not be allowed to use.
func TestConvertCommand_OnlyTheExactResume(t *testing.T) {
	for _, to := range []*ConvertOpts{
		nil,
		{Confinement: ConfinementLegacy},
		{IDMap: &IDMap{Base: 1_000_000_000, Size: IDMapSize}, Confinement: ConfinementDefault},
	} {
		got := ConvertCommand("web", to)
		if got != "lv ct convert web" {
			t.Errorf("ConvertCommand(%+v) = %q, want %q", to, got, "lv ct convert web")
		}
	}
}
