package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// M10: the listing totals what the retained copies hold, so an operator sees
// the space they take: nothing removes them while their VM exists.
//
// Mutation: drop the retained total — the line is missing and the test is red.
func TestPrintSupersededDisks_TotalsTheRetainedCopies(t *testing.T) {
	var out bytes.Buffer
	printSupersededDisks(&out, &pb.SupersededDisksResponse{Host: "node-a", RetentionDays: 7, Disks: []*pb.SupersededDisk{
		{Path: "/d/a.superseded-x", VmName: "a", SizeBytes: 1000, Retained: "VM a exists"},
		{Path: "/d/b.superseded-y", VmName: "b", SizeBytes: 500, Retained: "VM b exists"},
		{Path: "/d/c.superseded-z", SizeBytes: 7},
	}}, false, time.Now())
	if !strings.Contains(out.String(), "Retained: 2 copies, 1500 bytes") {
		t.Fatalf("listing has no retained total:\n%s", out.String())
	}
}

// A .kept- file is listed as kept, not as held or by the retention.
//
// Mutation: drop the kept case — it reads "held: ...".
func TestPrintSupersededDisks_MarksAKeptDisk(t *testing.T) {
	var out bytes.Buffer
	printSupersededDisks(&out, &pb.SupersededDisksResponse{Host: "node-a", RetentionDays: 7, Disks: []*pb.SupersededDisk{
		{Path: "/d/rv-root.qcow2.kept-x", DiskPath: "/d/rv-root.qcow2", SizeBytes: 9, Held: "kept", Kept: true},
	}}, false, time.Now())
	if !strings.Contains(out.String(), "kept: a disk a deleted VM was kept with") || strings.Contains(out.String(), "held:") {
		t.Fatalf("the kept disk is not marked kept:\n%s", out.String())
	}
}

// A kept seed is listed as a kept seed, which can hold user-data (review m4),
// told by its seed field, not by the server's reason text (re-review N3).
//
// Mutation: drop the seed case, or select it by the held text again — it
// reads as a kept disk.
func TestPrintSupersededDisks_MarksAKeptSeed(t *testing.T) {
	var out bytes.Buffer
	printSupersededDisks(&out, &pb.SupersededDisksResponse{Host: "node-a", Disks: []*pb.SupersededDisk{
		{Path: "/c/rv.iso.kept-x", DiskPath: "/c/rv.iso", SizeBytes: 9, Kept: true, Seed: true, Held: "kept"},
	}}, false, time.Now())
	if !strings.Contains(out.String(), "kept: a cloud-init seed a deleted VM was kept with, which can hold user-data") {
		t.Fatalf("the kept seed is not marked a kept seed:\n%s", out.String())
	}
}

// A kept file is listed under the VM of its name, and one that is an earlier
// VM's of that name says it is not the VM that exists now (lab 2, abort
// proof, surprise 3).
//
// Mutation: drop the earlier-VM note — red.
func TestPrintSupersededDisks_SaysAKeptFileIsAnEarlierVMs(t *testing.T) {
	var out bytes.Buffer
	printSupersededDisks(&out, &pb.SupersededDisksResponse{Host: "node-a", Disks: []*pb.SupersededDisk{
		{Path: "/d/web-root.qcow2.kept-x", DiskPath: "/d/web-root.qcow2", SizeBytes: 9, Kept: true, VmName: "web", VmState: "running", EarlierVm: true},
	}}, false, time.Now())
	s := out.String()
	if !strings.Contains(s, " web ") || !strings.Contains(s, "it is an earlier VM web's, not the VM web that exists now") {
		t.Fatalf("the kept disk is not listed under web as an earlier web's:\n%s", s)
	}
}

// A copy of a deleted VM is listed under that VM as "<vm> (deleted)", and
// is not counted as retained; a kept file of a deleted VM keeps the bare
// name (round-12 review M3).
//
// Mutation: drop the "(deleted)" suffix — red.
func TestPrintSupersededDisks_NamesADeletedVM(t *testing.T) {
	var out bytes.Buffer
	printSupersededDisks(&out, &pb.SupersededDisksResponse{Host: "node-a", RetentionDays: 7, Disks: []*pb.SupersededDisk{
		{Path: "/p/gone-root.qcow2.superseded-x", DiskPath: "/p/gone-root.qcow2", SizeBytes: 9, VmName: "gone", VmState: "deleted"},
		{Path: "/d/old-root.qcow2.kept-x", DiskPath: "/d/old-root.qcow2", SizeBytes: 9, VmName: "old", VmState: "deleted", Kept: true, Held: "kept"},
	}}, false, time.Now())
	s := out.String()
	if !strings.Contains(s, "gone (deleted)") {
		t.Fatalf("the deleted VM's copy is not listed as \"gone (deleted)\":\n%s", s)
	}
	if strings.Contains(s, "old (deleted)") {
		t.Fatalf("a kept file is listed with the deleted suffix:\n%s", s)
	}
	if strings.Contains(s, "Retained:") {
		t.Fatalf("a deleted VM's copy is counted as retained:\n%s", s)
	}
}

type supersededRestoreClient struct {
	pb.LiteVirtClient
	resp *pb.SupersededDisksResponse
}

func (c *supersededRestoreClient) SupersededDisks(context.Context, *pb.SupersededDisksRequest, ...grpc.CallOption) (*pb.SupersededDisksResponse, error) {
	return c.resp, nil
}

// lab2-D2-proof F12: a --restore of a firmware quarantine says what it set
// aside, not "the disk it replaced".
//
// Mutation: the old "The disk it replaced" text — red.
func TestSupersededDisksRestore_SaysWhatItReplaced(t *testing.T) {
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, &supersededRestoreClient{resp: &pb.SupersededDisksResponse{Host: "node-1",
			Restored: "/var/lib/litevirt/fwmig-quarantine/fw1-reconciled-1", RestoredTo: "fw1",
			SetAside: "/var/lib/litevirt/fwmig-quarantine/fw1-reconciled-2"}})
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newHostSupersededDisksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"node-1", "--restore", "/var/lib/litevirt/fwmig-quarantine/fw1-reconciled-1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("superseded-disks --restore: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "What it replaced is kept as /var/lib/litevirt/fwmig-quarantine/fw1-reconciled-2.") || strings.Contains(got, "disk it replaced") {
		t.Errorf("output:\n%s", got)
	}
}
