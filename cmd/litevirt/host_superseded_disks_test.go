package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

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
