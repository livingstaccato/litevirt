package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The target's XML identity check of EnsureFirmwareState compares the domain's
// uuid with the one the source sent. A stored spec uuid that differs from the
// domain's only in case (libvirt reports lower case; a stored value is never
// overwritten) is the same uuid, so a plain VM's cold move goes ahead; a
// different value is still refused, before anything is defined.
//
// Mutation: compare with != instead of strings.EqualFold — the case row goes
// red; always accept — the mismatch row goes red.
func TestEnsureFirmwareState_PlainVMXMLUuidCaseInsensitive(t *testing.T) {
	const plainSpec = `{"name":"fw","uuid":"` + fwRollbackUUID + `"}`
	for _, tc := range []struct {
		name    string
		xmlUUID string
		wantOK  bool
	}{
		{"same uuid, other case", strings.ToUpper(fwRollbackUUID), true},
		{"different uuid", "dddddddd-4444-4444-8444-dddddddddddd", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFWRollbackFixture(t)
			if err := f.dst.db.Execute(context.Background(),
				`UPDATE vms SET spec = ? WHERE name = ?`, plainSpec, fwRollbackVM); err != nil {
				t.Fatal(err)
			}
			_, err := f.dst.EnsureFirmwareState(f.peer.srcCtx, &pb.EnsureFirmwareStateRequest{
				VmName: fwRollbackVM, Uuid: fwRollbackUUID, AttemptId: "a1",
				DomainXml: `<domain type='kvm'><name>fw</name><uuid>` + tc.xmlUUID + `</uuid></domain>`,
			})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("EnsureFirmwareState = %v, want the define to go ahead", err)
				}
				if !f.dstVirt.DomainExists(fwRollbackVM) {
					t.Fatal("the domain was not defined")
				}
				return
			}
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "does not match request") {
				t.Fatalf("EnsureFirmwareState = %v, want InvalidArgument identity mismatch", err)
			}
			if f.dstVirt.DomainExists(fwRollbackVM) {
				t.Fatal("a domain with another uuid was defined")
			}
		})
	}
}
