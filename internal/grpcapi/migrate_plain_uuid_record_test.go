package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fwmig"
)

// A plain VM's cold move now sends its uuid, and the target's guard on a live
// firmware move's records (fwmig Lookup(name, uuid)) matches a record of that
// uuid under ANY name: a hold of another VM name that carries the same uuid
// refuses the move, naming the attempt, and defines nothing.
//
// Mutation: pass "" for the uuid to firmwareMoveRecordRefusal in
// EnsureFirmwareState (or drop the by-uuid match in fwmig Lookup) — red.
func TestEnsureFirmwareState_PlainVMRefusedByAnotherNamesRecordOfItsUuid(t *testing.T) {
	f := newFwtFixture(t, fwtSpecSBTPM)
	f.putHold(fwmig.Hold{Binding: f.binding(fwtA1), State: fwmig.HoldVerified}, []byte("t0"), []byte("tpm"))

	const plain = "plain1"
	insertTestVMWithSpec(t, adminCtx(), f.s.db, plain, fwtSrc, "migrating", `{"name":"plain1","uuid":"`+fwtUUID+`"}`)
	_, err := f.s.EnsureFirmwareState(f.peer, &pb.EnsureFirmwareStateRequest{
		VmName: plain, Uuid: fwtUUID, AttemptId: "c1",
		DomainXml: `<domain type='kvm'><name>` + plain + `</name><uuid>` + fwtUUID + `</uuid></domain>`,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwtA1) {
		t.Fatalf("EnsureFirmwareState = %v, want FailedPrecondition naming attempt %s", err, fwtA1)
	}
	if f.fake.DomainExists(plain) {
		t.Fatal("a domain was defined for the refused move")
	}
}
