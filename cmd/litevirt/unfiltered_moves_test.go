package main

import (
	"reflect"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv network set --allow-unfiltered-access-vlan-moves` against a node on an
// older build: that server ignores the field and answers without it, which
// the CLI must not report as done. A matching reply, and a set that did not
// touch the opt-in, pass.
//
// Mutation: unfilteredMovesTookEffect always nil — red.
func TestUnfilteredMovesTookEffect(t *testing.T) {
	on := &pb.SetNetworkGuardConfigRequest{Name: "lan", SetAllowUnfilteredAccessVlanMoves: true, AllowUnfilteredAccessVlanMoves: true}
	if err := unfilteredMovesTookEffect(on, &pb.NetworkInfo{Name: "lan"}); err == nil || !strings.Contains(err.Error(), "did not apply") {
		t.Fatalf("an older server's reply to turning it on: %v, want an error", err)
	}
	if err := unfilteredMovesTookEffect(on, &pb.NetworkInfo{Name: "lan", AllowUnfilteredAccessVlanMoves: true}); err != nil {
		t.Fatalf("applied: %v", err)
	}
	off := &pb.SetNetworkGuardConfigRequest{Name: "lan", SetAllowUnfilteredAccessVlanMoves: true}
	if err := unfilteredMovesTookEffect(off, &pb.NetworkInfo{Name: "lan"}); err != nil {
		t.Fatalf("turned off: %v", err)
	}
	if err := unfilteredMovesTookEffect(&pb.SetNetworkGuardConfigRequest{Name: "lan", SetGateway: true}, &pb.NetworkInfo{Name: "lan"}); err != nil {
		t.Fatalf("a set without the opt-in: %v", err)
	}
}

// `lv doctor access-vlan-moves` lists exactly the networks with the opt-in on.
//
// Mutation: list every network — red.
func TestUnfilteredMoveNetworks(t *testing.T) {
	got := unfilteredMoveNetworks([]*pb.NetworkInfo{{Name: "b", AllowUnfilteredAccessVlanMoves: true}, {Name: "plain"},
		{Name: "a", AllowUnfilteredAccessVlanMoves: true}})
	if want := []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
