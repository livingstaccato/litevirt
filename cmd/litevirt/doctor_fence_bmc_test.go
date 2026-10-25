package main

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv doctor fence` names every host whose stored BMC address carries a
// bracket (ha.fence.bmc_address_unsafe), with the fix, and the command
// prints it, not just the printer.
//
// Mutations: drop printUnsafeBMC from the command — the command test is red;
// print resolved rows too — node-2 is named, red.
func TestDoctorFence_NamesUnsafeBMCAddresses(t *testing.T) {
	conds := []*pb.HealthCondition{
		{Code: "ha.fence.bmc_address_unsafe", SubjectKind: "host", SubjectId: "node-3", Lifecycle: "confirmed",
			Evidence: `{"field":"ipmi_address","value":"10.0.0.9 (trust=on","remedy":"set an address without '[' or ']': ` +
				"`lv host config node-3 --ipmi-address <addr>`" + `"}`},
		{Code: "ha.fence.bmc_address_unsafe", SubjectKind: "host", SubjectId: "node-2", Lifecycle: "resolved",
			Evidence: `{"field":"ipmi_address"}`},
	}
	var out bytes.Buffer
	printUnsafeBMC(&out, conds)
	got := out.String()
	for _, want := range []string{"node-3", "ipmi_address", "lv host config node-3 --ipmi-address"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "node-2") {
		t.Errorf("output names node-2, whose condition is resolved:\n%s", got)
	}
	cmdOut, _ := runDoctorFenceWithHealth(t, &pb.FenceReadiness{}, &pb.ClusterHealth{Conditions: conds})
	if !strings.Contains(cmdOut, "node-3") || !strings.Contains(cmdOut, "BMC address") {
		t.Fatalf("lv doctor fence did not report the unsafe BMC address:\n%s", cmdOut)
	}
}
