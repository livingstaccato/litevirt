package main

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The flags ask for one action at a time, and each modifier only with an
// action that takes it.
//
// Mutation: allow two actions; take --accept-nvram-hash without
// --confirm-target-nvram — red.
func TestFirmwareMoveFlags_Request(t *testing.T) {
	ok := []struct {
		name string
		f    firmwareMoveFlags
		want pb.FirmwareMoveDoctorAction
	}{
		{"show", firmwareMoveFlags{}, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED},
		{"accept_source_ack_stop", firmwareMoveFlags{acceptSource: true, ack: true, stopTarget: true},
			pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE},
		{"confirm", firmwareMoveFlags{confirmNvram: true, nvramHash: strings.Repeat("a", 64)},
			pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM},
		{"push_ack", firmwareMoveFlags{pushNvram: true, ack: true}, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM},
		{"discard_stop", firmwareMoveFlags{discard: true, stopTarget: true}, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET},
		{"resolve", firmwareMoveFlags{resolve: "quarantine"}, pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_RESOLVE_CONDITION},
	}
	for _, c := range ok {
		req, err := c.f.request("os1")
		if err != nil || req.GetAction() != c.want || req.GetVmName() != "os1" {
			t.Errorf("%s: %v %v, want %v", c.name, req, err, c.want)
		}
	}
	bad := map[string]firmwareMoveFlags{
		"two_actions":         {acceptTarget: true, acceptSource: true},
		"hash_without_action": {nvramHash: strings.Repeat("a", 64)},
		"confirm_no_hash":     {confirmNvram: true},
		"ack_with_adopt":      {adopt: true, ack: true},
		"stop_with_adopt":     {adopt: true, stopTarget: true},
	}
	for name, f := range bad {
		if _, err := f.request("os1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The report shows both records, every hash and path, and the hosts that did
// not answer.
func TestRenderFirmwareMoveReport(t *testing.T) {
	var b bytes.Buffer
	renderFirmwareMoveReport(&b, "os1", &pb.FirmwareMoveDoctorResponse{
		Outcome: "done",
		Hosts: []*pb.FirmwareMoveHostRecords{
			{Host: "node-1", MarkerJson: `{"phase":"target_ran","parked_from":"cutover","target":"node-2","src_permall_sha256":"aaa"}`,
				Hashes: map[string]string{"permall_now": "aaa", "nvram_now": "bbb"}, Paths: map[string]string{"nvram": "/n"}},
			{Host: "node-2", HoldJson: `{"state":"verified","source":"node-1","nvram_t0_sha256":"ccc"}`,
				Domain: &pb.TargetDomain{Present: true, State: "running"}, Quarantines: []string{"/q/os1-x"}},
			{Host: "node-3"},
			{Host: "node-5", LeftoverJson: `{"source":"node-1","attempt":"a1","uuid":"u1"}`},
		},
		Unreachable: []string{"node-4 (active): connection refused"},
	})
	out := b.String()
	for _, want := range []string{"done", "host node-1:", "phase=target_ran", "parked_from=cutover", "src_permall_sha256=aaa",
		"permall_now:", "nvram_now:", "host node-2:", "state=verified", "nvram_t0_sha256=ccc", "domain:       running",
		"quarantine:   /q/os1-x", "NOT READ: node-4", "host node-5:", "leftover:     source=node-1 attempt=a1"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "host node-3:") {
		t.Errorf("a host with nothing of the VM is shown:\n%s", out)
	}
}
