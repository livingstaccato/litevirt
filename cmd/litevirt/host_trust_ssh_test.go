package main

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv host config <host> --trust-ssh-poweroff` sets the host's
// litevirt.trust_ssh_poweroff label through SetHostLabels (admin-only and
// audited on the server), and =false removes it. Alone it asks ConfigureHost
// nothing; beside another flag both run.
//
// Mutations: set the label without the flag being given — the plain
// --region call sets it, red; skip SetHostLabels — no label request, red.
func TestHostConfig_TrustSSHPoweroff(t *testing.T) {
	mock := &mockClient{}
	out, _, err := runCmd(t, mock, "host", "config", "host-a", "--trust-ssh-poweroff")
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.setHostLabels) != 1 || mock.setHostLabels[0].GetName() != "host-a" ||
		mock.setHostLabels[0].GetLabels()[corrosion.LabelTrustSSHPoweroff] != "true" || len(mock.configuredHosts) != 0 {
		t.Fatalf("label requests %+v, configure %d; want one setting %s=true and no ConfigureHost",
			mock.setHostLabels, len(mock.configuredHosts), corrosion.LabelTrustSSHPoweroff)
	}
	if !strings.Contains(out, "they run twice") {
		t.Fatalf("turning it on does not state the risk: %q", out)
	}

	mock = &mockClient{}
	if _, _, err := runCmd(t, mock, "host", "config", "host-a", "--trust-ssh-poweroff=false", "--region", "r1"); err != nil {
		t.Fatal(err)
	}
	if len(mock.setHostLabels) != 1 || len(mock.setHostLabels[0].GetRemove()) != 1 ||
		mock.setHostLabels[0].GetRemove()[0] != corrosion.LabelTrustSSHPoweroff || len(mock.configuredHosts) != 1 {
		t.Fatalf("label requests %+v, configure %d; want the label removed and ConfigureHost run", mock.setHostLabels, len(mock.configuredHosts))
	}

	mock = &mockClient{}
	if _, _, err := runCmd(t, mock, "host", "config", "host-a", "--region", "r1"); err != nil {
		t.Fatal(err)
	}
	if len(mock.setHostLabels) != 0 {
		t.Fatalf("a config without --trust-ssh-poweroff changed the label: %+v", mock.setHostLabels)
	}
}
