package main

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// lv ct inspect names a container's privilege mode and confinement; an
// earlier build's container reads privileged, legacy.
func TestWriteContainerInspect(t *testing.T) {
	var b bytes.Buffer
	writeContainerInspect(&b, &pb.Container{Name: "web", HostName: "n1", State: "running", Project: "acme",
		Privileged: false, Confinement: "default", IdmapBase: 1000065536})
	for _, want := range []string{"Name:", "web", "Privileged:", "no (ids 1000065536-1000131071)", "Confinement:", "default"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("inspect output missing %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	writeContainerInspect(&b, &pb.Container{Name: "old", Privileged: true, Confinement: "legacy"})
	if !strings.Contains(b.String(), "yes (root in the container is root on the host") || !strings.Contains(b.String(), "lv ct convert --unprivileged old") {
		t.Errorf("privileged container not flagged:\n%s", b.String())
	}
}

// lv doctor privileged-containers lists the privileged and legacy-confined
// containers, templates included.
func TestPrivilegedContainers(t *testing.T) {
	got := privilegedContainers([]*pb.Container{
		{Name: "new", Confinement: "default", IdmapBase: 1},
		{Name: "old", Privileged: true, Confinement: "legacy", HostName: "n1"},
		{Name: "loose", Confinement: "legacy", IdmapBase: 2},
		{Name: "admin-priv", Privileged: true, Confinement: "default"},
	})
	if len(got) != 3 || got[0].Name != "old" || got[1].Name != "loose" || got[2].Name != "admin-priv" {
		t.Fatalf("privilegedContainers = %+v", got)
	}
}
