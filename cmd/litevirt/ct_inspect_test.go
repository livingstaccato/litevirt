package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

type ctInspectMock struct {
	pb.LiteVirtClient
	got *pb.InspectContainerRequest
}

func (m *ctInspectMock) InspectContainer(_ context.Context, in *pb.InspectContainerRequest, _ ...grpc.CallOption) (*pb.ContainerDetail, error) {
	m.got = in
	return &pb.ContainerDetail{
		Container: &pb.Container{
			HostName: "node-4", Name: "blct", State: "stopped", Image: "alpine:3.19",
			CpuLimit: 2, MemoryMib: 512, Project: "acme",
			CreatedAt: "2026-10-08T12:43:00Z", UpdatedAt: "2026-10-08T12:50:00Z",
		},
		Privilege: "privileged", Distro: "alpine", Release: "3.19", Template: "download",
		Interfaces: []*pb.ContainerInterfaceDetail{{Name: "eth0", NetworkName: "lxtnet", Ip: "172.16.77.50/24", Mac: "aa:bb:cc:00:00:01", Veth: "lvc0"}},
		RootfsPath: "/var/lib/lxc/blct/rootfs", RootfsBytes: 3 << 20,
		Snapshots: []*pb.ContainerSnapshot{{Name: "s1", SizeBytes: 4096, CreatedAt: "2026-10-08T12:45:00Z"}},
		Backups: []*pb.ContainerBackupRef{
			{Repo: "/srv/lxtrepo", TotalBytes: 1 << 20, Available: true},
			{Repo: "/srv/lxtbk", TotalBytes: 1 << 20, UnavailableReason: "repo /srv/lxtbk does not exist on node-4"},
		},
		HostDetail: true,
	}, nil
}

func runCTInspect(t *testing.T, mock pb.LiteVirtClient, args ...string) (string, error) {
	t.Helper()
	orig := cli.Connect
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) { return mock, func() {}, nil }
	t.Cleanup(func() { cli.Connect = orig })
	root := newRootCmd()
	root.SetArgs(args)
	origOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := root.Execute()
	w.Close()
	os.Stdout = origOut
	var b bytes.Buffer
	b.ReadFrom(r)
	return b.String(), err
}

// `lv ct inspect` prints the container's fields, NICs, rootfs, snapshots and
// backups, with a backup in a vanished repo marked unavailable.
func TestCTInspect_Text(t *testing.T) {
	mock := &ctInspectMock{}
	out, err := runCTInspect(t, mock, "ct", "inspect", "blct", "--host", "node-4")
	if err != nil {
		t.Fatalf("ct inspect: %v", err)
	}
	if mock.got == nil || mock.got.GetName() != "blct" || mock.got.GetHostName() != "node-4" {
		t.Fatalf("request = %+v, want blct on node-4", mock.got)
	}
	for _, want := range []string{
		"Name:", "blct", "Host:", "node-4", "State:", "stopped", "Image:", "alpine:3.19",
		"Project:", "acme", "CPU limit:", "2", "Memory:", "512 MiB", "Privilege:", "privileged",
		"eth0", "lxtnet", "172.16.77.50/24", "/var/lib/lxc/blct/rootfs", "3.0 MiB",
		"s1", "/srv/lxtrepo", "/srv/lxtbk", "unavailable", "does not exist on node-4",
		"Created:", "2026-10-08T12:43:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// -o json prints the detail as JSON, like `lv inspect`.
func TestCTInspect_JSON(t *testing.T) {
	out, err := runCTInspect(t, &ctInspectMock{}, "ct", "inspect", "blct", "-o", "json")
	if err != nil {
		t.Fatalf("ct inspect -o json: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if v["privilege"] != "privileged" || v["container"].(map[string]any)["name"] != "blct" {
		t.Fatalf("JSON = %v", v)
	}
}

// An unknown output format is an error, not silently text.
func TestCTInspect_BadOutputFormat(t *testing.T) {
	if _, err := runCTInspect(t, &ctInspectMock{}, "ct", "inspect", "blct", "-o", "yaml"); err == nil {
		t.Fatal("-o yaml accepted")
	}
}
