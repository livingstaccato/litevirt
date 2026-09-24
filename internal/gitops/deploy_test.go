package gitops

import (
	"errors"
	"io"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type scriptedDeploy struct {
	msgs []*pb.DeployProgress
	end  error // returned once msgs run out; nil means io.EOF
	read int
}

func (s *scriptedDeploy) Recv() (*pb.DeployProgress, error) {
	if s.read >= len(s.msgs) {
		if s.end != nil {
			return nil, s.end
		}
		return nil, io.EOF
	}
	s.read++
	return s.msgs[s.read-1], nil
}

func TestDrainDeploy_ReadsToTheEndAndReportsEveryFailure(t *testing.T) {
	s := &scriptedDeploy{msgs: []*pb.DeployProgress{
		{Phase: "applying", VmName: "a"},
		{Phase: "error", VmName: "a", Error: "define refused"},
		{Phase: "applying", VmName: "b"},
		{Phase: "done", VmName: "b"},
		{Phase: "applying", VmName: "c"},
		{Phase: "error", VmName: "c", Error: "no capacity"},
	}}
	err := DrainDeploy(s)
	if s.read != len(s.msgs) {
		t.Errorf("read %d of %d messages — the stream was abandoned", s.read, len(s.msgs))
	}
	if err == nil {
		t.Fatal("DrainDeploy reported success for a deploy with failures")
	}
	for _, want := range []string{"2 failure(s)", "a: define refused", "c: no capacity"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestDrainDeploy_StreamErrorKeepsEarlierFailures(t *testing.T) {
	s := &scriptedDeploy{
		msgs: []*pb.DeployProgress{{Phase: "error", VmName: "a", Error: "define refused"}},
		end:  errors.New("rolling update aborted"),
	}
	err := DrainDeploy(s)
	if err == nil {
		t.Fatal("DrainDeploy reported success for a failed stream")
	}
	for _, want := range []string{"a: define refused", "rolling update aborted"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestDrainDeploy_CleanDeployIsNil(t *testing.T) {
	s := &scriptedDeploy{msgs: []*pb.DeployProgress{
		{Phase: "applying", VmName: "a"}, {Phase: "done", VmName: "a"},
	}}
	if err := DrainDeploy(s); err != nil {
		t.Fatalf("clean deploy: %v", err)
	}
}
