package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

const localOnlyNotice = "this node holds no record of stack \"hb\": removing only the workloads it lists here; left for an Admin: ..."

// A down that the daemon could do only on this node's workloads says so,
// with what is left, and does not report the stack torn down.
func TestComposeDown_ALocalOnlyTeardownSaysSo(t *testing.T) {
	spy := &deployClient{teardown: []*pb.DeleteProgress{
		{VmName: "stack", Status: "local-only", Error: localOnlyNotice},
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
	}}
	out, err := runComposeCLI(t, spy, false, "", "down", "-y")
	if err != nil {
		t.Fatalf("lv compose down: %v\n%s", err, out)
	}
	if !strings.Contains(out, localOnlyNotice) {
		t.Errorf("the local-only notice was not printed:\n%s", out)
	}
	if strings.Contains(out, "torn down") {
		t.Errorf("a local-only teardown was reported torn down:\n%s", out)
	}
	if !strings.Contains(out, "this node's workloads only") {
		t.Errorf("no final line saying only this node's workloads were removed:\n%s", out)
	}
}

// A workload that a local-only down could not delete is not retried by
// anything: the error must not promise that it is.
func TestComposeDown_ALocalOnlyFailurePromisesNoRetry(t *testing.T) {
	spy := &deployClient{teardown: []*pb.DeleteProgress{
		{VmName: "stack", Status: "local-only", Error: localOnlyNotice},
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "error", Error: "undefine refused"},
	}}
	out, err := runComposeCLI(t, spy, false, "", "down", "-y")
	if err == nil {
		t.Fatalf("a failed local-only down succeeded:\n%s", out)
	}
	if strings.Contains(err.Error(), "retries") || strings.Contains(err.Error(), `"deleting"`) {
		t.Errorf("the error promises a retry: %v", err)
	}
	for _, want := range []string{"local-only", "1 of 1", "nothing will retry"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
}
