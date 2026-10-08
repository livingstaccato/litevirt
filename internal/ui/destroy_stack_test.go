package ui

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DeleteStack reports what it could not remove as "error" statuses and still
// ends the stream OK. The destroy handler drained the stream without looking
// and always said the stack was destroyed, although it was left "deleting".

func destroyStack(t *testing.T, mock *mockGRPC) *http.Response {
	t.Helper()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/stacks/hb")))
	return w.Result()
}

func TestHandler_DestroyStack_FailedDeletionIsNotReportedDestroyed(t *testing.T) {
	mock := newDefaultMock()
	mock.deleteStackFrames = []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
		{VmName: "ha2", Status: "deleting"},
		{VmName: "ha2", Status: "error", Error: "an operation is in progress"},
		{VmName: "network hb_back", Status: "error", Error: "deprovision network: boom"},
	}
	resp := destroyStack(t, mock)
	trig := resp.Header.Get("HX-Trigger")
	if strings.Contains(trig, "Stack 'hb' destroyed") || strings.Contains(trig, `"success"`) {
		t.Errorf("a failed teardown was toasted as a success: %s", trig)
	}
	for _, want := range []string{`"error"`, "2 of 3", "ha2", "network hb_back", "deleting"} {
		if !strings.Contains(trig, want) {
			t.Errorf("toast %s does not mention %q", trig, want)
		}
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = %d for an incomplete teardown", resp.StatusCode)
	}
}

func TestHandler_DestroyStack_StreamFailureIsNotReportedDestroyed(t *testing.T) {
	mock := newDefaultMock()
	mock.deleteStackFrames = []*pb.DeleteProgress{{VmName: "ha1", Status: "deleting"}}
	mock.deleteStackStreamErr = status.Error(codes.Unavailable, "connection reset")
	resp := destroyStack(t, mock)
	trig := resp.Header.Get("HX-Trigger")
	if strings.Contains(trig, "Stack 'hb' destroyed") || !strings.Contains(trig, `"error"`) {
		t.Errorf("a teardown whose stream broke was not reported as failed: %s", trig)
	}
	if !strings.Contains(trig, "connection reset") {
		t.Errorf("toast %s does not carry the stream error", trig)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = %d for a broken teardown stream", resp.StatusCode)
	}
}

func TestHandler_DestroyStack_CleanTeardownStillSaysDestroyed(t *testing.T) {
	mock := newDefaultMock()
	mock.deleteStackFrames = []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
	}
	resp := destroyStack(t, mock)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if trig := resp.Header.Get("HX-Trigger"); !strings.Contains(trig, "Stack 'hb' destroyed") {
		t.Errorf("success toast missing: %s", trig)
	}
	if got := resp.Header.Get("HX-Redirect"); got != "/stacks" {
		t.Errorf("HX-Redirect = %q, want /stacks", got)
	}
}

// A VM the stack did not create is kept (status "kept", the reason in
// Error). The destroy says which VMs were kept and why, on a complete
// teardown and an incomplete one alike, and a kept VM is not a failure.
func TestHandler_DestroyStack_NamesEachKeptVMAndWhy(t *testing.T) {
	kept := []*pb.DeleteProgress{
		{VmName: "rc5-isosym", Status: "kept", Error: `not created by stack "hb" (it belongs to no stack); left alone`},
		{VmName: "other", Status: "kept", Error: `not created by stack "hb" (it belongs to stack "web"); left alone`},
	}
	t.Run("complete", func(t *testing.T) {
		mock := newDefaultMock()
		mock.deleteStackFrames = append([]*pb.DeleteProgress{
			{VmName: "ha1", Status: "deleting"}, {VmName: "ha1", Status: "deleted"},
		}, kept...)
		resp := destroyStack(t, mock)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200: a kept VM is not a failure", resp.StatusCode)
		}
		trig := resp.Header.Get("HX-Trigger")
		for _, want := range []string{"Stack 'hb' destroyed", "rc5-isosym", "belongs to no stack", "other", `belongs to stack \"web\"`} {
			if !strings.Contains(trig, want) {
				t.Errorf("toast %s does not mention %q", trig, want)
			}
		}
	})
	t.Run("incomplete", func(t *testing.T) {
		mock := newDefaultMock()
		mock.deleteStackFrames = append([]*pb.DeleteProgress{
			{VmName: "ha2", Status: "error", Error: "boom"},
		}, kept...)
		resp := destroyStack(t, mock)
		trig := resp.Header.Get("HX-Trigger")
		for _, want := range []string{"1 of 1", "ha2", "rc5-isosym", "belongs to no stack"} {
			if !strings.Contains(trig, want) {
				t.Errorf("toast %s does not mention %q", trig, want)
			}
		}
	})
}
