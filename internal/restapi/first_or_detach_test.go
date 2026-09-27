package restapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestFirstOrDetach_ReturnsAPromptFirstMessage: the ordinary path must be
// untouched, or every migration would answer 202 and the caller would lose the
// first progress message it relies on.
func TestFirstOrDetach_ReturnsAPromptFirstMessage(t *testing.T) {
	want := &emptypb.Empty{}
	first, err, timedOut, rest := firstOrDetach(func() (proto.Message, error) {
		return want, nil
	})
	if timedOut {
		t.Fatal("a message that was ready immediately reported a timeout")
	}
	if err != nil || first != proto.Message(want) {
		t.Fatalf("first = %v, err = %v; want the message back", first, err)
	}
	if rest == nil {
		t.Fatal("the continuation must be usable for the detached reader")
	}
}

// TestFirstOrDetach_DoesNotDropTheFirstMessageOnTimeout is the property the
// obvious implementation gets wrong.
//
// When the ack times out the in-flight Recv is still running, and it owns the
// first message. Abandoning it would drop that message from the detached
// stream, so the operation's log would start at the second one. The
// continuation must deliver it before reading anything further.
func TestFirstOrDetach_DoesNotDropTheFirstMessageOnTimeout(t *testing.T) {
	prev := ackTimeoutForTest
	ackTimeoutForTest = 50 * time.Millisecond
	t.Cleanup(func() { ackTimeoutForTest = prev })

	slow := &emptypb.Empty{}
	second := errors.New("stream done")
	calls := 0
	_, _, timedOut, rest := firstOrDetach(func() (proto.Message, error) {
		calls++
		if calls == 1 {
			time.Sleep(200 * time.Millisecond)
			return slow, nil
		}
		return nil, second
	})
	if !timedOut {
		t.Fatal("a first message that took four times the ack budget did not time out")
	}

	got, err := rest()
	if err != nil || got != proto.Message(slow) {
		t.Fatalf("the detached reader got (%v, %v); the first message must not be dropped", got, err)
	}
	if _, err := rest(); !errors.Is(err, second) {
		t.Fatalf("the second read returned %v, want the stream's own next result", err)
	}
}

// TestAckFirstAndDetach_AcceptsASlowFirstFrame: the volume, backup and
// cross-region handlers acknowledge through ackFirstAndDetach, so it has to
// carry the same ack budget the migrate handler does. A first frame queued
// behind a per-resource lock must be answered 202 inside the budget, not hold
// the handler past the server's WriteTimeout — and the operation must still
// be read to completion behind the answer.
func TestAckFirstAndDetach_AcceptsASlowFirstFrame(t *testing.T) {
	prev := ackTimeoutForTest
	ackTimeoutForTest = 50 * time.Millisecond
	t.Cleanup(func() { ackTimeoutForTest = prev })

	drained := make(chan struct{})
	calls := 0
	recv := func() (proto.Message, error) {
		calls++
		if calls == 1 {
			time.Sleep(200 * time.Millisecond)
			return &emptypb.Empty{}, nil
		}
		close(drained)
		return nil, io.EOF
	}
	canceled := make(chan struct{})
	w := httptest.NewRecorder()
	start := time.Now()
	ackFirstAndDetach(w, "move volume", func() { close(canceled) }, recv)

	if elapsed := time.Since(start); elapsed >= 200*time.Millisecond {
		t.Fatalf("the handler waited %v for the first frame; it must answer within the ack budget", elapsed)
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 Accepted for a first frame that missed the budget", w.Code)
	}
	for name, ch := range map[string]chan struct{}{"stream drained": drained, "context released": canceled} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("detached reader: %s never happened", name)
		}
	}
}
