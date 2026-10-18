package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// A Ctrl-C at a y/N prompt ends it at once: the read returns the context's
// error instead of waiting for a line that never comes.
//
// Mutation: read without the select on ctx — red.
func TestConfirm_ACancelEndsThePromptAtOnce(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Confirm(ctx, r, io.Discard, "Apply?")
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Confirm = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("a cancelled prompt kept waiting for its answer")
	}
}

func TestConfirm_ReadsTheAnswer(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "Y\n": true, "y\r\n": true, "n\n": false, "\n": false, "": false, "yes\n": false} {
		got, err := Confirm(context.Background(), strings.NewReader(in), io.Discard, "Apply?")
		if err != nil || got != want {
			t.Errorf("answer %q = %v, %v; want %v", in, got, err, want)
		}
	}
}

// ReadLine consumes the line and nothing after it.
func TestReadLine_LeavesTheRestOfTheInput(t *testing.T) {
	in := strings.NewReader("alice\nrest")
	line, err := ReadLine(context.Background(), in)
	if err != nil || line != "alice" {
		t.Fatalf("ReadLine = %q, %v", line, err)
	}
	rest, _ := io.ReadAll(in)
	if string(rest) != "rest" {
		t.Errorf("left %q, want %q", rest, "rest")
	}
}

// A Ctrl-C at a password prompt ends it at once.
//
// Mutation: read without the select on ctx — red.
func TestReadPassword_ACancelEndsThePromptAtOnce(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	orig := readPasswordFd
	readPasswordFd = func(int) ([]byte, error) { <-block; return nil, io.EOF }
	t.Cleanup(func() { readPasswordFd = orig })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ReadPassword(ctx, "Password: ")
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ReadPassword = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("a cancelled password prompt kept waiting")
	}
}
