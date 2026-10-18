package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ReadLine reads one line from in, without its line ending. It returns
// ctx.Err() as soon as ctx ends, so a Ctrl-C at a prompt ends the command at
// once. It reads byte by byte, so nothing after the line is consumed.
func ReadLine(ctx context.Context, in io.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				if buf[0] == '\n' {
					ch <- result{strings.TrimSuffix(b.String(), "\r"), nil}
					return
				}
				b.WriteByte(buf[0])
			}
			if err != nil {
				if err == io.EOF && b.Len() > 0 {
					err = nil
				}
				ch <- result{strings.TrimSuffix(b.String(), "\r"), err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		return r.line, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Confirm prints prompt and " [y/N] " to out and reads the answer from in:
// true for y or Y. An unreadable answer is a no; an ended ctx is its error.
func Confirm(ctx context.Context, in io.Reader, out io.Writer, prompt string) (bool, error) {
	fmt.Fprint(out, prompt+" [y/N] ")
	line, err := ReadLine(ctx, in)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(out)
			return false, ctx.Err()
		}
		return false, nil
	}
	ans := strings.TrimSpace(line)
	return ans == "y" || ans == "Y", nil
}

// readPasswordFd reads a password from a terminal without echo (a seam).
var readPasswordFd = term.ReadPassword

// ReadPassword prompts on stderr for a password and reads it from stdin
// without echoing it. It returns ctx.Err() as soon as ctx ends, with the
// terminal's echo restored first.
func ReadPassword(ctx context.Context, prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, prompt)
	state, _ := term.GetState(fd) // nil when stdin is not a terminal
	type result struct {
		pw  []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		pw, err := readPasswordFd(fd)
		ch <- result{pw, err}
	}()
	select {
	case r := <-ch:
		fmt.Fprintln(os.Stderr)
		if r.err != nil {
			return "", r.err
		}
		return string(r.pw), nil
	case <-ctx.Done():
		if state != nil {
			_ = term.Restore(fd, state)
		}
		fmt.Fprintln(os.Stderr)
		return "", ctx.Err()
	}
}
