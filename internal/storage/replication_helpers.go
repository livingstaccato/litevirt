package storage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"
)

func osStat(p string) (os.FileInfo, error) { return os.Stat(p) }

// pipeCmds wires `<binA> <argsA> | <binB> <argsB>`, optionally
// hopping over SSH for the receive side. Synchronous: returns when
// both processes have exited.
//
//   - sshTarget == "" — both commands run locally; binA's stdout
//     pipes to binB's stdin via os.Pipe.
//   - sshTarget != "" — binB is wrapped as `ssh <target> <binB args…>`
//     so the receive runs on the remote host.
//
// Errors include the exit details of whichever side failed.
func pipeCmds(ctx context.Context, sshTarget, binA string, argsA []string, binB string, argsB []string) ([]byte, error) {
	a := exec.CommandContext(ctx, binA, argsA...)
	var b *exec.Cmd
	if sshTarget != "" {
		b = exec.CommandContext(ctx, "ssh", append([]string{sshTarget, binB}, argsB...)...)
	} else {
		b = exec.CommandContext(ctx, binB, argsB...)
	}

	out, err := a.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	b.Stdin = out

	if err := b.Start(); err != nil {
		return nil, fmt.Errorf("start receiver: %w", err)
	}
	if err := a.Run(); err != nil {
		_ = b.Wait()
		return nil, fmt.Errorf("sender %s: %w", binA, err)
	}
	if err := b.Wait(); err != nil {
		return nil, fmt.Errorf("receiver %s: %w", binB, err)
	}
	return nil, nil
}

// nowSnapTag returns a timestamp suitable as a snapshot suffix:
// "20260510-091500". Used when the caller didn't supply an explicit
// SnapshotName.
func nowSnapTag() string {
	return time.Now().UTC().Format("20060102-150405")
}

// pathExists is a `os.Stat`-style probe used by btrfs to detect the
// previous-replicate snapshot dir for incremental `-p` sends.
// Wrapped here (rather than imported from os in btrfs.go) so the
// stat path is centralised.
func pathExists(p string) bool {
	_, err := osStat(p)
	return err == nil
}

// sortedKeys returns m's keys in order, so a record is written the same way
// every time.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
