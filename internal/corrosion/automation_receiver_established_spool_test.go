package corrosion

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

func TestReceiverEstablishedSpoolExactFrames(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}})
	evidence, err := f.attempt.view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.receiver.prepareEstablishment(ctx, f.attempt, evidence)
	if err != nil {
		t.Fatal(err)
	}
	digest := f.attempt.view.EvidenceDigest()
	key := hex.EncodeToString(digest[:])
	for _, mode := range []string{"complete", "truncate", "extra", "body", "length", "cancel", "write-error", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			spool, err := newReceiverEstablishedSpool()
			if err != nil {
				t.Fatal(err)
			}
			dir := spool.dir
			defer func() {
				spool.close()
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatal("spool cleanup failed", err)
				}
			}()
			if info, e := os.Stat(dir); e != nil || info.Mode().Perm() != 0700 {
				t.Fatal("spool parent is not private", e)
			}
			if mode == "write-error" {
				if err = spool.file.Close(); err != nil {
					t.Fatal(err)
				}
				if err = spool.add(ctx, f.attempt.id, key, raw); err == nil {
					t.Fatal("closed FD write accepted")
				}
				return
			}
			if err = spool.add(ctx, f.attempt.id, key, raw); err != nil {
				t.Fatal(err)
			}
			if mode == "duplicate" {
				if err = spool.add(ctx, f.attempt.id, key, raw); err == nil {
					t.Fatal("duplicate original prepared")
				}
				return
			}
			if err = spool.seal(); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "truncate":
				err = spool.file.Truncate(spool.size - 1)
			case "extra":
				_, err = spool.file.Write([]byte{0})
			case "body":
				_, err = spool.file.WriteAt([]byte{raw[0] ^ 1}, 132)
			case "length":
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], maxReceiverEstablishedBytes+1)
				_, err = spool.file.WriteAt(b[:], 128)
			}
			if err != nil {
				t.Fatal(err)
			}
			callctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			count := 0
			err = spool.replay(callctx, func(attempt, digest string, artifact []byte) error {
				count++
				if mode == "complete" && (attempt != f.attempt.id || digest != key || !bytes.Equal(artifact, raw)) {
					t.Fatal("changed prepared original")
				}
				return nil
			})
			if mode == "complete" {
				if err != nil || count != 1 {
					t.Fatal("prepared artifact lost", count, err)
				}
			} else if err == nil {
				t.Fatal("altered spool accepted", mode)
			}
		})
	}
}
