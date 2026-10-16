package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc/peer"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceExportBinaryEvidenceChunks(t *testing.T) {
	p, intent := sourcePreparationFixture(t)
	ctx := context.Background()
	serials := make([]string, 50000)
	for i := range serials {
		serials[i] = fmt.Sprintf("f000%08x", i)
	}
	if e := pki.GenerateCRL(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), filepath.Join(p.dir, "crl.pem"), serials); e != nil {
		t.Fatal(e)
	}
	if e := p.InitializePublication(ctx); e != nil {
		t.Fatal(e)
	}
	prepared, e := p.Prepare(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	id, e := p.Publish(ctx, prepared)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := p.client.Query(ctx, `SELECT evidence FROM local_automation_publications WHERE id=?`, id)
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	expected := rows[0].Bytes("evidence")
	if len(expected) <= AutomationExportChunkBytes {
		t.Fatal("fixture did not require multiple binary chunks", len(expected))
	}
	ctx = peer.NewContext(ctx, mustExportPeer(t, p))
	r := AutomationExportRequest{Intent: intent, Publication: id, Component: 1}
	first, e := p.ExportAutomationSource(ctx, r)
	if e != nil || first.Terminal || first.Cursor == "" {
		t.Fatal("first evidence chunk", e)
	}
	var all []byte
	pages := 0
	for {
		page, e := p.ExportAutomationSource(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		again, e := p.ExportAutomationSource(ctx, r)
		if e != nil || !bytes.Equal(mustExportJSON(t, page), mustExportJSON(t, again)) {
			t.Fatal("binary chunk retry differs", e)
		}
		if len(page.Chunk) > AutomationExportChunkBytes || len(page.Records) != 0 {
			t.Fatal("evidence mixed/unbounded")
		}
		all = append(all, page.Chunk...)
		pages++
		if page.Terminal {
			sum := sha256.Sum256(all)
			if !bytes.Equal(all, expected) || page.TerminalDigest != hex.EncodeToString(sum[:]) || page.TerminalBytes != int64(len(all)) || page.TerminalRecords != int64(pages) {
				t.Fatal("binary evidence terminal differs")
			}
			break
		}
		r.Cursor = page.Cursor
		if pages > 35 {
			t.Fatal("unbounded evidence chunks")
		}
	}
	t.Logf("actual signed binary trust evidence=%d bytes in %d bounded chunks", len(all), pages)
	corrupt := append([]byte(nil), expected...)
	corrupt[len(corrupt)-1] ^= 1
	if e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_publications SET evidence=? WHERE id=?`, corrupt, id); e != nil {
		t.Fatal(e)
	}
	r.Cursor = first.Cursor
	for n := 0; n < 35; n++ {
		page, e := p.ExportAutomationSource(ctx, r)
		if e != nil {
			if !strings.Contains(e.Error(), "terminal count/bytes/digest") {
				t.Fatal("unexpected binary corruption failure", e)
			}
			return
		}
		if page.Terminal {
			t.Fatal("corrupt binary evidence declared complete")
		}
		r.Cursor = page.Cursor
	}
	t.Fatal("corrupt evidence never terminated")
}
