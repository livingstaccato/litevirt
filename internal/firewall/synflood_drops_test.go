package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The drop counts are the lv-sf 4 and lv-sf 6 counters summed over the
// chains that carry them (forward and output); nothing else counts, an
// observe-mode would-drop least of all.
//
// Mutations: count lv-sf 4 into the v6 total — red; count only the first
// chain's line — red.
func TestParseSynFloodDrops(t *testing.T) {
	js := `{"nftables":[{"metainfo":{}},
{"rule":{"family":"bridge","chain":"forward","comment":"lv-sf 4","expr":[{"counter":{"packets":7,"bytes":420}},{"drop":null}]}},
{"rule":{"family":"bridge","chain":"forward","comment":"lv-sf 6","expr":[{"counter":{"packets":2,"bytes":160}},{"drop":null}]}},
{"rule":{"family":"bridge","chain":"output","comment":"lv-sf 4","expr":[{"counter":{"packets":5,"bytes":300}},{"drop":null}]}},
{"rule":{"family":"bridge","chain":"output","comment":"lv-sf 6","expr":[{"counter":{"packets":1,"bytes":80}},{"drop":null}]}},
{"rule":{"family":"bridge","chain":"forward","comment":"lv-wd - in synflood","expr":[{"counter":{"packets":99,"bytes":1}}]}},
{"rule":{"family":"bridge","chain":"forward","comment":"lv-sf 44","expr":[{"counter":{"packets":50,"bytes":1}}]}}]}`
	v4, v6, err := parseSynFloodDrops([]byte(js))
	if err != nil || v4 != 12 || v6 != 3 {
		t.Fatalf("parseSynFloodDrops = %d, %d, %v; want 12, 3", v4, v6, err)
	}
	if _, _, err := parseSynFloodDrops([]byte("{")); err == nil {
		t.Error("unparseable nft output read as no drops")
	}
}

// A host with no per-NIC table (no guest NIC) has dropped nothing; any other
// nft failure is an error, never a zero.
//
// Mutation: read every nft failure as zero — red.
func TestSynFloodDrops_NoTableIsZeroOtherFailureIsAnError(t *testing.T) {
	prev := nftListNICTable
	t.Cleanup(func() { nftListNICTable = prev })
	nftListNICTable = func(context.Context) ([]byte, error) {
		return []byte("Error: No such file or directory\nlist table bridge litevirt-nic"), errors.New("exit status 1")
	}
	if v4, v6, err := SynFloodDrops(context.Background()); err != nil || v4 != 0 || v6 != 0 {
		t.Errorf("no table: %d, %d, %v; want 0, 0, nil", v4, v6, err)
	}
	nftListNICTable = func(context.Context) ([]byte, error) {
		return []byte("Error: Operation not permitted"), errors.New("exit status 1")
	}
	if _, _, err := SynFloodDrops(context.Background()); err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Errorf("nft refused: err = %v, want it named", err)
	}
}
