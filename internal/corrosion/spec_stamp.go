package corrosion

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// The spec edit stamp: once spec_conflict_v1 has latched, every edit that
// moves a VM's spec_generation (MutateDesiredSpec, an operation's claim)
// records inside the spec document itself
//
//	"spec_edit": {"at": "<the edit's NowTS>", "lineage": ["<parent>", ...]}
//
// at is when the spec was edited. It is what two edits at one generation are
// ordered by, and it is NOT the row's updated_at: every state, actuals and
// host write bumps that, so the row clock says nothing about which spec edit
// came later (CLAUDE.md: never compare a copy against its parent row's
// updated_at).
//
// lineage is the content hash of the spec the edit was made from, then that
// spec's own lineage, newest first, at most specLineageMax long. A version
// at generation g therefore names its ancestor at g-d at lineage[d-1], which
// is how a receiver tells an edit that descends from the version it replaces
// from one that does not — and so which edits a resolution drops, however
// many edits each side made.
//
// A spec written before the latch, or by a writer that does not stamp (a
// create, a network rename), has no stamp: it orders as the earliest, and it
// has no lineage, so nothing is judged about its ancestors.

const (
	specEditKey     = "spec_edit"
	specLineageMax  = 16
	specContentSize = 16 // bytes of sha256 kept per lineage entry
)

type specEditMeta struct {
	At      string   `json:"at"`
	Lineage []string `json:"lineage,omitempty"`
}

// specCanonical is the spec's content without its stamp: the JSON
// re-encoded with sorted keys and numbers kept as written. A document that is
// not JSON is its own canonical form.
func specCanonical(spec string) []byte {
	dec := json.NewDecoder(bytes.NewReader([]byte(spec)))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return []byte(spec)
	}
	if m, ok := v.(map[string]interface{}); ok {
		delete(m, specEditKey)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return []byte(spec)
	}
	return out
}

// specContentHash identifies a spec's content, stamp excluded.
func specContentHash(spec string) string {
	sum := sha256.Sum256(specCanonical(spec))
	return hex.EncodeToString(sum[:specContentSize])
}

// specMetaOf is spec's stamp; zero when it has none.
func specMetaOf(spec string) specEditMeta {
	var doc struct {
		Edit *specEditMeta `json:"spec_edit"`
	}
	if json.Unmarshal([]byte(spec), &doc) != nil || doc.Edit == nil {
		return specEditMeta{}
	}
	return *doc.Edit
}

// stampSpec returns spec carrying an edit stamp made at at from parent. A
// spec that is not a JSON object is returned as it is: unstamped.
func stampSpec(spec, parent, at string) string {
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(spec), &doc) != nil || doc == nil {
		return spec
	}
	lineage := append([]string{specContentHash(parent)}, specMetaOf(parent).Lineage...)
	if len(lineage) > specLineageMax {
		lineage = lineage[:specLineageMax]
	}
	raw, err := json.Marshal(specEditMeta{At: at, Lineage: lineage})
	if err != nil {
		return spec
	}
	doc[specEditKey] = raw
	out, err := json.Marshal(doc)
	if err != nil {
		return spec
	}
	return string(out)
}

// specStampOrder orders two specs by their edit stamps: <0 when a's edit is
// earlier. An unstamped spec is the earliest.
func specStampOrder(a, b string) int {
	at, bt := specMetaOf(a).At, specMetaOf(b).At
	switch {
	case at == "" && bt == "":
		return 0
	case at == "":
		return -1
	case bt == "":
		return 1
	}
	return lwwOrder(at, bt)
}

// specAncestorAt reports what spec's lineage says of its ancestor depth
// generations back (depth >= 1): known=false when the lineage does not reach
// that far, else whether that ancestor's content hash is hash.
func specAncestorAt(spec string, depth int64, hash string) (is, known bool) {
	lineage := specMetaOf(spec).Lineage
	if depth < 1 || depth > int64(len(lineage)) {
		return false, false
	}
	return lineage[depth-1] == hash, true
}
