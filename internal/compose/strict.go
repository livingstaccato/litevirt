package compose

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Unknown fields are errors. A misspelt key used to be dropped by the YAML
// decoder without a word, leaving the default in force — `retires: 5` meant
// three retries, and nothing said so. Each unknown key is reported with the
// field it most likely meant:
//
//	vms.db.healthcheck: unknown field "retires" — did you mean "retries"?
//
// Two kinds of key are legitimate without being fields: extension fields
// (any key starting "x-", free for the author's own use, for example to hold
// a YAML anchor) and YAML merge keys (`<<: *anchor`), whose merged keys are
// checked in turn, positioned where the anchor writes them.

// ParseStored parses compose YAML that was validated when it was deployed and
// has been stored since. It skips the checks a later build may have added
// (unknown fields) so a stack stays readable to the code that tears it down or
// resolves its volumes; it still refuses what cannot be decoded at all.
// Anything a person has just written goes through ParseBytes.
func ParseStored(data []byte) (*File, error) {
	return parseWith(data, parseOpts{stored: true})
}

type parseOpts struct {
	// stored: the YAML was accepted earlier; skip the checks that only
	// guard against a person's mistakes.
	stored bool
}

// checkFileFields reports every unknown field in the file.
func (v *validator) checkFileFields(root *yaml.Node) {
	v.checkFields(root, reflect.TypeOf(File{}), "", 0)
}

// checkFields reports every key of mapping n that struct type t has no field
// for, and recurses into the fields it does have.
func (v *validator) checkFields(n *yaml.Node, t reflect.Type, path string, depth int) {
	n = resolveAlias(n)
	if n == nil || depth > 32 {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return // a shorthand scalar, or a type error the decoder reports
		}
		fs := fieldsOf(t)
		for _, e := range mappingEntries(n) {
			k := e.key.Value
			if strings.HasPrefix(k, "x-") {
				continue
			}
			ft, ok := fs.types[k]
			if !ok {
				hint := ""
				if s := suggest(k, fs.names); s != "" {
					hint = fmt.Sprintf("did you mean %q?", s)
				} else if len(fs.names) <= 10 {
					hint = "valid fields: " + strings.Join(fs.names, ", ")
				}
				v.ps.addAt(e.key, path, fmt.Sprintf("unknown field %q", k), hint)
				continue
			}
			v.checkFields(e.val, ft, joinPath(path, k), depth+1)
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return
		}
		for _, e := range mappingEntries(n) {
			v.checkFields(e.val, t.Elem(), joinPath(path, e.key.Value), depth+1)
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, c := range n.Content {
			v.checkFields(c, t.Elem(), fmt.Sprintf("%s[%d]", path, i), depth+1)
		}
	}
}

type entry struct{ key, val *yaml.Node }

// mappingEntries is n's key/value pairs with merge keys expanded: explicit
// keys first, then merged keys the mapping does not write itself.
func mappingEntries(n *yaml.Node) []entry {
	var out, merges []entry
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMergeKey(k) {
			merges = append(merges, entry{k, v})
			continue
		}
		seen[k.Value] = true
		out = append(out, entry{k, v})
	}
	for _, m := range merges {
		for _, src := range mergeSources(m.val) {
			for i := 0; i+1 < len(src.Content); i += 2 {
				k, v := src.Content[i], src.Content[i+1]
				if isMergeKey(k) || seen[k.Value] {
					continue
				}
				seen[k.Value] = true
				out = append(out, entry{k, v})
			}
		}
	}
	return out
}

type structFields struct {
	names []string                // in declaration order
	types map[string]reflect.Type // yaml name → field type
}

var fieldCache sync.Map // reflect.Type → structFields

// fieldsOf is the YAML field names of struct type t, as yaml.v3 decodes them.
func fieldsOf(t reflect.Type) structFields {
	if c, ok := fieldCache.Load(t); ok {
		return c.(structFields)
	}
	fs := structFields{types: map[string]reflect.Type{}}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		fs.names = append(fs.names, name)
		fs.types[name] = f.Type
	}
	fieldCache.Store(t, fs)
	return fs
}

// suggest is the candidate key most likely meant, or "" when none is close:
// ignoring case, within an edit distance (adjacent swaps count once) of about
// a third of the candidate's length.
func suggest(key string, candidates []string) string {
	k := strings.ToLower(key)
	best, bestD := "", 1<<30
	for _, c := range candidates {
		d := osaDistance(k, strings.ToLower(c))
		limit := max(1, len(c)/3)
		if d <= limit && d < bestD {
			best, bestD = c, d
		}
	}
	return best
}

// osaDistance is the optimal-string-alignment edit distance: insertions,
// deletions, substitutions and adjacent transpositions each cost one.
func osaDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
