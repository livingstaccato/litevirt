package compose

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose validation reports every problem in a file in one pass, one line
// each, in the form compilers use and editors recognise:
//
//	compose validation errors:
//	  - stack.yaml:7:15: vms.db.healthcheck.target: "ssh" is not a port number — use 22
//	  - stack.yaml:9:7: vms.db.healthcheck: unknown field "retires" — did you mean "retries"?
//	  - vms.web: image or iso required — set image: or iso:
//
// The position is where the problem is written (the key, for an unknown
// field; the value, otherwise; the enclosing block, for a missing field), and
// is left out when the file has no node for it. The path names the field the
// way the file nests it: map keys joined by dots, list items by [index].

// Problem is one thing wrong with a compose file.
type Problem struct {
	// Path is the field, e.g. "vms.db.healthcheck.target"; "" for the file.
	Path string
	// Line and Column are the 1-based position in the file, 0 when unknown.
	Line   int
	Column int
	// Message says what is wrong.
	Message string
	// Hint, when set, is a one-line fix.
	Hint string
}

func (p Problem) render(file string) string {
	var b strings.Builder
	if p.Line > 0 {
		if file != "" {
			b.WriteString(file + ":")
		}
		fmt.Fprintf(&b, "%d:%d: ", p.Line, p.Column)
	}
	if p.Path != "" {
		b.WriteString(p.Path + ": ")
	}
	b.WriteString(p.Message)
	if p.Hint != "" {
		b.WriteString(" — " + p.Hint)
	}
	return b.String()
}

// String renders the problem as one line, without a file name.
func (p Problem) String() string { return p.render("") }

// ValidationError is every problem found in a compose file.
type ValidationError struct {
	// File, when set, prefixes each position.
	File     string
	Problems []Problem
}

func (e *ValidationError) Error() string {
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = p.render(e.File)
	}
	return "compose validation errors:\n  - " + strings.Join(lines, "\n  - ")
}

// problems collects Problems, positioning each from the file's node index.
type problems struct {
	idx  *nodeIndex
	list []Problem
}

// add records a problem with the field at path, positioned at its value (or,
// when the file does not write that field, the nearest enclosing one).
func (ps *problems) add(path, msg, hint string) {
	line, col := ps.idx.pos(path)
	ps.list = append(ps.list, Problem{Path: path, Line: line, Column: col, Message: msg, Hint: hint})
}

// addAt records a problem positioned at node n.
func (ps *problems) addAt(n *yaml.Node, path, msg, hint string) {
	p := Problem{Path: path, Message: msg, Hint: hint}
	if n != nil {
		p.Line, p.Column = n.Line, n.Column
	}
	ps.list = append(ps.list, p)
}

func (ps *problems) empty() bool { return len(ps.list) == 0 }

// err returns the problems as a *ValidationError, sorted by position (the
// unpositioned last, by path), or nil when there are none.
func (ps *problems) err() error {
	if len(ps.list) == 0 {
		return nil
	}
	list := append([]Problem(nil), ps.list...)
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.Line == 0) != (b.Line == 0) {
			return a.Line != 0
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Message < b.Message
	})
	return &ValidationError{Problems: list}
}

// nodeIndex maps field paths to where the file writes them.
type nodeIndex struct {
	vals map[string]*yaml.Node // path → value node
	keys map[string]*yaml.Node // path → key node
}

// maxIndexNodes bounds the walk: aliases can make a small document expand
// exponentially, and positions are a convenience, never worth that.
const maxIndexNodes = 100000

func indexNodes(doc *yaml.Node) *nodeIndex {
	idx := &nodeIndex{vals: map[string]*yaml.Node{}, keys: map[string]*yaml.Node{}}
	root := documentRoot(doc)
	if root == nil {
		return idx
	}
	budget := maxIndexNodes
	idx.vals[""] = root
	idx.walk(root, "", &budget, 0)
	return idx
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return doc.Content[0]
	}
	return doc
}

func (idx *nodeIndex) walk(n *yaml.Node, path string, budget *int, depth int) {
	n = resolveAlias(n)
	if n == nil || depth > 64 {
		return
	}
	switch n.Kind {
	case yaml.MappingNode:
		// Explicit keys win over merged ones (`<<: *anchor`) wherever they
		// appear, so index them first; merged keys fill only the gaps.
		var merges []*yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if isMergeKey(k) {
				merges = append(merges, v)
				continue
			}
			idx.put(joinPath(path, k.Value), k, v, budget, depth)
		}
		for _, m := range merges {
			for _, src := range mergeSources(m) {
				for i := 0; i+1 < len(src.Content); i += 2 {
					k, v := src.Content[i], src.Content[i+1]
					if isMergeKey(k) {
						continue
					}
					p := joinPath(path, k.Value)
					if _, ok := idx.vals[p]; !ok {
						idx.put(p, k, v, budget, depth)
					}
				}
			}
		}
	case yaml.SequenceNode:
		for i, v := range n.Content {
			idx.put(path+"["+strconv.Itoa(i)+"]", nil, v, budget, depth)
		}
	}
}

func (idx *nodeIndex) put(p string, k, v *yaml.Node, budget *int, depth int) {
	if *budget <= 0 {
		return
	}
	*budget--
	if k != nil {
		idx.keys[p] = k
	}
	idx.vals[p] = v
	idx.walk(v, p, budget, depth+1)
}

// pos is where path is written, or the nearest enclosing field the file does
// write: a scalar's value, or a block's key (the line that opens it). 0, 0
// when the file writes none of it.
func (idx *nodeIndex) pos(path string) (int, int) {
	if idx == nil {
		return 0, 0
	}
	for p := path; ; p = parentPath(p) {
		if n, ok := idx.vals[p]; ok {
			n = resolveAlias(n)
			if k := idx.keys[p]; k != nil && n != nil && n.Kind != yaml.ScalarNode {
				return k.Line, k.Column
			}
			if n != nil && n.Line > 0 {
				return n.Line, n.Column
			}
		}
		if p == "" {
			return 0, 0
		}
	}
}

// atLine is the deepest field whose value is written on line, and its column,
// for errors that know only a line. "", 0 when none is.
func (idx *nodeIndex) atLine(line int) (string, int) {
	if idx == nil || line <= 0 {
		return "", 0
	}
	best, col := "", 0
	for p, n := range idx.vals {
		if n == nil || n.Line != line || p == "" {
			continue
		}
		depth, bestDepth := strings.Count(p, ".")+strings.Count(p, "["), strings.Count(best, ".")+strings.Count(best, "[")
		if best == "" || depth > bestDepth || (depth == bestDepth && (n.Column < col || (n.Column == col && p < best))) {
			best, col = p, n.Column
		}
	}
	return best, col
}

// has reports whether the file writes the field at path.
func (idx *nodeIndex) has(path string) bool {
	if idx == nil {
		return false
	}
	_, ok := idx.vals[path]
	return ok
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// parentPath strips the last ".key" or "[i]" from p.
func parentPath(p string) string {
	if strings.HasSuffix(p, "]") {
		if i := strings.LastIndexByte(p, '['); i >= 0 {
			return p[:i]
		}
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return p[:i]
	}
	return ""
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 16; i++ {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

func isMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" && (k.Tag == "!!merge" || k.Tag == "")
}

// mergeSources is the mappings a `<<` value merges: one mapping, or a list.
func mergeSources(v *yaml.Node) []*yaml.Node {
	v = resolveAlias(v)
	if v == nil {
		return nil
	}
	switch v.Kind {
	case yaml.MappingNode:
		return []*yaml.Node{v}
	case yaml.SequenceNode:
		var out []*yaml.Node
		for _, c := range v.Content {
			if c = resolveAlias(c); c != nil && c.Kind == yaml.MappingNode {
				out = append(out, c)
			}
		}
		return out
	}
	return nil
}
