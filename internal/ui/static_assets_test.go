package ui

import (
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// consoleTemplates are the pages that load the bundled noVNC client.
var consoleTemplates = []string{
	"templates/vnc.html",
	"templates/vnc_modal.html",
	"templates/console_modal.html",
}

// buildFetchedPrefixes are the static paths `make vendor-js` downloads at build
// time instead of committing (see the Makefile and .gitignore). A plain
// `go test` tree does not have them, so only the all-templates check skips
// them; the console module graph must never depend on one.
var buildFetchedPrefixes = []string{
	"static/vendor/htmx/",
	"static/vendor/uplot/",
	"static/fonts/",
}

var (
	// <script src="...">, <link href="..."> and CSS url("...") under /static/.
	htmlStaticRef = regexp.MustCompile(`(?:src|href)\s*=\s*["'](/static/[^"']+)["']`)
	// Static and dynamic ES module specifiers:
	//   import X from "s";  import {a} from 's';  import "s";
	//   export {a} from "s";  import("s")
	moduleSpecifier = regexp.MustCompile(`(?m)(?:^|[;\s])(?:import|export)\s*(?:[\w*{}\s,$]+?\s*from\s*)?\(?\s*["']([^"'\n]+)["']`)
)

// staticPath maps a URL path or module specifier, resolved against the file
// that references it, to its path inside staticFS. The UI serves staticFS at
// /static/ unchanged (http.FileServerFS in Handler), so "/static/a.js" is the
// embedded file "static/a.js".
func staticPath(fromFile, spec string) (string, bool) {
	switch {
	case strings.HasPrefix(spec, "/static/"):
		return strings.TrimPrefix(spec, "/"), true
	case strings.HasPrefix(spec, "./"), strings.HasPrefix(spec, "../"):
		return path.Join(path.Dir(fromFile), spec), true
	}
	return "", false
}

// walkModuleGraph follows every import reachable from the entry specifiers and
// returns the embedded paths it visited and the ones that are not embedded,
// each missing path listed with the file that imports it.
func walkModuleGraph(t *testing.T, entries map[string]string) (visited []string, missing []string) {
	t.Helper()
	seen := map[string]bool{}
	type edge struct{ from, to string }
	queue := []edge{}
	for to, from := range entries {
		queue = append(queue, edge{from, to})
	}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		if seen[e.to] {
			continue
		}
		seen[e.to] = true
		data, err := fs.ReadFile(staticFS, e.to)
		if err != nil {
			missing = append(missing, "/"+e.to+" (imported by "+e.from+")")
			continue
		}
		visited = append(visited, e.to)
		if !strings.HasSuffix(e.to, ".js") {
			continue
		}
		for _, m := range moduleSpecifier.FindAllStringSubmatch(string(data), -1) {
			p, ok := staticPath(e.to, m[1])
			if !ok {
				t.Errorf("%s imports %q, which is not a /static/ or relative path: the UI serves no bare module specifiers", e.to, m[1])
				continue
			}
			queue = append(queue, edge{e.to, p})
		}
	}
	sort.Strings(visited)
	sort.Strings(missing)
	return visited, missing
}

// TestConsoleModuleGraphIsEmbedded walks every <script src> and ES module
// import reachable from the console pages and requires each target to be in
// staticFS. An ES module whose import 404s aborts the whole graph, so one
// missing file (pako, kept out of the repo by an unanchored `vendor/` ignore
// rule) leaves the console blank with no error on the page.
func TestConsoleModuleGraphIsEmbedded(t *testing.T) {
	entries := map[string]string{}
	for _, tmpl := range consoleTemplates {
		data, err := fs.ReadFile(templateFS, tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		src := string(data)
		for _, m := range htmlStaticRef.FindAllStringSubmatch(src, -1) {
			p, _ := staticPath(tmpl, m[1])
			entries[p] = tmpl
		}
		for _, m := range moduleSpecifier.FindAllStringSubmatch(src, -1) {
			p, ok := staticPath(tmpl, m[1])
			if !ok {
				t.Errorf("%s imports %q, which is not a /static/ path", tmpl, m[1])
				continue
			}
			entries[p] = tmpl
		}
	}
	if _, ok := entries["static/novnc/rfb.js"]; !ok {
		t.Fatalf("no console template imports /static/novnc/rfb.js; the walk would prove nothing (entries: %v)", entries)
	}

	visited, missing := walkModuleGraph(t, entries)
	for _, p := range visited {
		for _, pre := range buildFetchedPrefixes {
			if strings.HasPrefix(p, pre) {
				t.Errorf("console module graph reaches build-fetched %s; it must only use committed files", p)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("console module graph imports %d file(s) that are not embedded, so the browser gets 404 and noVNC never loads:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	// noVNC's inflator/deflator pull in pako; a walk that never reached it
	// would pass vacuously if the import syntax stopped matching.
	if len(visited) < 40 {
		t.Errorf("walk visited only %d files; the import pattern has probably stopped matching noVNC's imports", len(visited))
	}
}

// TestTemplateStaticRefsAreEmbedded checks every /static/ reference in every
// template, except the assets `make vendor-js` fetches at build time.
func TestTemplateStaticRefsAreEmbedded(t *testing.T) {
	tmpls, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil || len(tmpls) == 0 {
		t.Fatalf("glob templates: %v (%d)", err, len(tmpls))
	}
	var missing []string
	for _, tmpl := range tmpls {
		data, err := fs.ReadFile(templateFS, tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		refs := htmlStaticRef.FindAllStringSubmatch(string(data), -1)
		refs = append(refs, moduleSpecifier.FindAllStringSubmatch(string(data), -1)...)
	ref:
		for _, m := range refs {
			if strings.Contains(m[1], "{{") {
				continue // templated (e.g. grafana/{{.Filename}})
			}
			p, ok := staticPath(tmpl, m[1])
			if !ok {
				continue
			}
			for _, pre := range buildFetchedPrefixes {
				if strings.HasPrefix(p, pre) {
					continue ref
				}
			}
			if _, err := fs.Stat(staticFS, p); err != nil {
				missing = append(missing, "/"+p+" (referenced by "+tmpl+")")
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("templates reference %d static file(s) that are not embedded:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}
