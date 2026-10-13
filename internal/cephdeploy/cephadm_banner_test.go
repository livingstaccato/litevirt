package cephdeploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCephadm is a cephadm that prints the banner cephadm v19 prints, on
// stderr, before the JSON the ceph command inside the shell prints on stdout
// (lab 2 N-3). The osd-tree answer also has a banner line on stdout, as
// other versions print. "fail" makes it exit 1 with a message on stderr.
const fakeCephadm = `#!/bin/sh
echo "Inferring fsid 0b1e6d6a-8f1c-11f0-9c52-525400a1b2c3" >&2
echo "Inferring config /var/lib/ceph/0b1e6d6a-8f1c-11f0-9c52-525400a1b2c3/mon.lab2-ceph/config" >&2
echo "Using ceph image with id '2bc0b0f4375d' and tag 'v19' created on 2025-07-29 20:12:46 +0000 UTC" >&2
case "$*" in
*fail*) echo "Error: no such cluster" >&2; exit 1 ;;
*" -s "*) echo '{"fsid":"0b1e6d6a","health":{"status":"HEALTH_OK","checks":{}},"monmap":{"num_mons":3},"osdmap":{"num_osds":3,"num_up_osds":3,"num_in_osds":3},"pgmap":{"num_pgs":33,"bytes_avail":1000,"bytes_used":24}}'; echo "Releasing lock" >&2 ;;
*"osd tree"*) echo "Inferring fsid 0b1e6d6a-8f1c-11f0-9c52-525400a1b2c3"; echo '{"nodes":[{"id":-1,"name":"default","type":"root","children":[0]},{"id":0,"name":"osd.0","type":"osd","status":"up","reweight":1}],"stray":[]}' ;;
esac
`

func fakeRunner(t *testing.T) *CephadmRunner {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cephadm")
	if err := os.WriteFile(bin, []byte(fakeCephadm), 0o755); err != nil {
		t.Fatal(err)
	}
	return &CephadmRunner{Bin: bin}
}

// N-3: `lv host ceph status` and the osd tree parse what ceph printed,
// whatever cephadm's banner around it.
//
// Mutations: "Status parses CombinedOutput" (stderr's banner in front of the
// JSON) — red; "no banner strip on stdout" — the osd tree is red.
func TestCephadm_StatusAndOSDTreeParseUnderTheBanner(t *testing.T) {
	r := fakeRunner(t)
	st, err := r.Status(context.Background())
	if err != nil {
		t.Fatalf("status under cephadm's banner: %v", err)
	}
	if st.Health != "HEALTH_OK" || st.OSDsUp != 3 || st.MonsTotal != 3 {
		t.Fatalf("status = %+v", st)
	}
	tree, err := r.OSDTree(context.Background())
	if err != nil {
		t.Fatalf("osd tree under a banner on stdout: %v", err)
	}
	if len(tree.Nodes) != 2 || tree.Nodes[1].Name != "osd.0" {
		t.Fatalf("osd tree = %+v", tree)
	}
}

// A failed call says what cephadm said, from stderr.
func TestCephadm_AFailedCallCarriesItsStderr(t *testing.T) {
	r := fakeRunner(t)
	_, err := r.jsonOutput(context.Background(), "fail")
	if err == nil || !strings.Contains(err.Error(), "no such cluster") {
		t.Fatalf("a failed cephadm call: %v; want its stderr in the error", err)
	}
}

func TestJSONDocument(t *testing.T) {
	cases := []struct{ in, want string }{
		{in: `{"a":1}`, want: `{"a":1}`},
		{in: "Inferring x\n{\"a\":1}\n", want: "{\"a\":1}\n"},
		{in: "banner\n  [1,2]", want: "  [1,2]"},
		{in: "no json here", want: "no json here"},
	}
	for _, c := range cases {
		if got := string(jsonDocument([]byte(c.in))); got != c.want {
			t.Errorf("jsonDocument(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// fakeCephadmTrailing prints, on stdout, a line after the JSON document, as
// a version that reports on stdout once the command is done might.
const fakeCephadmTrailing = `#!/bin/sh
case "$*" in
*" -s "*) echo '{"fsid":"0b1e6d6a","health":{"status":"HEALTH_OK","checks":{}},"monmap":{"num_mons":3},"osdmap":{"num_osds":3,"num_up_osds":3,"num_in_osds":3},"pgmap":{"num_pgs":33,"bytes_avail":1000,"bytes_used":24}}'; echo "Releasing lock" ;;
*"osd tree"*) echo "Inferring fsid 0b1e6d6a"; echo '{"nodes":[{"id":-1,"name":"default","type":"root","children":[0]},{"id":0,"name":"osd.0","type":"osd","status":"up","reweight":1}],"stray":[]}'; echo "[done]" ;;
esac
`

// Re-review 3: what ceph printed parses when stdout carries anything after
// the JSON document too: only the first JSON value is read.
//
// Mutation: json.Unmarshal of the whole remainder — "invalid character":
// red.
func TestCephadm_StatusAndOSDTreeParseWithTrailingStdout(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cephadm")
	if err := os.WriteFile(bin, []byte(fakeCephadmTrailing), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &CephadmRunner{Bin: bin}
	st, err := r.Status(context.Background())
	if err != nil {
		t.Fatalf("status with a line after the JSON: %v", err)
	}
	if st.Health != "HEALTH_OK" || st.OSDsUp != 3 {
		t.Fatalf("status = %+v", st)
	}
	tree, err := r.OSDTree(context.Background())
	if err != nil {
		t.Fatalf("osd tree with a line after the JSON: %v", err)
	}
	if len(tree.Nodes) != 2 || tree.Nodes[1].Name != "osd.0" {
		t.Fatalf("osd tree = %+v", tree)
	}
}
