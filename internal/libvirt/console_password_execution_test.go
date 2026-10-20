package libvirt

import (
	"errors"
	golibvirt "github.com/digitalocean/go-libvirt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var executionConsoleRefusal = errors.New("qemu-system-x86_64: -vnc :1,password=on: Cipher backend does not support DES algorithm")

func TestStartDomainBoundConsoleFallbackKeepsUUID(t *testing.T) {
	for _, paused := range []bool{false, true} {
		name := "running"
		if paused {
			name = "paused"
		}
		t.Run(name, func(t *testing.T) {
			m := newExecutionDomainModel()
			m.firstError = executionConsoleRefusal
			m.onCreate = func() { m.named = m.b }
			unavailable := 0
			g := StartGuard{Before: func(string) (bool, error) { return paused, nil }}
			if err := startDomainBound(m, g, "web", executionUUIDA, PolicySet, func(string) { unavailable++ }); err != nil {
				t.Fatal(err)
			}
			want := "create:A,xml:A,define:A,create:A"
			if paused {
				want = "paused:A,xml:A,define:A,paused:A,resume:A"
			}
			executionTrace(t, m, want)
			if len(m.definitions) != 1 || HasConsolePassword(m.definitions[0]) || UUIDFromXML(m.definitions[0]) != executionUUIDA || unavailable != 1 || len(m.xmlFlags) != 1 || m.xmlFlags[0] != (golibvirt.DomainXMLSecure|golibvirt.DomainXMLInactive) {
				t.Fatal("fallback did not preserve secure original identity and reporting")
			}
		})
	}
}
func TestStartDomainBoundConsoleXMLMismatchRefuses(t *testing.T) {
	for _, which := range []string{"uuid", "name", "missing-uuid", "duplicate-uuid", "duplicate-name", "malformed", "define-return"} {
		t.Run(which, func(t *testing.T) {
			m := newExecutionDomainModel()
			m.firstError = executionConsoleRefusal
			m.onCreate = func() { m.named = m.b }
			reported := false
			switch which {
			case "uuid":
				m.xml = strings.ReplaceAll(m.xml, executionUUIDA, executionUUIDB)
			case "name":
				m.xml = strings.ReplaceAll(m.xml, "<name>web</name>", "<name>other</name>")
			case "missing-uuid":
				m.xml = strings.ReplaceAll(m.xml, "<uuid>"+executionUUIDA+"</uuid>", "")
			case "duplicate-uuid":
				m.xml = strings.ReplaceAll(m.xml, "</uuid>", "</uuid><uuid>"+executionUUIDB+"</uuid>")
			case "duplicate-name":
				m.xml = strings.ReplaceAll(m.xml, "</name>", "</name><name>other</name>")
			case "malformed":
				m.xml = "<domain>"
			case "define-return":
				m.defineResult = &m.b
			}
			err := startDomainBound(m, StartGuard{}, "web", executionUUIDA, PolicySet, func(string) { reported = true })
			want := "create:A,xml:A"
			if which == "define-return" {
				want += ",define:B"
			}
			if err == nil || reported {
				t.Fatalf("BOUND_UUID_XML: mismatch accepted: %v %v", err, m.calls)
			}
			executionTrace(t, m, want)
		})
	}
}
func TestStartDomainBoundConsoleCompatibility(t *testing.T) {
	for _, which := range []string{"leave", "no-password", "ordinary-error", "xml-error", "define-error", "fips"} {
		t.Run(which, func(t *testing.T) {
			m := newExecutionDomainModel()
			m.firstError = executionConsoleRefusal
			policy := PolicySet
			reports := 0
			old := fipsEnabledPath
			fipsEnabledPath = filepath.Join(t.TempDir(), "fips")
			defer func() { fipsEnabledPath = old }()
			if err := os.WriteFile(fipsEnabledPath, []byte("0\n"), 0600); err != nil {
				t.Fatal(err)
			}
			switch which {
			case "leave":
				policy = PolicyLeave
			case "no-password":
				m.xml = strings.ReplaceAll(m.xml, " passwd='original'", "")
			case "ordinary-error":
				m.firstError = errors.New("disk unavailable")
			case "xml-error":
				m.xmlError = errors.New("XML unavailable")
			case "define-error":
				m.defineError = errors.New("backend rejected definition")
			case "fips":
				m.firstError = errors.New("qemu-system-x86_64: -vnc :1: address in use")
				if err := os.WriteFile(fipsEnabledPath, []byte("1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := startDomainBound(m, StartGuard{}, "web", executionUUIDA, policy, func(string) { reports++ })
			want := "create:A"
			if which != "leave" && which != "ordinary-error" {
				want += ",xml:A"
			}
			if which == "define-error" || which == "fips" {
				want += ",define:A"
			}
			if which == "fips" {
				want += ",create:A"
			}
			executionTrace(t, m, want)
			if (err == nil) != (which == "fips") || reports != map[bool]int{true: 1, false: 0}[which == "fips"] {
				t.Fatalf("compatibility result: %v reports=%d", err, reports)
			}
		})
	}
}
