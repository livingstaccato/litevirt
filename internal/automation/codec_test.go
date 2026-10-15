package automation_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation"
)

func command() automation.Command {
	return automation.Command{Kind: "read_barrier", ClusterUID: "cluster-1", PrincipalID: "principal-1", OwnerID: "owner-1", RequestID: "read-1", Session: 1}
}

// A session, randomized ciphertext, or a recipient rewrap must not create a new request.
func TestCanonicalCommandExcludesSessionRenewalAndRewrap(t *testing.T) {
	a := command()
	a.SecretIntentTag, a.SecretKeyEpoch = []byte("private-tag"), "equality-1"
	a.Ciphertext = []byte("recipient-1:random-ciphertext")
	b := a
	b.Session, b.Ciphertext = 2, []byte("recipient-2:rewrapped-ciphertext")
	x, err := automation.CanonicalCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := automation.CanonicalCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatal("renewal or rewrap changed retry identity")
	}
	if bytes.Contains(x, a.Ciphertext) || bytes.Contains(y, b.Ciphertext) {
		t.Fatal("ciphertext entered identity")
	}
}

// Dropping any immutable field collapses requests that must conflict.
func TestCanonicalCommandDistinguishesImmutableFacts(t *testing.T) {
	a := command()
	a.Body = []byte(`{"version":1,"payload":"YQ=="}`)
	a.SecretIntentTag, a.SecretKeyEpoch = []byte("private-tag"), "equality-1"
	x, err := automation.CanonicalCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*automation.Command){
		"kind":           func(c *automation.Command) { c.Kind = "admit_create" },
		"cluster":        func(c *automation.Command) { c.ClusterUID = "cluster-2" },
		"project":        func(c *automation.Command) { c.ProjectUID = "project-2" },
		"principal":      func(c *automation.Command) { c.PrincipalID = "principal-2" },
		"owner":          func(c *automation.Command) { c.OwnerID = "owner-2" },
		"management":     func(c *automation.Command) { c.ManagementKey = "key-2" },
		"request":        func(c *automation.Command) { c.RequestID = "read-2" },
		"resource":       func(c *automation.Command) { c.ResourceUID = "resource-2" },
		"generation":     func(c *automation.Command) { c.Generation++ },
		"revision":       func(c *automation.Command) { c.ExpectedRevision++ },
		"body bytes":     func(c *automation.Command) { c.Body = []byte(`{"version":1,"payload":"YQo="}`) },
		"secret":         func(c *automation.Command) { c.SecretIntentTag = []byte("other-private-tag") },
		"equality epoch": func(c *automation.Command) { c.SecretKeyEpoch = "equality-2" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b := a
			change(&b)
			y, err := automation.CanonicalCommand(b)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(x, y) {
				t.Fatal("different immutable requests collapsed")
			}
		})
	}
}

func TestCanonicalCommandNormalizesJSONWithoutLosingBytesOrPrecision(t *testing.T) {
	a, b := command(), command()
	a.Body = []byte(` { "version":1, "n":9007199254740993, "nested":{"z":-0,"a":[1.00,1e2,"x\r\ny"]}} `)
	b.Body = []byte(`{"nested":{"a":[1,100,"x\r\ny"],"z":0},"n":9007199254740993,"version":1.0}`)
	x, err := automation.CanonicalCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := automation.CanonicalCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatal("equivalent JSON changed identity")
	}
	b.Body = []byte(`{"nested":{"a":[1,100,"x\r\ny"],"z":0},"n":9007199254740992,"version":1}`)
	y, err = automation.CanonicalCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(x, y) {
		t.Fatal("distinct large integers collapsed")
	}
	b.Body = []byte(`{"nested":{"a":[1,100,"x\ny"],"z":0},"n":9007199254740993,"version":1}`)
	y, err = automation.CanonicalCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(x, y) {
		t.Fatal("line ending bytes collapsed")
	}
}

func TestCanonicalCommandRejectsAmbiguousBody(t *testing.T) {
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"version":2}`, `{"version":"1"}`, `{"version":1} {}`,
		`{"version":1,"version":1}`, `{"version":1,"x":{"a":1,"\u0061":2}}`,
		`{"version":1,"x":01}`, `{"version":1,"x":NaN}`, `{"version":1,"x":"\ud800"}`,
		`{"version":1,"x":"\udc00"}`, "{\"version\":1,\"x\":\"\xff\"}",
	} {
		t.Run(fmt.Sprintf("case-%x", []byte(body)), func(t *testing.T) {
			c := command()
			c.Body = []byte(body)
			if _, err := automation.CanonicalCommand(c); automation.Code(err) != automation.CodeValidation {
				t.Fatal("invalid body did not return validation code")
			}
		})
	}
}

func TestCanonicalCommandValidationAndPrivateErrors(t *testing.T) {
	for _, mutate := range []func(*automation.Command){
		func(c *automation.Command) { c.RequestID = "" },
		func(c *automation.Command) { c.OwnerID = "\xff" },
		func(c *automation.Command) { c.SecretIntentTag = []byte("DO-NOT-LEAK") },
		func(c *automation.Command) { c.SecretKeyEpoch = "DO-NOT-LEAK" },
		func(c *automation.Command) { c.Body = []byte(`{"version":1,"DO-NOT-LEAK":`) },
	} {
		c := command()
		mutate(&c)
		_, err := automation.CanonicalCommand(c)
		if automation.Code(fmt.Errorf("wrapped: %w", err)) != automation.CodeValidation {
			t.Fatal("missing wrapped validation code")
		}
		if strings.Contains(err.Error(), "DO-NOT-LEAK") {
			t.Fatal("private input leaked through error")
		}
	}
	c := command()
	c.Kind = "future-command"
	if _, err := automation.CanonicalCommand(c); automation.Code(err) != automation.CodeUnsupported {
		t.Fatal("unknown kind not rejected")
	}
	if automation.Code(nil) != "" || automation.Code(errors.New("unexpected")) != "" {
		t.Fatal("unexpected errors misclassified")
	}
}

func TestCanonicalCommandBoundsUntrustedJSON(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"x":1e999999999999999999999999}`,
		`{"version":1,"x":10e1000000000}`,
		`{"version":1,"x":0.1e-1000000000}`,
		`{"version":1,"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}",
		`{"version":1,"x":"` + strings.Repeat("a", 1<<20) + `"}`,
	} {
		c := command()
		c.Body = []byte(body)
		if _, err := automation.CanonicalCommand(c); automation.Code(err) != automation.CodeValidation {
			t.Fatal("unbounded JSON accepted")
		}
	}
	c := command()
	c.Body = []byte(`{"version":1,"x":1e999999999}`)
	b, err := automation.CanonicalCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 1024 {
		t.Fatal("exponent expanded output")
	}
}

func TestCanonicalCommandNormalizesEmptySecretAndUnicodeEscapes(t *testing.T) {
	a, b := command(), command()
	a.Body = []byte(`{"version":1,"text":"\ud83d\ude00"}`)
	b.Body = []byte(`{"version":1,"text":"😀"}`)
	b.SecretIntentTag = []byte{}
	x, err := automation.CanonicalCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := automation.CanonicalCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatal("equivalent absent secret or Unicode changed identity")
	}
}

func TestCanonicalCommandWireIdentity(t *testing.T) {
	c := command()
	b, err := automation.CanonicalCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	want := "litevirt/automation/command/v1\x00" + `{"Kind":"read_barrier","ClusterUID":"cluster-1","ProjectUID":"","PrincipalID":"principal-1","OwnerID":"owner-1","ManagementKey":"","RequestID":"read-1","ResourceUID":"","Generation":0,"ExpectedRevision":0,"Body":null,"SecretIntentTag":null,"SecretKeyEpoch":""}`
	if string(b) != want {
		t.Fatal("wire identity does not match the versioned contract fixture")
	}
}
