package libvirt

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

const executionUUIDA = "11111111-1111-4111-8111-111111111111"
const executionUUIDB = "22222222-2222-4222-8222-222222222222"

// An actual snapshotAPI model: all methods reached by the bound start are
// overridden. Unused methods panic through the nil embedded interface.
type executionDomainModel struct {
	snapshotAPI
	a, b, named                                                 golibvirt.Domain
	calls                                                       []string
	lookups                                                     int
	firstError, resumeError, lookupError, xmlError, defineError error
	xml                                                         string
	defineResult                                                *golibvirt.Domain
	onCreate                                                    func()
	flags                                                       []uint32
	xmlFlags                                                    []golibvirt.DomainXMLFlags
	definitions                                                 []string
}

func executionDomain(uuid string) golibvirt.Domain {
	raw, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil {
		panic(err)
	}
	d := golibvirt.Domain{Name: "web"}
	copy(d.UUID[:], raw)
	return d
}
func newExecutionDomainModel() *executionDomainModel {
	a, b := executionDomain(executionUUIDA), executionDomain(executionUUIDB)
	return &executionDomainModel{a: a, b: b, named: a, xml: "<domain><name>web</name><uuid>" + executionUUIDA + "</uuid><devices><graphics type='vnc' passwd='original'/></devices></domain>"}
}
func (m *executionDomainModel) label(d golibvirt.Domain) string {
	if d == m.a {
		return "A"
	}
	if d == m.b {
		return "B"
	}
	return "foreign"
}
func (m *executionDomainModel) DomainLookupByName(name string) (golibvirt.Domain, error) {
	m.lookups++
	if name != "web" {
		return golibvirt.Domain{}, errors.New("wrong lookup")
	}
	return m.named, m.lookupError
}
func (m *executionDomainModel) create(d golibvirt.Domain, kind string) error {
	m.calls = append(m.calls, kind+":"+m.label(d))
	if m.onCreate != nil {
		m.onCreate()
	}
	err := m.firstError
	m.firstError = nil
	return err
}
func (m *executionDomainModel) DomainCreate(d golibvirt.Domain) error { return m.create(d, "create") }
func (m *executionDomainModel) DomainCreateWithFlags(d golibvirt.Domain, f uint32) (golibvirt.Domain, error) {
	m.flags = append(m.flags, f)
	return d, m.create(d, "paused")
}
func (m *executionDomainModel) DomainResume(d golibvirt.Domain) error {
	m.calls = append(m.calls, "resume:"+m.label(d))
	return m.resumeError
}
func (m *executionDomainModel) DomainDestroy(d golibvirt.Domain) error {
	m.calls = append(m.calls, "destroy:"+m.label(d))
	return nil
}
func (m *executionDomainModel) DomainGetXMLDesc(d golibvirt.Domain, f golibvirt.DomainXMLFlags) (string, error) {
	m.calls = append(m.calls, "xml:"+m.label(d))
	m.xmlFlags = append(m.xmlFlags, f)
	x := m.xml
	if d.UUID == m.b.UUID {
		x = strings.ReplaceAll(x, executionUUIDA, executionUUIDB)
	}
	return x, m.xmlError
}
func (m *executionDomainModel) DomainDefineXML(x string) (golibvirt.Domain, error) {
	m.definitions = append(m.definitions, x)
	// Model libvirt's UUID selection rather than always handing back A.
	d := m.a
	if UUIDFromXML(x) == executionUUIDB {
		d = m.b
	}
	if m.defineResult != nil {
		d = *m.defineResult
	}
	m.calls = append(m.calls, "define:"+m.label(d))
	return d, m.defineError
}
func executionTrace(t *testing.T, m *executionDomainModel, want string) {
	t.Helper()
	if got := strings.Join(m.calls, ","); got != want || m.lookups != 1 {
		t.Fatalf("BOUND_UUID_EFFECTS: trace=%s lookups=%d want=%s", got, m.lookups, want)
	}
}
func TestStartDomainBoundUUIDReuseDoesNotMutateSuccessor(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		m := newExecutionDomainModel()
		if err := startDomainBound(m, StartGuard{}, "web", executionUUIDA, PolicyLeave, nil); err != nil {
			t.Fatal(err)
		}
		executionTrace(t, m, "create:A")
	})
	t.Run("successor", func(t *testing.T) {
		m := newExecutionDomainModel()
		m.named = m.b
		err := startDomainBound(m, StartGuard{}, "web", executionUUIDA, PolicyLeave, nil)
		if err == nil || len(m.calls) != 0 {
			t.Fatalf("BOUND_UUID_SUCCESSOR: err=%v effects=%v", err, m.calls)
		}
		executionTrace(t, m, "")
	})
	t.Run("wrong-name", func(t *testing.T) {
		m := newExecutionDomainModel()
		m.named.Name = "other"
		if err := startDomainBound(m, StartGuard{}, "web", executionUUIDA, PolicyLeave, nil); err == nil {
			t.Fatal("accepted foreign name")
		}
		executionTrace(t, m, "")
	})
	t.Run("lookup-error", func(t *testing.T) {
		m := newExecutionDomainModel()
		m.lookupError = errors.New("lost backend")
		if err := startDomainBound(m, StartGuard{}, "web", executionUUIDA, PolicyLeave, nil); err == nil {
			t.Fatal("accepted unavailable lookup")
		}
		executionTrace(t, m, "")
	})
}
func TestStartDomainBoundRejectsInvalidUUID(t *testing.T) {
	for _, u := range []string{"", "00000000-0000-0000-0000-000000000000", "11111111111141118111111111111111", "AAAAAAAA-1111-4111-8111-111111111111", "bad"} {
		t.Run(u, func(t *testing.T) {
			m := newExecutionDomainModel()
			if err := startDomainBound(m, StartGuard{}, "web", u, PolicyLeave, nil); err == nil || m.lookups != 0 || len(m.calls) != 0 {
				t.Fatal("invalid identity reached backend")
			}
		})
	}
}
func TestStartDomainBoundPausedFailureCleansOriginal(t *testing.T) {
	for _, stage := range []string{"success", "before", "after", "resume"} {
		t.Run(stage, func(t *testing.T) {
			m := newExecutionDomainModel()
			m.onCreate = func() { m.named = m.b }
			guard := StartGuard{Before: func(string) (bool, error) {
				m.named = m.b
				if stage == "before" {
					return false, errors.New("guard")
				}
				return true, nil
			}, AfterPaused: func(string) error {
				if stage == "after" {
					return errors.New("guard")
				}
				return nil
			}}
			if stage == "resume" {
				m.resumeError = errors.New("resume")
			}
			err := startDomainBound(m, guard, "web", executionUUIDA, PolicyLeave, nil)
			if (err == nil) != (stage == "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			want := map[string]string{"success": "paused:A,resume:A", "before": "", "after": "paused:A,destroy:A", "resume": "paused:A,resume:A,destroy:A"}[stage]
			executionTrace(t, m, want)
			if stage != "before" && (len(m.flags) != 1 || m.flags[0] != uint32(golibvirt.DomainStartPaused)) {
				t.Fatal("not actually paused")
			}
		})
	}
}
