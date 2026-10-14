package libvirt

import (
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

func TestJobErrmsg(t *testing.T) {
	str := func(f, v string) golibvirt.TypedParam {
		return golibvirt.TypedParam{Field: f, Value: *golibvirt.NewTypedParamValueString(v)}
	}
	if got := jobErrmsg(nil); got != "" {
		t.Errorf("no params: %q", got)
	}
	params := []golibvirt.TypedParam{str("operation", "backup"), str(golibvirt.DomainJobErrmsg, " Input/output error \n")}
	if got := jobErrmsg(params); got != "Input/output error" {
		t.Errorf("errmsg = %q", got)
	}
	if got := jobErrmsg([]golibvirt.TypedParam{str("operation", "backup")}); got != "" {
		t.Errorf("no errmsg param: %q", got)
	}
}

func TestDiskErrorsCause(t *testing.T) {
	if got := diskErrorsCause(nil, 0); got != "" {
		t.Errorf("none: %q", got)
	}
	if got := diskErrorsCause([]golibvirt.DomainDiskError{{Disk: "vda"}, {Disk: "vdb"}}, 2); got != "libvirt reports an I/O error on disk vda, vdb" {
		t.Errorf("two disks: %q", got)
	}
	if got := diskErrorsCause([]golibvirt.DomainDiskError{{Disk: "vda"}}, 0); got != "" {
		t.Errorf("n=0: %q", got)
	}
}
