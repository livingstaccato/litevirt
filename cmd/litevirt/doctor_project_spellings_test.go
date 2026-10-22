package main

import (
	"reflect"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestMultiSpelledProjects(t *testing.T) {
	got := multiSpelledProjects([]*pb.Project{
		{Name: "_default"}, {Name: "/acme"}, {Name: "acme"}, {Name: "/solo"}, {Name: "/a/b"}, {Name: "a/b/"},
	})
	want := map[string][]string{"/acme": {"/acme", "acme"}, "/a/b": {"/a/b", "a/b/"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multiSpelledProjects = %v, want %v", got, want)
	}
}
