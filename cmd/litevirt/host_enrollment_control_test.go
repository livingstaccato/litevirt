package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestEnrollmentControlCommandIsHiddenAndFixed(t *testing.T) {
	root := newRootCmd()
	command, _, err := root.Find([]string{"host-enroll-control", "rollback"})
	if err != nil || command == root || command.Name() != "host-enroll-control" || !command.Hidden {
		t.Fatalf("RED_ENROLLMENT_CONTROL_COMMAND: fixed hidden command missing: %v", err)
	}
	var help bytes.Buffer
	root.SetOut(&help)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(help.String(), "host-enroll-control") {
		t.Fatal("private control appeared in public help")
	}
	if os.Geteuid() == 0 {
		t.Skip("valid root execution requires separately mapped privileged fixture")
	}
	for _, purpose := range []string{"rollback", "launcher", "worker"} {
		t.Run(purpose, func(t *testing.T) {
			command := newRootCmd()
			command.SetArgs([]string{"host-enroll-control", purpose})
			if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "requires root") {
				t.Fatalf("fixed purpose escaped actual root gate: %v", err)
			}
		})
	}
}

func TestEnrollmentControlCommandRejectsOtherPurposes(t *testing.T) {
	for _, arguments := range [][]string{{}, {"exec"}, {"prepare"}, {"apparmor"}, {"/bin/sh"}, {"rollback", "/tmp/other"}, {"worker", "--path=/tmp"}, {"--root=/tmp", "rollback"}} {
		t.Run(strings.Join(arguments, ":"), func(t *testing.T) {
			command := newRootCmd()
			command.SetArgs(append([]string{"host-enroll-control"}, arguments...))
			if err := command.Execute(); err == nil {
				t.Fatal("control command accepted an arbitrary purpose, path or extra argument")
			} else if len(arguments) == 1 && !strings.Contains(err.Error(), "unsupported enrollment control purpose") {
				t.Fatalf("RED_ENROLLMENT_CONTROL_COMMAND: fixed purpose gate was not reached: %v", err)
			}
		})
	}
}
