package main

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestCloneOpenSSHUsesGit(t *testing.T) {
	const repo = "https://github.com/openssh/openssh-portable.git"
	const target = "openssh-portable"
	var gotName string
	var gotArgs []string

	orig := runCommand
	runCommand = func(name string, args ...string) error {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return nil
	}
	t.Cleanup(func() { runCommand = orig })

	if err := cloneOpenSSH(target); err != nil {
		t.Fatalf("cloneOpenSSH: %v", err)
	}

	wantArgs := []string{"clone", "--depth=1", repo, target}
	if gotName != "git" {
		t.Fatalf("expected git command, got %q", gotName)
	}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args mismatch: got %v, want %v", gotArgs, wantArgs)
	}
}

func TestCloneOpenSSHReturnsError(t *testing.T) {
	orig := runCommand
	runCommand = func(name string, args ...string) error {
		return exec.ErrNotFound
	}
	t.Cleanup(func() { runCommand = orig })

	err := cloneOpenSSH("openssh-portable")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "git clone") {
		t.Fatalf("expected git clone prefix, got %v", err)
	}
}
