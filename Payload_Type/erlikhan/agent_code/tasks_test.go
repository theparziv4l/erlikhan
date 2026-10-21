package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dispatchAs(t *testing.T, command, parameters string) (Response, bool) {
	t.Helper()
	return (&Agent{}).dispatch(Task{Command: command, Parameters: parameters, ID: "1"})
}

func TestDispatchSleep(t *testing.T) {
	a := &Agent{}
	resp, exit := a.dispatch(Task{Command: "sleep", Parameters: `{"arguments":"30 10"}`, ID: "1"})
	if exit || resp.Status != "success" {
		t.Fatalf("sleep: %+v exit=%v", resp, exit)
	}
	if a.interval != 30 || a.jitter != 10 {
		t.Fatalf("interval/jitter = %d/%d", a.interval, a.jitter)
	}
	resp, _ = a.dispatch(Task{Command: "sleep", Parameters: `{"arguments":"nope"}`, ID: "2"})
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("bad sleep should error, got %+v", resp)
	}
}

func TestDispatchExit(t *testing.T) {
	resp, exit := dispatchAs(t, "exit", "")
	if !exit || resp.UserOutput != "exiting" {
		t.Fatalf("exit: %+v exit=%v", resp, exit)
	}
}

func TestDispatchUnknown(t *testing.T) {
	resp, exit := dispatchAs(t, "rm-rf", "")
	if exit || resp.Status != "error: unknown command rm-rf" {
		t.Fatalf("unknown: %+v exit=%v", resp, exit)
	}
}

func TestDispatchNotIncluded(t *testing.T) {
	old := includedCommands
	includedCommands = "shell,exit"
	defer func() { includedCommands = old }()
	resp, exit := dispatchAs(t, "sleep", `{"arguments":"1"}`)
	if exit || resp.Status != "error: command sleep not included in this build" {
		t.Fatalf("excluded: %+v exit=%v", resp, exit)
	}
	if resp, _ := dispatchAs(t, "exit", ""); resp.Status != "success" {
		t.Fatalf("included command should still run: %+v", resp)
	}
	// Empty selection means all commands (offline builds without -X).
	includedCommands = ""
	if resp, _ := dispatchAs(t, "sleep", `{"arguments":"1"}`); resp.Status != "success" {
		t.Fatalf("empty selection should allow all: %+v", resp)
	}
}

func TestDispatchLs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	resp, exit := dispatchAs(t, "ls", `{"arguments":`+quoteForTest(dir)+`}`)
	if exit || resp.Status != "success" {
		t.Fatalf("ls: %+v exit=%v", resp, exit)
	}
	if !strings.Contains(resp.UserOutput, "a.txt") || !strings.Contains(resp.UserOutput, "sub/") {
		t.Fatalf("ls output missing entries: %q", resp.UserOutput)
	}
	resp, _ = dispatchAs(t, "ls", `{"arguments":`+quoteForTest(filepath.Join(dir, "missing"))+`}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("ls of missing dir should error, got %+v", resp)
	}
}

func quoteForTest(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
