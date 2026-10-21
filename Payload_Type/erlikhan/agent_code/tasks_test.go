package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

func TestDispatchLsShape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, _ := dispatchAs(t, "ls", `{"arguments":`+quoteForTest(dir)+`}`)
	if resp.Status != "success" || resp.FileBrowser == nil || resp.FileBrowser.Files == nil {
		t.Fatalf("ls: %+v", resp)
	}
	if len(*resp.FileBrowser.Files) != 1 || resp.FileBrowser.Name == "" {
		t.Fatalf("file_browser: %+v", resp.FileBrowser)
	}
	resp, _ = dispatchAs(t, "ls", `{"arguments":`+quoteForTest(filepath.Join(dir, "missing"))+`}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("ls missing should error, got %+v", resp)
	}
}

func TestDispatchDownloadErrors(t *testing.T) {
	// Missing file fails before any network use.
	resp, _ := dispatchAs(t, "download", `{"arguments":`+quoteForTest(filepath.Join(t.TempDir(), "missing"))+`}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("download missing should error, got %+v", resp)
	}
	old := includedCommands
	includedCommands = "shell"
	defer func() { includedCommands = old }()
	resp, _ = dispatchAs(t, "download", `{"arguments":"x"}`)
	if resp.Status != "error: command download not included in this build" {
		t.Fatalf("excluded download: %+v", resp)
	}
}

func TestDispatchUploadErrors(t *testing.T) {
	resp, _ := dispatchAs(t, "upload", `{"remote_path": "C:\\x"}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("upload without file should error, got %+v", resp)
	}
	resp, _ = dispatchAs(t, "upload", `{"file": "u"}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("upload without path should error, got %+v", resp)
	}
}

func TestDispatchRmMkdir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "newdir")
	resp, _ := dispatchAs(t, "mkdir", `{"arguments":`+quoteForTest(sub)+`}`)
	if resp.Status != "success" {
		t.Fatalf("mkdir: %+v", resp)
	}
	if st, err := os.Stat(sub); err != nil || !st.IsDir() {
		t.Fatal("dir not created")
	}
	resp, _ = dispatchAs(t, "rm", `{"arguments":`+quoteForTest(sub)+`}`)
	if resp.Status != "success" || resp.RemovedFiles == nil || len(*resp.RemovedFiles) != 1 {
		t.Fatalf("rm: %+v", resp)
	}
	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatal("dir not removed")
	}
	resp, _ = dispatchAs(t, "rm", `{"arguments":`+quoteForTest(sub)+`}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("rm missing should error, got %+v", resp)
	}
}

func TestRuntimeLoadUnload(t *testing.T) {
	old := includedCommands
	includedCommands = "shell,load,unload"
	defer func() { includedCommands = old }()
	if resp, _ := dispatchAs(t, "sleep", `{"arguments":"1"}`); resp.Status != "error: command sleep not included in this build" {
		t.Fatalf("sleep should start excluded: %+v", resp)
	}
	if resp, _ := dispatchAs(t, "load", `{"arguments":"sleep"}`); resp.Status != "success" {
		t.Fatalf("load: %+v", resp)
	}
	if resp, _ := dispatchAs(t, "sleep", `{"arguments":"1"}`); resp.Status != "success" {
		t.Fatalf("sleep after load: %+v", resp)
	}
	if resp, _ := dispatchAs(t, "unload", `{"arguments":"sleep"}`); resp.Status != "success" {
		t.Fatalf("unload: %+v", resp)
	}
	if resp, _ := dispatchAs(t, "sleep", `{"arguments":"1"}`); resp.Status != "error: command sleep not included in this build" {
		t.Fatalf("sleep after unload: %+v", resp)
	}
	if resp, _ := dispatchAs(t, "unload", `{"arguments":"exit"}`); !strings.Contains(resp.Status, "cannot unload") {
		t.Fatalf("unload exit: %+v", resp)
	}
	if resp, _ := dispatchAs(t, "load", `{"arguments":"nope"}`); !strings.Contains(resp.Status, "unknown command") {
		t.Fatalf("load unknown: %+v", resp)
	}
}

func checkArtifact(t *testing.T, resp Response, base, want string) {
	t.Helper()
	if resp.Artifacts == nil || len(*resp.Artifacts) != 1 {
		t.Fatalf("artifacts: %+v", resp.Artifacts)
	}
	got := (*resp.Artifacts)[0]
	if got.BaseArtifact != base || !strings.Contains(got.Artifact, want) {
		t.Fatalf("artifact: %+v", got)
	}
}

func TestArtifacts(t *testing.T) {
	resp, _ := dispatchAs(t, "shell", `{"arguments":"echo hi"}`)
	if resp.Status != "success" {
		t.Fatalf("shell: %+v", resp)
	}
	checkArtifact(t, resp, "Process Create", "cmd.exe /c echo hi")
	path := filepath.Join(t.TempDir(), "gone.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, _ = dispatchAs(t, "rm", `{"arguments":`+quoteForTest(path)+`}`)
	if resp.Status != "success" {
		t.Fatalf("rm: %+v", resp)
	}
	checkArtifact(t, resp, "File Delete", "gone.txt")
	if runtime.GOOS == "windows" {
		t.Skip("child kill covered by windows CI")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("sleep unavailable")
	}
	resp, _ = dispatchAs(t, "kill", `{"arguments":"`+strconv.Itoa(cmd.Process.Pid)+`"}`)
	if resp.Status != "success" {
		cmd.Process.Kill()
		t.Fatalf("kill: %+v", resp)
	}
	checkArtifact(t, resp, "Process Kill", "pid ")
	cmd.Wait()
}
