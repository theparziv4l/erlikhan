package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestProcessesPayloadWire(t *testing.T) {
	procs := processesPayload([]ProcEntry{
		{PID: 4, PPID: 0, Name: "System", Arch: "x64", BinPath: `C:\Windows\System32\ntoskrnl.exe`, User: `NT AUTHORITY\SYSTEM`, IntegrityLevel: 0x4000, StartTime: 1700000000},
		{PID: 1234, PPID: 4, Name: "svchost.exe", Arch: "x64"},
	})
	raw, err := json.Marshal(map[string]any{"processes": procs})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"process_id":4`, `"parent_process_id":0`, `"architecture":"x64"`,
		`"bin_path":`, `"name":"svchost.exe"`, `"user":`, `"integrity_level":16384`, `"start_time":1700000000`} {
		if !strings.Contains(s, want) {
			t.Fatalf("wire missing %s: %s", want, s)
		}
	}
	if strings.Contains(s, "command_line") {
		t.Fatalf("empty optionals should omit: %s", s)
	}
}

func TestPsText(t *testing.T) {
	text := psText([]ProcEntry{{PID: 4, PPID: 0, Name: "System"}, {PID: 100, PPID: 4, Name: "smss.exe"}})
	if text != "4 0 System\n100 4 smss.exe\n" {
		t.Fatalf("text: %q", text)
	}
}

func TestParseKillArg(t *testing.T) {
	if pid, err := parseKillArg("1234"); err != nil || pid != 1234 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
	for _, bad := range []string{"", "abc", "0", "-1", "1.5"} {
		if _, err := parseKillArg(bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
}

func TestKillProcessErrors(t *testing.T) {
	if err := killProcess(-1); err == nil {
		t.Fatal("negative pid should fail")
	}
	if err := killProcess(999999999); err == nil {
		t.Fatal("missing pid should fail")
	}
}

func TestListProcessesPlatform(t *testing.T) {
	entries, err := listProcesses()
	if runtime.GOOS == "windows" {
		if err != nil || len(entries) == 0 {
			t.Fatalf("ps: %d entries, %v", len(entries), err)
		}
	} else if err == nil {
		t.Fatal("non-windows ps should fail")
	}
}

func TestAgentArch(t *testing.T) {
	if agentArch() == "" {
		t.Fatal("empty arch")
	}
}

func TestDispatchPsKill(t *testing.T) {
	if runtime.GOOS != "windows" {
		if resp, _ := dispatchAs(t, "ps", ""); !strings.HasPrefix(resp.Status, "error:") {
			t.Fatalf("ps off-windows should error, got %+v", resp)
		}
	}
	resp, _ := dispatchAs(t, "kill", `{"arguments":"abc"}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("kill abc should error, got %+v", resp)
	}
	// Killing a real child process proves the path end to end.
	if runtime.GOOS == "windows" {
		t.Skip("child kill covered by windows CI")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("sleep unavailable")
	}
	pid := cmd.Process.Pid
	resp, _ = dispatchAs(t, "kill", `{"arguments":"`+strconv.Itoa(pid)+`"}`)
	if resp.Status != "success" {
		cmd.Process.Kill()
		t.Fatalf("kill child: %+v", resp)
	}
	cmd.Wait()
	if err := cmd.Process.Signal(os.Signal(nil)); err == nil {
		t.Fatal("child should be dead")
	}
}
