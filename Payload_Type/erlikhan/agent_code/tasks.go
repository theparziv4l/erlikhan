package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// commandEntry is one row of the dispatch table. To add a command, add a
// row plus a handler here, register it in the container commandSpecs and
// add it to the C table in agent_code_c/tasks.c.
type commandEntry struct {
	name string
	run  func(a *Agent, arg string) (output, status string, exit bool)
}

var commandTable = []commandEntry{
	{name: "shell", run: handleShell},
	{name: "powershell", run: handlePowershell},
	{name: "sleep", run: handleSleep},
	{name: "ls", run: handleLs},
	{name: "exit", run: handleExit},
}

// dispatch runs one task and reports whether the agent must exit afterwards.
func (a *Agent) dispatch(t Task) (Response, bool) {
	resp := Response{TaskID: t.ID, Completed: true, Status: "success"}
	entry := findCommand(t.Command)
	if entry == nil {
		resp.Status = "error: unknown command " + t.Command
		resp.UserOutput = resp.Status
		return resp, false
	}
	if !commandAllowed(t.Command) {
		resp.Status = "error: command " + t.Command + " not included in this build"
		resp.UserOutput = resp.Status
		return resp, false
	}
	out, status, exit := entry.run(a, taskArg(t.Parameters))
	resp.UserOutput, resp.Status = out, status
	return resp, exit
}

func findCommand(name string) *commandEntry {
	for i := range commandTable {
		if commandTable[i].name == name {
			return &commandTable[i]
		}
	}
	return nil
}

// commandAllowed reports whether name is in the build-time command list.
// An empty list (offline builds without -X) allows everything.
func commandAllowed(name string) bool {
	if strings.TrimSpace(includedCommands) == "" {
		return true
	}
	for _, c := range strings.Split(includedCommands, ",") {
		if strings.TrimSpace(c) == name {
			return true
		}
	}
	return false
}

func handleShell(_ *Agent, arg string) (string, string, bool) {
	out, err := runShell(arg)
	if err != nil {
		return out, "error: " + err.Error(), false
	}
	return out, "success", false
}

func handlePowershell(_ *Agent, arg string) (string, string, bool) {
	out, err := runPowershell(arg)
	if err != nil {
		return out, "error: " + err.Error(), false
	}
	return out, "success", false
}

func handleSleep(a *Agent, arg string) (string, string, bool) {
	interval, jitter, err := parseSleep(arg)
	if err != nil {
		return err.Error(), "error: " + err.Error(), false
	}
	a.interval, a.jitter = interval, jitter
	return fmt.Sprintf("sleep set to %ds jitter %d%%", interval, jitter), "success", false
}

func handleLs(_ *Agent, arg string) (string, string, bool) {
	out, err := runLs(arg)
	if err != nil {
		return "", "error: " + err.Error(), false
	}
	return out, "success", false
}

func handleExit(_ *Agent, _ string) (string, string, bool) {
	return "exiting", "success", true
}

// runLs lists one directory, one entry per line ("name/" for subdirs).
func runLs(arg string) (string, error) {
	dir := strings.TrimSpace(arg)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Name())
		if e.IsDir() {
			b.WriteString("/")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func runShell(arg string) (string, error) {
	name, flag := "cmd.exe", "/c"
	if runtime.GOOS != "windows" {
		name, flag = "sh", "-c"
	}
	return runCmd(name, flag, arg)
}

func runPowershell(arg string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("powershell needs Windows")
	}
	return runCmd("powershell.exe", "/c", arg)
}

func runCmd(name, flag, arg string) (string, error) {
	cmd := exec.Command(name, flag, arg)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// parseSleep reads "interval [jitter]" in seconds, e.g. "60 10".
func parseSleep(arg string) (int, int, error) {
	fields := strings.Fields(arg)
	if len(fields) == 0 || len(fields) > 2 {
		return 0, 0, fmt.Errorf("usage: sleep <interval> [jitter]")
	}
	interval, err := strconv.Atoi(fields[0])
	if err != nil || interval < 0 {
		return 0, 0, fmt.Errorf("bad interval %q", fields[0])
	}
	jitter := 0
	if len(fields) == 2 {
		jitter, err = strconv.Atoi(fields[1])
		if err != nil || jitter < 0 || jitter > 100 {
			return 0, 0, fmt.Errorf("bad jitter %q", fields[1])
		}
	}
	return interval, jitter, nil
}

// sleepTime mirrors Thanatos: interval plus/minus jitter percent.
func sleepTime(interval, jitter int) time.Duration {
	if interval <= 0 {
		return 0
	}
	if jitter <= 0 {
		return time.Duration(interval) * time.Second
	}
	delta := interval * jitter / 100
	low := interval - delta
	if low < 0 {
		low = 0
	}
	n := low
	if span := interval + delta - low; span > 0 {
		n = low + rand.Intn(span+1) //nolint:gosec // jitter needs no CSPRNG
	}
	return time.Duration(n) * time.Second
}
