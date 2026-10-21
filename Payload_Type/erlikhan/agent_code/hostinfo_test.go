package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDispatchWhoami(t *testing.T) {
	resp, _ := dispatchAs(t, "whoami", "")
	if resp.Status != "success" || resp.UserOutput == "" {
		t.Fatalf("whoami: %+v", resp)
	}
	if u, err := user.Current(); err == nil && !strings.Contains(resp.UserOutput, u.Username) {
		t.Fatalf("whoami %q lacks %q", resp.UserOutput, u.Username)
	}
}

func TestDispatchEnv(t *testing.T) {
	t.Setenv("ERLIKHAN_PROBE", "probe-value")
	resp, _ := dispatchAs(t, "env", "")
	if resp.Status != "success" || !strings.Contains(resp.UserOutput, "ERLIKHAN_PROBE=probe-value") {
		t.Fatalf("env: %.200s", resp.UserOutput)
	}
}

func TestDispatchPwdCd(t *testing.T) {
	resp, _ := dispatchAs(t, "pwd", "")
	if resp.Status != "success" {
		t.Fatalf("pwd: %+v", resp)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if resp.UserOutput != cwd {
		t.Fatalf("pwd = %q, want %q", resp.UserOutput, cwd)
	}
	dir := t.TempDir()
	resp, _ = dispatchAs(t, "cd", `{"arguments":`+quoteForTest(dir)+`}`)
	if resp.Status != "success" {
		t.Fatalf("cd: %+v", resp)
	}
	// Restore for the rest of the suite.
	defer dispatchAs(t, "cd", `{"arguments":`+quoteForTest(cwd)+`}`)
	got, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("cwd = %q, want %q", got, dir)
	}
	resp, _ = dispatchAs(t, "cd", `{"arguments":`+quoteForTest(filepath.Join(dir, "missing"))+`}`)
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("cd missing should error, got %+v", resp)
	}
	resp, _ = dispatchAs(t, "cd", "")
	if !strings.Contains(resp.Status, "usage") {
		t.Fatalf("cd empty should show usage, got %+v", resp)
	}
}

func TestDispatchCpMv(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.txt")
	mkParams := func(a, b string) string {
		return `{"source":` + quoteForTest(a) + `,"destination":` + quoteForTest(b) + `}`
	}
	resp, _ := dispatchAs(t, "cp", mkParams(src, dst))
	if resp.Status != "success" {
		t.Fatalf("cp: %+v", resp)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "payload" {
		t.Fatal("copy differs")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("cp must keep the source")
	}
	// Hand-built arguments string also works.
	dst2 := filepath.Join(dir, "dst2.txt")
	resp, _ = dispatchAs(t, "cp", `{"arguments":`+quoteForTest(src+" "+dst2)+`}`)
	if resp.Status != "success" {
		t.Fatalf("cp args fallback: %+v", resp)
	}
	moved := filepath.Join(dir, "moved.txt")
	resp, _ = dispatchAs(t, "mv", mkParams(dst, moved))
	if resp.Status != "success" {
		t.Fatalf("mv: %+v", resp)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatal("mv result missing")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("mv must remove the source")
	}
	resp, _ = dispatchAs(t, "cp", mkParams(filepath.Join(dir, "missing"), dst))
	if !strings.HasPrefix(resp.Status, "error:") {
		t.Fatalf("cp missing should error, got %+v", resp)
	}
	resp, _ = dispatchAs(t, "mv", `{"source":"only"}`)
	if !strings.Contains(resp.Status, "usage") {
		t.Fatalf("mv partial should show usage, got %+v", resp)
	}
}

func TestDispatchIpconfig(t *testing.T) {
	resp, _ := dispatchAs(t, "ipconfig", "")
	if resp.Status != "success" || !strings.Contains(resp.UserOutput, "host: ") {
		t.Fatalf("ipconfig: %+v", resp)
	}
}

func TestDispatchUptime(t *testing.T) {
	resp, _ := dispatchAs(t, "uptime", "")
	if resp.Status != "success" || !strings.HasPrefix(resp.UserOutput, "uptime ") {
		t.Fatalf("uptime: %+v", resp)
	}
}

func TestFormatUptime(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m30s"},
		{60 * time.Second, "1m0s"},
		{3661 * time.Second, "1h1m1s"},
		{90061 * time.Second, "1d1h1m1s"},
		{-time.Second, "0s"},
	} {
		if got := formatUptime(tc.d); got != tc.want {
			t.Errorf("formatUptime(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestTwinPaths(t *testing.T) {
	src, dst, err := twinPaths("cp", `{"source": "a", "destination": "b"}`)
	if err != nil || src != "a" || dst != "b" {
		t.Fatalf("named: %q %q %v", src, dst, err)
	}
	src, dst, err = twinPaths("mv", `{"arguments": "a b"}`)
	if err != nil || src != "a" || dst != "b" {
		t.Fatalf("arguments: %q %q %v", src, dst, err)
	}
	if _, _, err := twinPaths("cp", `{"source": "a"}`); err == nil {
		t.Fatal("partial should fail")
	}
	if _, _, err := twinPaths("cp", "a b c"); err == nil {
		t.Fatal("three fields should fail")
	}
}
