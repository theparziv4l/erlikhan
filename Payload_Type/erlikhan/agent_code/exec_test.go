package main

import (
	"os"
	"strings"
	"testing"
)

func TestDispatchExecuteAssemblyErrors(t *testing.T) {
	resp, _ := dispatchAs(t, "execute_assembly", `{"assembly_arguments": "x"}`)
	if !strings.Contains(resp.Status, "no assembly file id") {
		t.Fatalf("missing file: %+v", resp)
	}
}

func TestDispatchExecuteAssemblyNeedsWindows(t *testing.T) {
	content := []byte("fake-assembly-bytes")
	fake := &fakeUploadMythic{content: content, wantID: "uuid-asm"}
	a := &Agent{post: fake.post}
	resp, _ := a.dispatch(Task{
		Command:    "execute_assembly",
		Parameters: `{"assembly_file": "uuid-asm", "assembly_arguments": "--a 1"}`,
		ID:         "t-asm",
	})
	// Off Windows the fetch succeeds but the CLR host refuses.
	if !strings.Contains(resp.Status, "needs Windows") {
		t.Fatalf("windows gate: %+v", resp)
	}
}

func TestDispatchExecuteAssemblyStaging(t *testing.T) {
	content := []byte(strings.Repeat("A", 100))
	fake := &fakeUploadMythic{content: content, wantID: "uuid-asm2"}
	var gotPath, gotArgs string
	var gotBytes []byte
	old := runAssembly
	runAssembly = func(path, args string) (string, error) {
		gotPath, gotArgs = path, args
		var err error
		gotBytes, err = os.ReadFile(path)
		if err != nil {
			t.Errorf("staged file unreadable: %v", err)
		}
		return "asm-output", nil
	}
	defer func() { runAssembly = old }()
	a := &Agent{post: fake.post}
	resp, _ := a.dispatch(Task{
		Command:    "execute_assembly",
		Parameters: `{"assembly_file": "uuid-asm2", "assembly_arguments": "a b"}`,
		ID:         "t-asm2",
	})
	if resp.Status != "success" || resp.UserOutput != "asm-output" {
		t.Fatalf("staged run: %+v", resp)
	}
	if string(gotBytes) != string(content) || gotArgs != "a b" {
		t.Fatalf("staged bytes/args: %d bytes %q", len(gotBytes), gotArgs)
	}
	if _, err := os.Stat(gotPath); !os.IsNotExist(err) {
		t.Fatalf("staged file %s not cleaned up", gotPath)
	}
	checkArtifact(t, resp, "Process Create", "execute_assembly")
}

func TestDispatchExecuteCoffErrors(t *testing.T) {
	resp, _ := dispatchAs(t, "execute_coff", `{"function_name": "go"}`)
	if !strings.Contains(resp.Status, "no bof file id") {
		t.Fatalf("missing file: %+v", resp)
	}
	resp, _ = dispatchAs(t, "execute_coff", `{"bof_file": "u", "coff_arguments": "zz"}`)
	if !strings.Contains(resp.Status, "bad coff_arguments") {
		t.Fatalf("bad hex: %+v", resp)
	}
	resp, _ = dispatchAs(t, "execute_coff", `{"bof_file": "u", "coff_arguments": "02000000ffff00"}`)
	if !strings.Contains(resp.Status, "bad coff_arguments") {
		t.Fatalf("total mismatch: %+v", resp)
	}
}

func TestDispatchExecuteCoffStaging(t *testing.T) {
	fake := &fakeUploadMythic{content: bofFixture, wantID: "uuid-bof"}
	var gotObj []byte
	var gotEntry string
	var gotArgs []byte
	var gotTimeout int
	old := runCoff
	runCoff = func(obj []byte, entry string, args []byte, timeout int) (string, error) {
		gotObj, gotEntry, gotArgs, gotTimeout = obj, entry, args, timeout
		return "bof-output", nil
	}
	defer func() { runCoff = old }()
	a := &Agent{post: fake.post}
	resp, _ := a.dispatch(Task{
		Command: "execute_coff",
		Parameters: `{"bof_file": "uuid-bof", "function_name": "run", "timeout": 7, ` +
			`"coff_arguments": "0b0000002a00000003000000686900"}`,
		ID: "t-bof",
	})
	if resp.Status != "success" || resp.UserOutput != "bof-output" {
		t.Fatalf("staged run: %+v", resp)
	}
	if string(gotObj) != string(bofFixture) {
		t.Fatal("fetched object differs")
	}
	if gotEntry != "run" || gotTimeout != 7 {
		t.Fatalf("entry/timeout: %q %d", gotEntry, gotTimeout)
	}
	if len(gotArgs) != 15 || gotArgs[4] != 42 {
		t.Fatalf("args buffer: %x", gotArgs)
	}
	checkArtifact(t, resp, "Process Create", "execute_coff")
	// Defaults: entrypoint go, timeout 30.
	resp, _ = a.dispatch(Task{
		Command: "execute_coff", Parameters: `{"bof_file": "uuid-bof"}`, ID: "t-bof2",
	})
	if resp.Status != "success" {
		t.Fatalf("defaults run: %+v", resp)
	}
	if gotEntry != "go" || gotTimeout != 30 || len(gotArgs) != 4 {
		t.Fatalf("defaults: %q %d %d bytes", gotEntry, gotTimeout, len(gotArgs))
	}
}

func TestDispatchExecuteCoffTooLarge(t *testing.T) {
	big := make([]byte, maxCoffBytes+1)
	fake := &fakeUploadMythic{content: big, wantID: "uuid-big"}
	a := &Agent{post: fake.post}
	resp, _ := a.dispatch(Task{
		Command: "execute_coff", Parameters: `{"bof_file": "uuid-big"}`, ID: "t-big",
	})
	if !strings.Contains(resp.Status, "too large") {
		t.Fatalf("oversize: %+v", resp)
	}
}

func TestFetchMythicFile(t *testing.T) {
	content := []byte(strings.Repeat("0123456789", 100))
	fake := &fakeUploadMythic{content: content, wantID: "uuid-f"}
	var buf strings.Builder
	written, chunks, err := fetchMythicFile("t-f", "uuid-f", 300, fake.post, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len(content)) || chunks != 4 {
		t.Fatalf("fetch: %d bytes %d chunks", written, chunks)
	}
	if buf.String() != string(content) {
		t.Fatal("fetched bytes differ")
	}
	if _, _, err := fetchMythicFile("t-f", "", 300, fake.post, &buf); err == nil {
		t.Fatal("missing file id should fail")
	}
	for _, n := range fake.nums {
		if n < 1 || n > 4 {
			t.Fatalf("chunk numbering: %v", fake.nums)
		}
	}
}
