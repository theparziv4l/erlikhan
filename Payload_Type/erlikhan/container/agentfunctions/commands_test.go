package agentfunctions

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func registeredCommands(t *testing.T) []agentstructs.Command {
	t.Helper()
	cmds := agentstructs.AllPayloadData.Get("erlikhan").GetCommands()
	if len(cmds) == 0 {
		t.Fatal("no commands registered for erlikhan")
	}
	return cmds
}

func findCommand(t *testing.T, cmds []agentstructs.Command, name string) agentstructs.Command {
	t.Helper()
	for _, c := range cmds {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("command %q not registered (have %v)", name, AllCommandNames())
	return agentstructs.Command{}
}

// TestExitCommandRecognized guards the callbacks-table "Exit Callback" action:
// Mythic resolves it through supported_ui_features == "callback_table:exit".
func TestExitCommandRecognized(t *testing.T) {
	exit := findCommand(t, registeredCommands(t), "exit")
	for _, f := range exit.SupportedUIFeatures {
		if f == "callback_table:exit" {
			return
		}
	}
	t.Fatalf("exit lacks callback_table:exit UI feature (have %v)", exit.SupportedUIFeatures)
}

func TestCoreCommandsAreBuiltin(t *testing.T) {
	cmds := registeredCommands(t)
	for _, name := range []string{"shell", "powershell", "sleep", "exit"} {
		if c := findCommand(t, cmds, name); !c.CommandAttributes.CommandIsBuiltin {
			t.Errorf("core command %q must be builtin", name)
		}
	}
}

func TestOptionalCommandsAreSelectable(t *testing.T) {
	cmds := registeredCommands(t)
	for _, tc := range []struct {
		name       string
		uiFeatures []string
	}{
		{"ls", []string{"file_browser:list"}},
		{"download", []string{"file_browser:download"}},
		{"upload", []string{"file_browser:upload"}},
		{"rm", []string{"file_browser:remove"}},
		{"mkdir", nil},
		{"ps", []string{"process_browser:list"}},
		{"kill", []string{"kill", "process_browser:kill"}},
		{"load", nil},
		{"unload", nil},
	} {
		c := findCommand(t, cmds, tc.name)
		if c.CommandAttributes.CommandIsBuiltin {
			t.Errorf("%s must not be builtin (operators should be able to remove it)", tc.name)
		}
		if !c.CommandAttributes.CommandIsSuggested {
			t.Errorf("%s should be suggested (pre-selected) for new payloads", tc.name)
		}
		for _, want := range tc.uiFeatures {
			found := false
			for _, f := range c.SupportedUIFeatures {
				if f == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s lacks UI feature %q (have %v)", tc.name, want, c.SupportedUIFeatures)
			}
		}
	}
}

func TestLoadTarget(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "ls"})
	name, err := loadTarget(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 1}, Args: *args,
	})
	if err != nil || name != "ls" {
		t.Fatalf("target: %q %v", name, err)
	}
	args = &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "nope"})
	if _, err := loadTarget(&agentstructs.PTTaskMessageAllData{Args: *args}); err == nil {
		t.Fatal("unknown command should fail")
	}
	if _, err := loadTarget(&agentstructs.PTTaskMessageAllData{}); err == nil {
		t.Fatal("missing arg should fail")
	}
}

func TestUnloadProtection(t *testing.T) {
	for _, p := range []string{"exit", "load", "unload"} {
		if !isProtected(p) {
			t.Errorf("%s should be protected", p)
		}
	}
	for _, ok := range []string{"shell", "ls", "ps"} {
		if isProtected(ok) {
			t.Errorf("%s should not be protected", ok)
		}
	}
	if !knownCommand("sleep") || knownCommand("nope") {
		t.Fatal("knownCommand wrong")
	}
}

func TestKillParse(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	if err := killLine(args, "1234"); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "arguments"); got != "1234" {
		t.Fatalf("pid = %q", got)
	}
	for _, bad := range []string{"", "abc", "0", "-4", "12x"} {
		if err := killLine(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
	args = &agentstructs.PTTaskMessageArgsData{}
	err := killDict(args, map[string]any{"host": "H", "process_id": float64(5678), "architecture": "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "arguments"); got != "5678" {
		t.Fatalf("pid = %q", got)
	}
	args = &agentstructs.PTTaskMessageArgsData{}
	if err := killDict(args, map[string]any{"host": "H", "process_id": "4321"}); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "arguments"); got != "4321" {
		t.Fatalf("pid = %q", got)
	}
	if err := killDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{}); err == nil {
		t.Fatal("missing pid should fail")
	}
}

func TestPayloadSupportsDynamicLoading(t *testing.T) {
	if !payloadDefinition.SupportsDynamicLoading {
		t.Fatal("payload must set SupportsDynamicLoading so operators can add/remove commands")
	}
}

func TestRegisteredMatchesSpecs(t *testing.T) {
	cmds := registeredCommands(t)
	if len(cmds) != len(commandSpecs) {
		t.Fatalf("registered %d commands, specs list %d", len(cmds), len(commandSpecs))
	}
	seen := map[string]bool{}
	for _, c := range cmds {
		seen[c.Name] = true
	}
	for _, name := range AllCommandNames() {
		if !seen[name] {
			t.Errorf("spec command %q not registered", name)
		}
	}
}

func TestResolveCommandList(t *testing.T) {
	all := AllCommandNames()
	final, added, err := resolveCommandList(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(final, ",") != strings.Join(all, ",") {
		t.Fatalf("empty input should default to all commands, got %v", final)
	}
	if len(added) != 0 {
		t.Fatalf("default selection should not report added commands, got %v", added)
	}

	final, added, err = resolveCommandList([]string{"ls"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shell", "powershell", "sleep", "exit", "ls"} {
		found := false
		for _, got := range final {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("resolved list %v missing %q", final, want)
		}
	}
	if len(added) != 4 {
		t.Errorf("expected 4 auto-added core commands, got %v", added)
	}

	dupes := append([]string{"ls"}, all...)
	final, added, err = resolveCommandList(dupes)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != len(all) {
		t.Errorf("duplicates should collapse, got %v", final)
	}
	if len(added) != 0 {
		t.Errorf("complete selection should add nothing, got %v", added)
	}

	if _, _, err = resolveCommandList([]string{"shell", "rm-rf"}); err == nil ||
		!strings.Contains(err.Error(), "rm-rf") {
		t.Fatalf("unknown command should fail naming it, got %v", err)
	}
}

// TestCommandLayersAgree keeps the three command implementations in sync:
// the container specs, the Go agent dispatch table and the C agent
// dispatch table. Add a command to all three or this fails naming the gap.
func TestCommandLayersAgree(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(thisFile)
	goSrc, err := os.ReadFile(filepath.Join(root, "..", "..", "agent_code", "tasks.go"))
	if err != nil {
		t.Fatal(err)
	}
	cSrc, err := os.ReadFile(filepath.Join(root, "..", "..", "agent_code_c", "tasks.c"))
	if err != nil {
		t.Fatal(err)
	}
	want := AllCommandNames()
	for _, tc := range []struct {
		layer string
		src   string
		block string
		end   string
		re    *regexp.Regexp
	}{
		{"go", string(goSrc), "commandTable = []commandEntry{", "\n}",
			regexp.MustCompile(`\{\s*name:\s*"([a-z0-9_]+)"`)},
		{"c", string(cSrc), "task_table[] = {", "};",
			regexp.MustCompile(`\{\s*"([a-z0-9_]+)"\s*,`)},
	} {
		got := extractTableNames(t, tc.layer, tc.src, tc.block, tc.end, tc.re)
		if strings.Join(got, ",") != strings.Join(sortedCopy(want), ",") {
			t.Errorf("%s layer commands %v disagree with container %v", tc.layer, got, want)
		}
	}
}

func extractTableNames(t *testing.T, layer, src, block, endMark string, re *regexp.Regexp) []string {
	t.Helper()
	start := strings.Index(src, block)
	if start < 0 {
		t.Fatalf("%s dispatch table %q not found", layer, block)
	}
	rest := src[start:]
	end := strings.Index(rest, endMark)
	if end < 0 {
		t.Fatalf("%s dispatch table unterminated", layer)
	}
	var names []string
	for _, m := range re.FindAllStringSubmatch(rest[:end], -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatalf("%s dispatch table holds no commands", layer)
	}
	return sortedCopy(names)
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func stringArg(t *testing.T, args *agentstructs.PTTaskMessageArgsData, name string) string {
	t.Helper()
	v, err := args.GetStringArg(name)
	if err != nil {
		t.Fatalf("arg %q: %v", name, err)
	}
	return v
}

func TestFbPathDict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input map[string]any
		want  string
	}{
		{"full path wins", map[string]any{"path": "C:\\a", "full_path": "C:\\a\\b", "file": "c"}, "C:\\a\\b"},
		{"path fallback", map[string]any{"path": "C:\\a"}, "C:\\a"},
		{"file fallback", map[string]any{"file": "c", "host": "H"}, "c"},
		{"plain arguments", map[string]any{"arguments": "C:\\x"}, "C:\\x"},
		{"plain path", map[string]any{"path": "C:\\x"}, "C:\\x"},
		{"empty", map[string]any{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &agentstructs.PTTaskMessageArgsData{}
			if err := fbPathDict(args, tc.input); err != nil {
				t.Fatal(err)
			}
			if got := stringArg(t, args, "arguments"); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUploadDict(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	err := uploadDict(args, map[string]any{"file": "uuid-1", "remote_path": "C:\\x\\a.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "remote_path"); got != "C:\\x\\a.bin" {
		t.Fatalf("remote_path = %q", got)
	}
	fileID, err := args.GetFileArg("file")
	if err != nil || fileID != "uuid-1" {
		t.Fatalf("file = %q, err %v", fileID, err)
	}
	// Browser context supplies the remote path.
	args = &agentstructs.PTTaskMessageArgsData{}
	if err := uploadDict(args, map[string]any{"file": "uuid-2", "full_path": "C:\\drop"}); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "remote_path"); got != "C:\\drop" {
		t.Fatalf("remote_path = %q", got)
	}
	// No file chosen.
	if err := uploadDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{"remote_path": "x"}); err == nil {
		t.Fatal("missing file should fail")
	}
}

func TestUploadLine(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	err := uploadLine(args, `{"remote_path": "C:\\x", "file": "uuid-3"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "remote_path"); got != "C:\\x" {
		t.Fatalf("remote_path = %q", got)
	}
	if _, err := args.GetFileArg("file"); err != nil {
		t.Fatalf("file: %v", err)
	}
	for _, bad := range []string{"", "C:\\x", `{"remote_path": "C:\\x"}`, "{nope"} {
		if err := uploadLine(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
}

func TestUploadTask(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "remote_path",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "C:\\x"})
	args.AddArg(agentstructs.CommandParameter{Name: "file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE, DefaultValue: "uuid-4"})
	resp := uploadTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 7}, Args: *args,
	})
	if !resp.Success || resp.TaskID != 7 {
		t.Fatalf("upload task: %+v", resp)
	}
	if resp.DisplayParams == nil || *resp.DisplayParams != "C:\\x" {
		t.Fatalf("display params: %+v", resp.DisplayParams)
	}
	resp = uploadTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 8},
	})
	if resp.Success {
		t.Fatal("missing args should fail")
	}
}
