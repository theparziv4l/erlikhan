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
	ls := findCommand(t, cmds, "ls")
	if ls.CommandAttributes.CommandIsBuiltin {
		t.Error("ls must not be builtin (operators should be able to remove it)")
	}
	if !ls.CommandAttributes.CommandIsSuggested {
		t.Error("ls should be suggested (pre-selected) for new payloads")
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

	final, added, err = resolveCommandList([]string{"ls", "ls", "shell", "powershell", "sleep", "exit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 5 {
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
