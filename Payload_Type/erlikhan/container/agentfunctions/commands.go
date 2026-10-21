package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/mitchellh/mapstructure"
)

// stringDict decodes UI modal input {"arguments": "..."} into task args.
func stringDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var decoded struct {
		Arguments string `mapstructure:"arguments"`
	}
	if err := mapstructure.Decode(input, &decoded); err != nil {
		logging.LogError(err, "Failed to decode arguments")
		return err
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  decoded.Arguments,
	})
	return nil
}

func stringLine(args *agentstructs.PTTaskMessageArgsData, input string) error {
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  input,
	})
	return nil
}

// passthroughTask forwards args to the agent untouched; the agent parses
// the parameters string itself.
func passthroughTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	if params, err := taskData.Args.GetStringArg("arguments"); err != nil {
		logging.LogError(err, "Failed to get arguments")
		response.Error, response.Success = err.Error(), false
	} else {
		response.DisplayParams = &params
	}
	return response
}

func noArgsTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	return agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
}

func noArgsParse(args *agentstructs.PTTaskMessageArgsData, input string) error { return nil }

func noArgsParseDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	return nil
}

// commandSpec is the container-side definition of one agent command.
// To add a command: append a row here, add a handler to the dispatch
// tables in agent_code/tasks.go and agent_code_c/tasks.c, then run
// TestCommandLayersAgree. Builtin commands are always compiled into the
// payload; the rest can be added or removed per payload build.
type commandSpec struct {
	name        string
	help        string
	description string
	mitre       []string
	uiFeatures  []string
	builtin     bool
	suggested   bool
	noArgs      bool
}

var commandSpecs = []commandSpec{
	{name: "shell", help: "shell <command>", description: "shell <command> (cmd.exe /c)",
		mitre: []string{"T1059"}, builtin: true},
	{name: "powershell", help: "powershell <command>", description: "powershell <command> (powershell.exe /c)",
		mitre: []string{"T1059.001"}, builtin: true},
	{name: "sleep", help: "sleep <interval> [jitter]",
		description: "sleep <interval> [jitter] (seconds, jitter percent)", builtin: true},
	{name: "ls", help: "ls [path]", description: "ls [path] (list directory)",
		mitre: []string{"T1083"}, suggested: true},
	{name: "exit", help: "exit", description: "exit the agent",
		uiFeatures: []string{"callback_table:exit"}, builtin: true, noArgs: true},
}

// AllCommandNames lists every command the agent implements, in spec order.
func AllCommandNames() []string {
	names := make([]string, 0, len(commandSpecs))
	for _, s := range commandSpecs {
		names = append(names, s.name)
	}
	return names
}

// resolveCommandList validates the operator's command selection: unknown
// names fail the build, and missing builtin (core) commands are appended.
// An empty selection means every known command. It returns the final list
// plus the core commands that were added back.
func resolveCommandList(input []string) (final, added []string, err error) {
	known := map[string]bool{}
	for _, s := range commandSpecs {
		known[s.name] = true
	}
	if len(input) == 0 {
		return AllCommandNames(), nil, nil
	}
	seen := map[string]bool{}
	for _, name := range input {
		if !known[name] {
			return nil, nil, fmt.Errorf("unknown command %q", name)
		}
		if !seen[name] {
			seen[name] = true
			final = append(final, name)
		}
	}
	for _, s := range commandSpecs {
		if s.builtin && !seen[s.name] {
			final = append(final, s.name)
			added = append(added, s.name)
		}
	}
	return final, added, nil
}

func (s commandSpec) register() {
	mitre := s.mitre
	if mitre == nil {
		mitre = []string{}
	}
	uiFeatures := s.uiFeatures
	if uiFeatures == nil {
		uiFeatures = []string{}
	}
	cmd := agentstructs.Command{
		Name:                s.name,
		HelpString:          s.help,
		Description:         s.description,
		Version:             1,
		SupportedUIFeatures: uiFeatures,
		MitreAttackMappings: mitre,
		Author:              "erlikhan",
		CommandAttributes: agentstructs.CommandAttribute{
			CommandIsBuiltin:   s.builtin,
			CommandIsSuggested: s.suggested,
		},
	}
	if s.noArgs {
		cmd.TaskFunctionCreateTasking = noArgsTask
		cmd.TaskFunctionParseArgString = noArgsParse
		cmd.TaskFunctionParseArgDictionary = noArgsParseDict
	} else {
		cmd.TaskFunctionCreateTasking = passthroughTask
		cmd.TaskFunctionParseArgString = stringLine
		cmd.TaskFunctionParseArgDictionary = stringDict
	}
	agentstructs.AllPayloadData.Get("erlikhan").AddCommand(cmd)
}

func init() {
	for _, s := range commandSpecs {
		s.register()
	}
}
