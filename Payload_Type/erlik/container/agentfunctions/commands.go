package agentfunctions

import (
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

func init() {
	agentstructs.AllPayloadData.Get("erlik").AddCommand(agentstructs.Command{
		Name:                           "shell",
		Description:                    "shell <command> (cmd.exe /c)",
		Version:                        1,
		MitreAttackMappings:            []string{"T1059"},
		Author:                         "erlik",
		TaskFunctionCreateTasking:      passthroughTask,
		TaskFunctionParseArgString:     stringLine,
		TaskFunctionParseArgDictionary: stringDict,
	})
	agentstructs.AllPayloadData.Get("erlik").AddCommand(agentstructs.Command{
		Name:                           "powershell",
		Description:                    "powershell <command> (powershell.exe /c)",
		Version:                        1,
		MitreAttackMappings:            []string{"T1059.001"},
		Author:                         "erlik",
		TaskFunctionCreateTasking:      passthroughTask,
		TaskFunctionParseArgString:     stringLine,
		TaskFunctionParseArgDictionary: stringDict,
	})
	agentstructs.AllPayloadData.Get("erlik").AddCommand(agentstructs.Command{
		Name:                           "sleep",
		Description:                    "sleep <interval> [jitter] (seconds, jitter percent)",
		Version:                        1,
		MitreAttackMappings:            []string{},
		Author:                         "erlik",
		TaskFunctionCreateTasking:      passthroughTask,
		TaskFunctionParseArgString:     stringLine,
		TaskFunctionParseArgDictionary: stringDict,
	})
	agentstructs.AllPayloadData.Get("erlik").AddCommand(agentstructs.Command{
		Name:                "exit",
		Description:         "exit the agent",
		Version:             1,
		MitreAttackMappings: []string{},
		Author:              "erlik",
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
			return nil
		},
	})
}
