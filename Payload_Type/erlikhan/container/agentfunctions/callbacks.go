package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// callbackSummary builds the one-line callback description.
func callbackSummary(c2Name string, commandCount int) string {
	if c2Name == "" {
		c2Name = "?"
	}
	return fmt.Sprintf("erlikhan/%s · %d commands", c2Name, commandCount)
}

// callbackSleep formats "Ns ±M%" from C2 profile params, "" when unknown.
func callbackSleep(params map[string]any) string {
	if params == nil {
		return ""
	}
	iv, err := numStrParam(params, "callback_interval")
	if err != nil {
		return ""
	}
	jt, err := numStrParam(params, "callback_jitter")
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%ds ±%d%%", iv, jt)
}

// onNewCallback stamps new callbacks with a description and sleep info.
func onNewCallback(data agentstructs.PTOnNewCallbackAllData) agentstructs.PTOnNewCallbackResponse {
	resp := agentstructs.PTOnNewCallbackResponse{
		AgentCallbackID: data.Callback.AgentCallbackID,
		Success:         true,
	}
	uuid := data.Callback.AgentCallbackID
	desc := callbackSummary("", len(data.Commands))
	msg := mythicrpc.MythicRPCCallbackUpdateMessage{
		AgentCallbackUUID: &uuid,
		Description:       &desc,
	}
	if len(data.C2Profiles) > 0 {
		desc = callbackSummary(data.C2Profiles[0].Name, len(data.Commands))
		msg.Description = &desc
		if sleep := callbackSleep(data.C2Profiles[0].Parameters); sleep != "" {
			msg.SleepInfo = &sleep
		}
	}
	rpcResp, err := mythicrpc.SendMythicRPCCallbackUpdate(msg)
	if err != nil {
		logging.LogError(err, "Failed to update new callback")
		resp.Error, resp.Success = err.Error(), false
		return resp
	}
	if rpcResp == nil || !rpcResp.Success {
		msg := "unknown error"
		if rpcResp != nil {
			msg = rpcResp.Error
		}
		resp.Error, resp.Success = msg, false
		return resp
	}
	return resp
}
