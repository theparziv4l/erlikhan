package main

import (
	agentfunctions "erlik/agentfunctions"
	"github.com/MythicMeta/MythicContainer"
)

func main() {
	agentfunctions.Initialize()
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServicePayload,
	})
}
