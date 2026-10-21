package main

import (
	agentfunctions "erlikhan/agentfunctions"
	"github.com/MythicMeta/MythicContainer"
)

func main() {
	agentfunctions.Initialize()
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServicePayload,
	})
}
