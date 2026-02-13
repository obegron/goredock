package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func handleExecCreate(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	var req execCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.Cmd) == 0 {
		writeError(w, http.StatusBadRequest, "missing exec command")
		return
	}
	execID, err := randomID(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	inst := &ExecInstance{
		ID:          execID,
		ContainerID: c.ID,
		Cmd:         append([]string{}, req.Cmd...),
		ExitCode:    -1,
	}
	store.saveExec(inst)
	writeJSON(w, http.StatusCreated, execCreateResponse{ID: execID})
}

func handleExecStart(w http.ResponseWriter, r *http.Request, store *containerStore, execID string) {
	inst, ok := store.getExec(execID)
	if !ok {
		writeError(w, http.StatusNotFound, "exec instance not found")
		return
	}
	c, ok := store.get(inst.ContainerID)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	cmdArgs := resolveCommandInRootfs(c.Rootfs, c.Env, inst.Cmd)
	socketBinds, err := dockerSocketBindsForContainer(c, unixSocketPathFromContainerEnv(c.Env))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "exec start failed: "+err.Error())
		return
	}
	cmd, err := buildContainerCommand(c.Rootfs, containerTmpDir(c), c.WorkingDir, c.User, socketBinds, cmdArgs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "exec start failed: "+err.Error())
		return
	}
	cmd.Dir = "/"
	cmd.Env = deduplicateEnv(append(os.Environ(), c.Env...))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	inst.Running = true
	store.saveExec(inst)
	runErr := cmd.Run()
	inst.Running = false
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			inst.ExitCode = exitErr.ExitCode()
		} else {
			inst.ExitCode = 126
		}
	} else {
		inst.ExitCode = 0
	}
	inst.Output = []byte(buf.String())
	store.saveExec(inst)

	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)
	if len(inst.Output) > 0 {
		_, _ = w.Write(frameDockerRawStream(1, inst.Output))
	}
}

func handleExecJSON(w http.ResponseWriter, r *http.Request, store *containerStore, execID string) {
	inst, ok := store.getExec(execID)
	if !ok {
		writeError(w, http.StatusNotFound, "exec instance not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ID":       inst.ID,
		"Running":  inst.Running,
		"ExitCode": inst.ExitCode,
		"ProcessConfig": map[string]interface{}{
			"entrypoint": firstArg(inst.Cmd),
			"arguments":  restArgs(inst.Cmd),
		},
	})
}
