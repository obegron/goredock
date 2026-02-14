package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func handleCreate(w http.ResponseWriter, r *http.Request, store *containerStore, allowedPrefixes []string, mirrorRules []imageMirrorRule, unixSocketPath string, trustInsecure bool) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Image) == "" {
		writeError(w, http.StatusBadRequest, "missing image")
		return
	}
	resolvedRef := rewriteImageReference(req.Image, mirrorRules)
	if !isImageAllowed(resolvedRef, allowedPrefixes) {
		writeError(w, http.StatusForbidden, "image not allowed by policy")
		return
	}
	name := normalizeContainerName(r.URL.Query().Get("name"))
	if name != "" && store.nameInUse(name) {
		writeError(w, http.StatusConflict, "container name already in use")
		return
	}

	imageRootfs, meta, _, err := ensureImageWithFallback(
		r.Context(),
		resolvedRef,
		req.Image,
		store.stateDir,
		nil,
		trustInsecure,
		ensureImage,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, err := randomID(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	hostname := normalizeContainerHostname(req.Hostname)
	if hostname == "" {
		hostname = defaultContainerHostname(id)
	}

	rootfs := filepath.Join(store.stateDir, "containers", id, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "rootfs allocation failed")
		return
	}
	if err := copyDir(imageRootfs, rootfs); err != nil {
		writeError(w, http.StatusInternalServerError, "rootfs copy failed")
		return
	}
	if err := writeContainerIdentityFiles(rootfs, hostname); err != nil {
		writeError(w, http.StatusInternalServerError, "hostname setup failed")
		return
	}
	logPath := filepath.Join(store.stateDir, "containers", id, "container.log")
	stdoutPath := filepath.Join(store.stateDir, "containers", id, "stdout.log")
	stderrPath := filepath.Join(store.stateDir, "containers", id, "stderr.log")
	tmpPath := filepath.Join(store.stateDir, "containers", id, "tmp")
	if err := os.MkdirAll(tmpPath, 0o777); err != nil {
		writeError(w, http.StatusInternalServerError, "tmp allocation failed")
		return
	}

	entrypoint := req.Entrypoint
	cmd := req.Cmd
	if len(entrypoint) == 0 {
		entrypoint = meta.Entrypoint
	}
	if len(cmd) == 0 {
		cmd = meta.Cmd
	}
	if len(req.Entrypoint) > 0 {
		entrypoint = req.Entrypoint
		cmd = req.Cmd
	}

	env := mergeEnv(meta.Env, req.Env)
	env = applyImageCompat(env, hostname, resolvedRef, req.Image, unixSocketPath, r.Host)
	workingDir := req.WorkingDir
	if workingDir == "" {
		workingDir = meta.WorkingDir
	}
	if workingDir == "" {
		workingDir = "/"
	}

	allExposed := mergeExposedPorts(meta.ExposedPorts, req.ExposedPorts)
	ports, err := resolvePortBindings(allExposed, req.ExposedPorts, req.HostConfig.PortBindings)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	c := &Container{
		ID:           id,
		Name:         name,
		Hostname:     hostname,
		User:         firstNonEmpty(strings.TrimSpace(req.User), strings.TrimSpace(meta.User)),
		Image:        req.Image,
		Rootfs:       rootfs,
		Created:      time.Now().UTC(),
		Running:      false,
		ExitCode:     0,
		Ports:        ports,
		ExposedPorts: allExposed,
		Env:          env,
		WorkingDir:   workingDir,
		LogPath:      logPath,
		StdoutPath:   stdoutPath,
		StderrPath:   stderrPath,
		Cmd:          append(entrypoint, cmd...),
	}

	if err := store.save(c); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{ID: id, Warnings: nil})
}

func handleStart(w http.ResponseWriter, r *http.Request, store *containerStore, m *metrics, limits runtimeLimits, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if c.Running {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if limits.maxConcurrent > 0 {
		m.mu.Lock()
		if m.running >= limits.maxConcurrent {
			m.mu.Unlock()
			writeError(w, http.StatusConflict, "max concurrent containers reached")
			return
		}
		m.running++
		m.mu.Unlock()
	}
	reserved := limits.maxConcurrent > 0

	cmdArgs := c.Cmd
	if len(cmdArgs) == 0 {
		cmdArgs = []string{"sleep", "3600"}
	}
	cmdArgs = resolveCommandInRootfs(c.Rootfs, c.Env, cmdArgs)
	runtimeTargets := clonePortTargets(c.PortTargets)
	if isRedisImage(c.Image) {
		if strings.TrimSpace(c.LoopbackIP) == "" {
			ip, allocErr := store.allocateLoopbackIP()
			if allocErr != nil {
				if reserved {
					m.mu.Lock()
					if m.running > 0 {
						m.running--
					}
					m.mu.Unlock()
				}
				writeError(w, http.StatusInternalServerError, "start failed: "+allocErr.Error())
				return
			}
			c.LoopbackIP = ip
		}
		cmdArgs = applyRedisRuntimeCompat(cmdArgs, c.LoopbackIP)
		runtimeTargets[6379] = c.LoopbackIP + ":6379"
	}

	socketBinds, err := dockerSocketBindsForContainer(c, unixSocketPathFromContainerEnv(c.Env))
	if err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}

	cmd, err := buildContainerCommand(c.Rootfs, containerTmpDir(c), c.WorkingDir, c.User, socketBinds, cmdArgs)
	if err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = deduplicateEnv(append(os.Environ(), c.Env...))

	logFile, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "log open failed")
		return
	}
	stdoutPath := c.StdoutPath
	if strings.TrimSpace(stdoutPath) == "" {
		stdoutPath = c.LogPath
	}
	stderrPath := c.StderrPath
	if strings.TrimSpace(stderrPath) == "" {
		stderrPath = c.LogPath
	}
	stdoutFile, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logFile.Close()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "log open failed")
		return
	}
	stderrFile, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		stdoutFile.Close()
		logFile.Close()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "log open failed")
		return
	}
	closeLogs := func() {
		_ = stderrFile.Close()
		_ = stdoutFile.Close()
		_ = logFile.Close()
	}
	cmd.Stdout = io.MultiWriter(logFile, stdoutFile)
	cmd.Stderr = io.MultiWriter(logFile, stderrFile)

	fmt.Printf("sidewhale: starting container %s (id %s)\n", c.Name, c.ID)
	fmt.Printf("sidewhale: command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))

	if err := cmd.Start(); err != nil {
		closeLogs()
		m.mu.Lock()
		m.startFailures++
		if reserved && m.running > 0 {
			m.running--
		}
		m.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}

	proxies, err := startPortProxies(c.Ports, runtimeTargets)
	if err != nil {
		_ = killProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		closeLogs()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "port proxy failed")
		return
	}
	store.setProxies(c.ID, proxies)

	c.Running = true
	c.Pid = cmd.Process.Pid
	c.ExitCode = 0
	c.StartedAt = time.Now().UTC()
	c.FinishedAt = time.Time{}
	c.PortTargets = runtimeTargets
	if err := store.save(c); err != nil {
		_ = killProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		store.stopProxies(c.ID)
		closeLogs()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}

	startedAt := time.Now()

	go func() {
		waitErr := cmd.Wait()
		exitCode := 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 126
			}
		}
		closeLogs()
		store.stopProxies(c.ID)
		finishedAt := time.Now().UTC()
		store.markStoppedWithExit(c.ID, &exitCode, finishedAt)
		m.mu.Lock()
		if m.running > 0 {
			m.running--
		}
		m.execDurationMs = time.Since(startedAt).Milliseconds()
		m.mu.Unlock()
	}()

	go monitorContainer(c.ID, c.Pid, c.LogPath, store, limits)

	w.WriteHeader(http.StatusNoContent)
}

func handleStop(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if !c.Running || c.Pid == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	terminateProcessTree(c.Pid, 2*time.Second)
	store.stopProxies(c.ID)
	exitCode := 137
	store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
	w.WriteHeader(http.StatusNoContent)
}

func handleKill(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if !c.Running || c.Pid == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	terminateProcessTree(c.Pid, 0)
	store.stopProxies(c.ID)
	exitCode := 137
	store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
	w.WriteHeader(http.StatusNoContent)
}

func handleDelete(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if c.Running {
		terminateProcessTree(c.Pid, 2*time.Second)
		store.stopProxies(c.ID)
		exitCode := 137
		store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
	}

	_ = os.RemoveAll(filepath.Dir(c.Rootfs))
	_ = os.Remove(c.LogPath)
	_ = os.Remove(c.StdoutPath)
	_ = os.Remove(c.StderrPath)
	_ = os.Remove(store.containerPath(c.ID))

	store.mu.Lock()
	delete(store.containers, c.ID)
	store.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func handleJSON(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	exposed := c.ExposedPorts
	if len(exposed) == 0 {
		exposed = make(map[string]struct{}, len(c.Ports))
		for internal := range c.Ports {
			exposed[fmt.Sprintf("%d/tcp", internal)] = struct{}{}
		}
	}
	path := firstArg(c.Cmd)
	args := restArgs(c.Cmd)
	resp := map[string]interface{}{
		"Id":      c.ID,
		"Name":    containerDisplayName(c),
		"Created": c.Created.Format(time.RFC3339Nano),
		"Path":    path,
		"Args":    args,
		"State": map[string]interface{}{
			"Status":     statusFromRunning(c.Running),
			"Running":    c.Running,
			"Paused":     false,
			"Restarting": false,
			"OOMKilled":  false,
			"Dead":       false,
			"Pid":        c.Pid,
			"ExitCode":   c.ExitCode,
			"Error":      "",
			"StartedAt":  containerStartedAt(c).Format(time.RFC3339Nano),
			"FinishedAt": containerFinishedAt(c).Format(time.RFC3339Nano),
		},
		"Config": map[string]interface{}{
			"Hostname":     c.Hostname,
			"User":         c.User,
			"Image":        c.Image,
			"Env":          c.Env,
			"Cmd":          args,
			"Entrypoint":   []string{path},
			"WorkingDir":   c.WorkingDir,
			"ExposedPorts": exposed,
		},
		"HostConfig": map[string]interface{}{
			"NetworkMode":  "default",
			"PortBindings": toDockerPorts(c.Ports),
		},
		"Mounts": []map[string]interface{}{},
		"NetworkSettings": map[string]interface{}{
			"Ports": toDockerPorts(c.Ports),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleTop(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	procLine := []string{"0", statusFromRunning(c.Running), strings.Join(c.Cmd, " ")}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"Titles":    []string{"PID", "STATE", "COMMAND"},
		"Processes": [][]string{procLine},
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("[]"))
}

func handleLogs(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	includeStdout := parseDockerBool(r.URL.Query().Get("stdout"), true)
	includeStderr := parseDockerBool(r.URL.Query().Get("stderr"), true)
	if !includeStdout && !includeStderr {
		w.WriteHeader(http.StatusOK)
		return
	}
	follow := parseDockerBool(r.URL.Query().Get("follow"), false)
	type logStream struct {
		stream byte
		file   *os.File
		offset int64
	}
	streams := make([]*logStream, 0, 2)
	addStream := func(path string, stream byte) error {
		logFile, err := os.Open(path)
		if err != nil {
			return err
		}
		streams = append(streams, &logStream{stream: stream, file: logFile})
		return nil
	}
	logPath := c.LogPath
	stdoutPath := c.StdoutPath
	if strings.TrimSpace(stdoutPath) == "" {
		stdoutPath = logPath
	}
	stderrPath := c.StderrPath
	if strings.TrimSpace(stderrPath) == "" {
		stderrPath = logPath
	}
	if includeStdout {
		if err := addStream(stdoutPath, 1); err != nil {
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
	}
	if includeStderr {
		if stdoutPath == stderrPath && includeStdout {
			// Backward-compat for legacy containers with a single merged logfile.
		} else if err := addStream(stderrPath, 2); err != nil {
			for _, s := range streams {
				_ = s.file.Close()
			}
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
	}
	for _, s := range streams {
		defer s.file.Close()
	}

	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)

	flush := func() {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	writeNew := func() error {
		for _, s := range streams {
			stat, err := s.file.Stat()
			if err != nil {
				return err
			}
			size := stat.Size()
			if size <= s.offset {
				continue
			}
			chunk := make([]byte, size-s.offset)
			n, err := s.file.ReadAt(chunk, s.offset)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			s.offset += int64(n)
			if n == 0 {
				continue
			}
			_, _ = w.Write(frameDockerRawStream(s.stream, chunk[:n]))
		}
		flush()
		return nil
	}

	if err := writeNew(); err != nil {
		return
	}
	if !follow {
		return
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := writeNew(); err != nil {
				return
			}
			current, ok := store.get(id)
			if !ok || !current.Running {
				_ = writeNew()
				return
			}
		}
	}
}

func handleStats(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}

	now := time.Now().UTC()
	memUsage, _ := readRSS(c.Pid)
	if !c.Running {
		memUsage = 0
	}
	memLimit := readMemTotal()
	if memLimit == 0 {
		memLimit = 1
	}
	payload := map[string]interface{}{
		"read":      now.Format(time.RFC3339Nano),
		"preread":   now.Format(time.RFC3339Nano),
		"id":        c.ID,
		"name":      containerDisplayName(c),
		"num_procs": 1,
		"pids_stats": map[string]interface{}{
			"current": 1,
		},
		"cpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage":         0,
				"percpu_usage":        []int64{},
				"usage_in_kernelmode": 0,
				"usage_in_usermode":   0,
			},
			"system_cpu_usage": 0,
			"online_cpus":      runtime.NumCPU(),
		},
		"precpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage":  0,
				"percpu_usage": []int64{},
			},
			"system_cpu_usage": 0,
			"online_cpus":      runtime.NumCPU(),
		},
		"memory_stats": map[string]interface{}{
			"usage": memUsage,
			"limit": memLimit,
			"stats": map[string]interface{}{},
		},
		"networks": map[string]interface{}{},
		"blkio_stats": map[string]interface{}{
			"io_service_bytes_recursive": []interface{}{},
			"io_serviced_recursive":      []interface{}{},
		},
	}

	stream := parseDockerBool(r.URL.Query().Get("stream"), true)
	if !stream {
		writeJSON(w, http.StatusOK, payload)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

func handleWait(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	condition := strings.TrimSpace(r.URL.Query().Get("condition"))
	if condition == "" {
		condition = "not-running"
	}
	switch condition {
	case "not-running", "next-exit", "removed":
	default:
		writeError(w, http.StatusBadRequest, "unsupported wait condition")
		return
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		c, ok := store.get(id)
		if !ok {
			if condition == "removed" {
				writeJSON(w, http.StatusOK, map[string]interface{}{"StatusCode": 0, "Error": nil})
				return
			}
			writeError(w, http.StatusNotFound, "container not found")
			return
		}
		if c.Running && !processAlive(c.Pid) {
			store.markStopped(c.ID)
			c, _ = store.get(id)
		}
		if c == nil || !c.Running {
			exitCode := 0
			if c != nil {
				exitCode = c.ExitCode
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"StatusCode": exitCode, "Error": nil})
			return
		}

		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func containerStartedAt(c *Container) time.Time {
	if c != nil && !c.StartedAt.IsZero() {
		return c.StartedAt
	}
	if c != nil && !c.Created.IsZero() {
		return c.Created
	}
	return time.Time{}
}

func containerFinishedAt(c *Container) time.Time {
	if c == nil {
		return time.Time{}
	}
	if c.Running {
		return time.Time{}
	}
	if !c.FinishedAt.IsZero() {
		return c.FinishedAt
	}
	if !c.Created.IsZero() {
		return c.Created
	}
	return time.Time{}
}

func clonePortTargets(in map[int]string) map[int]string {
	out := make(map[int]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func applyRedisRuntimeCompat(cmdArgs []string, loopbackIP string) []string {
	if len(cmdArgs) == 0 || strings.TrimSpace(loopbackIP) == "" {
		return cmdArgs
	}
	if hasArg(cmdArgs, "--bind") {
		return cmdArgs
	}
	out := append([]string{}, cmdArgs...)
	out = append(out, "--bind", loopbackIP)
	return out
}

func hasArg(args []string, needle string) bool {
	for _, arg := range args {
		if arg == needle {
			return true
		}
	}
	return false
}
