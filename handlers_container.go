package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
	if err := os.Chmod(tmpPath, 0o1777); err != nil {
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
		ID:            id,
		Name:          name,
		Hostname:      hostname,
		User:          firstNonEmpty(strings.TrimSpace(req.User), strings.TrimSpace(meta.User)),
		Image:         req.Image,
		ResolvedImage: resolvedRef,
		Rootfs:        rootfs,
		Created:       time.Now().UTC(),
		Running:       false,
		ExitCode:      0,
		Ports:         ports,
		ExposedPorts:  allExposed,
		Env:           env,
		WorkingDir:    workingDir,
		LogPath:       logPath,
		StdoutPath:    stdoutPath,
		StderrPath:    stderrPath,
		Cmd:           append(entrypoint, cmd...),
		NetworkMode:   "bridge",
		ExtraHosts:    normalizeExtraHosts(req.HostConfig.ExtraHosts),
	}

	requestedMode := strings.TrimSpace(req.HostConfig.NetworkMode)
	if requestedMode != "" {
		c.NetworkMode = requestedMode
	}
	if strings.EqualFold(c.NetworkMode, "default") {
		c.NetworkMode = "bridge"
	}

	attachedToNetwork := false
	for networkRef, endpoint := range req.NetworkingConfig.EndpointsConfig {
		networkRef = strings.TrimSpace(networkRef)
		if networkRef == "" {
			continue
		}
		if strings.EqualFold(networkRef, "default") {
			networkRef = "bridge"
		}
		n, ok := store.getNetwork(networkRef)
		if !ok {
			writeError(w, http.StatusNotFound, "network not found")
			return
		}
		if err := store.connectContainerToNetwork(n.ID, c, endpoint.Aliases); err != nil {
			writeError(w, http.StatusInternalServerError, "network attach failed")
			return
		}
		attachedToNetwork = true
		if strings.TrimSpace(req.HostConfig.NetworkMode) == "" || strings.EqualFold(c.NetworkMode, "default") {
			c.NetworkMode = n.Name
		}
	}

	if !attachedToNetwork {
		switch strings.ToLower(strings.TrimSpace(c.NetworkMode)) {
		case "", "default", "bridge":
			c.NetworkMode = "bridge"
			if err := store.connectContainerToNetwork(builtInBridgeNetworkID, c, nil); err != nil {
				writeError(w, http.StatusInternalServerError, "network attach failed")
				return
			}
		case "host", "none":
		default:
			n, ok := store.getNetwork(c.NetworkMode)
			if !ok {
				writeError(w, http.StatusNotFound, "network not found")
				return
			}
			if err := store.connectContainerToNetwork(n.ID, c, nil); err != nil {
				writeError(w, http.StatusInternalServerError, "network attach failed")
				return
			}
		}
	}

	if err := store.save(c); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{ID: id, Warnings: nil})
}

func handleStart(w http.ResponseWriter, r *http.Request, store *containerStore, m *metrics, limits runtimeLimits, runtimeBackend, k8sRuntimeNamespace string, k8sImagePullSecrets []string, id string) {
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
	if runtimeBackend == runtimeBackendK8s {
		client, err := newInClusterK8sClient()
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
		if ns := strings.TrimSpace(k8sRuntimeNamespace); ns != "" {
			client.namespace = ns
		}
		client.imagePullSecrets = append([]string{}, k8sImagePullSecrets...)
		if c.K8sPodName == "" {
			podName, err := client.createPod(r.Context(), c)
			if err != nil {
				if reserved {
					m.mu.Lock()
					if m.running > 0 {
						m.running--
					}
					m.mu.Unlock()
				}
				m.mu.Lock()
				m.startFailures++
				m.mu.Unlock()
				writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
				return
			}
			c.K8sPodName = podName
			c.K8sNamespace = client.namespace
		}
		podIP, podState, err := client.waitForPodStarted(r.Context(), c.K8sNamespace, c.K8sPodName, 2*time.Minute)
		if err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			m.mu.Lock()
			m.startFailures++
			m.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		targets := map[int]string{}
		if podState.Running {
			for cp := range c.Ports {
				targets[cp] = fmt.Sprintf("%s:%d", podIP, cp)
			}
			store.stopProxies(c.ID)
			proxies, err := startPortProxies(c.Ports, targets)
			if err != nil {
				if reserved {
					m.mu.Lock()
					if m.running > 0 {
						m.running--
					}
					m.mu.Unlock()
				}
				m.mu.Lock()
				m.startFailures++
				m.mu.Unlock()
				writeError(w, http.StatusInternalServerError, "port proxy failed")
				return
			}
			store.setProxies(c.ID, proxies)
		}
		c.Running = podState.Running
		c.Pid = 0
		c.ExitCode = podState.ExitCode
		if podState.StartedAt.IsZero() {
			c.StartedAt = time.Now().UTC()
		} else {
			c.StartedAt = podState.StartedAt
		}
		c.FinishedAt = podState.FinishedAt
		c.K8sPodIP = podIP
		c.PortTargets = targets
		if err := store.save(c); err != nil {
			store.stopProxies(c.ID)
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
		go monitorK8sPod(c.ID, c.K8sNamespace, c.K8sPodName, store, m, startedAt)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	cmdArgs := c.Cmd
	if len(cmdArgs) == 0 {
		cmdArgs = []string{"sleep", "3600"}
	}
	cmdArgs = resolveCommandInRootfs(c.Rootfs, c.Env, cmdArgs)
	runtimeEnv := append([]string{}, c.Env...)
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
	if isLLdapImage(c.Image) {
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
		runtimeEnv = applyLLdapRuntimeCompatEnv(runtimeEnv, c.LoopbackIP)
		runtimeTargets[3890] = c.LoopbackIP + ":3890"
		runtimeTargets[17170] = c.LoopbackIP + ":17170"
	}
	if isNginxImage(c.Image) {
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
		if err := writeNginxCompatConfig(c.Rootfs, 8080); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: nginx compat failed")
			return
		}
		cmdArgs = applyNginxRuntimeCompatCommand(cmdArgs, 8080)
		runtimeTargets[80] = c.LoopbackIP + ":8080"
	}
	if isSSHDImage(c.Image) {
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
		const sshdCompatPort = 2222
		cmdArgs = applySSHDRuntimeCompat(cmdArgs, c.LoopbackIP, sshdCompatPort)
		runtimeTargets[22] = fmt.Sprintf("%s:%d", c.LoopbackIP, sshdCompatPort)
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
	if err := os.Chmod(containerTmpDir(c), 0o1777); err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: tmp permission fix failed")
		return
	}
	if err := writeContainerIdentityFilesWithAliasesAndHosts(c.Rootfs, c.Hostname, store.peerAliasesForContainer(c.ID), c.ExtraHosts); err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: hosts update failed")
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
	runtimeEnv = applyTiniRuntimeCompatEnv(runtimeEnv, cmdArgs)
	cmd.Env = deduplicateEnv(append(os.Environ(), runtimeEnv...))

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
	refreshNetworkAliasHosts(store, c.ID)

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
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err == nil {
			_ = client.deletePod(r.Context(), c.K8sNamespace, c.K8sPodName, 2)
		}
		store.stopProxies(c.ID)
		exitCode := 137
		store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
		w.WriteHeader(http.StatusNoContent)
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
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err == nil {
			_ = client.deletePod(r.Context(), c.K8sNamespace, c.K8sPodName, 0)
		}
		store.stopProxies(c.ID)
		exitCode := 137
		store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
		w.WriteHeader(http.StatusNoContent)
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
		if strings.TrimSpace(c.K8sPodName) != "" {
			client, err := newInClusterK8sClient()
			if err == nil {
				_ = client.deletePod(r.Context(), c.K8sNamespace, c.K8sPodName, 2)
			}
		} else {
			terminateProcessTree(c.Pid, 2*time.Second)
		}
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
	store.disconnectContainerFromAllNetworks(c.ID)

	w.WriteHeader(http.StatusNoContent)
}

func handleJSON(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if strings.TrimSpace(c.K8sPodName) != "" {
		if synced, err := syncK8sContainerState(r.Context(), store, c); err == nil && synced != nil {
			c = synced
		}
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
	networks := store.networkSettingsForContainer(c.ID)
	networkMode := strings.TrimSpace(c.NetworkMode)
	if networkMode == "" {
		networkMode = "bridge"
	}
	if strings.TrimSpace(c.K8sPodName) != "" && strings.TrimSpace(c.K8sPodIP) != "" {
		if bridgeRaw, ok := networks["bridge"]; ok {
			if bridge, ok := bridgeRaw.(map[string]interface{}); ok {
				bridge["IPAddress"] = c.K8sPodIP
				bridge["IPPrefixLen"] = 24
			}
		}
	}
	switch strings.ToLower(networkMode) {
	case "none", "host":
		networks = map[string]interface{}{
			strings.ToLower(networkMode): map[string]interface{}{
				"NetworkID":           strings.ToLower(networkMode),
				"EndpointID":          "",
				"Gateway":             "",
				"IPAddress":           "",
				"IPPrefixLen":         0,
				"IPv6Gateway":         "",
				"GlobalIPv6Address":   "",
				"GlobalIPv6PrefixLen": 0,
				"MacAddress":          "",
				"Aliases":             []string{},
			},
		}
	}
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
			"NetworkMode":  networkMode,
			"PortBindings": toDockerPorts(c.Ports),
		},
		"Mounts": []map[string]interface{}{},
		"NetworkSettings": map[string]interface{}{
			"Ports":    toDockerPorts(c.Ports),
			"Networks": networks,
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
	now := time.Now().UTC()
	evt := map[string]interface{}{
		"status": "noop",
		"id":     "sidewhale",
		"from":   "sidewhale",
		"Type":   "container",
		"Action": "noop",
		"Actor": map[string]interface{}{
			"ID":         "sidewhale",
			"Attributes": map[string]string{},
		},
		"time":     now.Unix(),
		"timeNano": now.UnixNano(),
	}
	enc := json.NewEncoder(w)
	_ = enc.Encode(evt)
}

func handleLogs(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
		logs, err := client.podLogs(r.Context(), c.K8sNamespace, c.K8sPodName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
		_, _ = w.Write(frameDockerRawStream(1, logs))
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
		if strings.TrimSpace(c.K8sPodName) != "" {
			if synced, err := syncK8sContainerState(r.Context(), store, c); err == nil && synced != nil {
				c = synced
			}
		}
		if c.Running && strings.TrimSpace(c.K8sPodName) == "" && !processAlive(c.Pid) {
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

func normalizeExtraHosts(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		host, ip, ok := parseExtraHost(raw)
		if !ok {
			continue
		}
		key := host + "=" + ip
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, host+":"+ip)
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

func applyTiniRuntimeCompatEnv(env, cmdArgs []string) []string {
	if !usesTini(cmdArgs) || hasArg(cmdArgs, "-s") || envHasKey(env, "TINI_SUBREAPER") {
		return env
	}
	out := append([]string{}, env...)
	out = append(out, "TINI_SUBREAPER=1")
	return out
}

func applyLLdapRuntimeCompatEnv(env []string, loopbackIP string) []string {
	ip := strings.TrimSpace(loopbackIP)
	if ip == "" {
		return env
	}
	defaults := []string{
		"LLDAP_LDAP_HOST=" + ip,
		"LLDAP_HTTP_HOST=" + ip,
	}
	return mergeEnv(defaults, env)
}

func applySSHDRuntimeCompat(cmdArgs []string, loopbackIP string, port int) []string {
	ip := strings.TrimSpace(loopbackIP)
	if len(cmdArgs) == 0 || ip == "" || port <= 0 {
		return cmdArgs
	}
	if hasArg(cmdArgs, "-p") {
		return cmdArgs
	}
	portArg := strconv.Itoa(port)
	listenArg := "ListenAddress=" + ip
	if len(cmdArgs) >= 3 {
		base := strings.ToLower(filepath.Base(strings.TrimSpace(cmdArgs[0])))
		if (base == "sh" || base == "bash") && cmdArgs[1] == "-c" {
			script := cmdArgs[2]
			lowerScript := strings.ToLower(script)
			if strings.Contains(lowerScript, "sshd") {
				if strings.Contains(script, " -p ") {
					return cmdArgs
				}
				out := append([]string{}, cmdArgs...)
				rewritten := script
				if !strings.Contains(rewritten, " -e ") && !strings.HasSuffix(rewritten, " -e") {
					rewritten += " -e"
				}
				rewritten += " -o " + listenArg + " -p " + portArg
				out[2] = rewritten
				return out
			}
		}
	}
	for _, arg := range cmdArgs {
		if strings.Contains(strings.ToLower(arg), "sshd") {
			out := append([]string{}, cmdArgs...)
			if !hasArg(out, "-e") {
				out = append(out, "-e")
			}
			out = append(out, "-o", listenArg, "-p", portArg)
			return out
		}
	}
	return cmdArgs
}

func applyNginxRuntimeCompatRootfs(rootfs string, listenPort int) error {
	if strings.TrimSpace(rootfs) == "" || listenPort <= 0 {
		return nil
	}
	paths := []string{
		filepath.Join(rootfs, "etc", "nginx", "conf.d", "default.conf"),
		filepath.Join(rootfs, "etc", "nginx", "http.d", "default.conf"),
		filepath.Join(rootfs, "etc", "nginx", "nginx.conf"),
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		rewritten := rewriteNginxListenConfig(string(b), listenPort)
		if rewritten == string(b) {
			continue
		}
		if err := os.WriteFile(p, []byte(rewritten), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func rewriteNginxListenConfig(conf string, listenPort int) string {
	if listenPort <= 0 {
		return conf
	}
	port := strconv.Itoa(listenPort)
	re := regexp.MustCompile(`(?m)^(\s*listen\s+)(\[::\]:)?80(\s+default_server)?;`)
	return re.ReplaceAllString(conf, "${1}${2}"+port+"${3};")
}

func refreshNetworkAliasHosts(store *containerStore, containerID string) {
	if store == nil || strings.TrimSpace(containerID) == "" {
		return
	}
	for _, id := range store.containersSharingNetworks(containerID) {
		c, ok := store.get(id)
		if !ok || c == nil || !c.Running {
			continue
		}
		_ = writeContainerIdentityFilesWithAliasesAndHosts(c.Rootfs, c.Hostname, store.peerAliasesForContainer(c.ID), c.ExtraHosts)
	}
}

func monitorK8sPod(containerID, namespace, podName string, store *containerStore, m *metrics, startedAt time.Time) {
	client, err := newInClusterK8sClient()
	if err != nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c, ok := store.get(containerID)
		if !ok || !c.Running {
			return
		}
		pod, err := client.getPod(context.Background(), namespace, podName)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				exitCode := 137
				finishedAt := time.Now().UTC()
				store.stopProxies(containerID)
				store.markStoppedWithExit(containerID, &exitCode, finishedAt)
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.execDurationMs = time.Since(startedAt).Milliseconds()
				m.mu.Unlock()
				return
			}
			continue
		}
		state := podRuntimeState(pod)
		switch strings.ToLower(strings.TrimSpace(pod.Status.Phase)) {
		case "running", "pending":
			if state.Running {
				continue
			}
			continue
		case "succeeded", "failed":
			exitCode := state.ExitCode
			finishedAt := time.Now().UTC()
			store.stopProxies(containerID)
			store.markStoppedWithExit(containerID, &exitCode, finishedAt)
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.execDurationMs = time.Since(startedAt).Milliseconds()
			m.mu.Unlock()
			return
		}
	}
}

func syncK8sContainerState(ctx context.Context, store *containerStore, c *Container) (*Container, error) {
	if c == nil || strings.TrimSpace(c.K8sPodName) == "" {
		return c, nil
	}
	client, err := newInClusterK8sClient()
	if err != nil {
		return c, err
	}
	pod, err := client.getPod(ctx, c.K8sNamespace, c.K8sPodName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Running = false
			c.Pid = 0
			if c.ExitCode == 0 {
				c.ExitCode = 137
			}
			if c.FinishedAt.IsZero() {
				c.FinishedAt = time.Now().UTC()
			}
			c.K8sPodIP = ""
			store.stopProxies(c.ID)
			_ = store.save(c)
			updated, _ := store.get(c.ID)
			if updated != nil {
				return updated, nil
			}
			return c, nil
		}
		return c, err
	}
	state := podRuntimeState(pod)
	c.K8sPodIP = strings.TrimSpace(pod.Status.PodIP)
	c.Running = state.Running
	if state.StartedAt.IsZero() {
		if c.StartedAt.IsZero() {
			c.StartedAt = time.Now().UTC()
		}
	} else {
		c.StartedAt = state.StartedAt
	}
	if state.Running {
		c.ExitCode = 0
		c.FinishedAt = time.Time{}
	} else {
		c.Pid = 0
		c.ExitCode = state.ExitCode
		if state.FinishedAt.IsZero() {
			if c.FinishedAt.IsZero() {
				c.FinishedAt = time.Now().UTC()
			}
		} else {
			c.FinishedAt = state.FinishedAt
		}
		store.stopProxies(c.ID)
	}
	_ = store.save(c)
	updated, _ := store.get(c.ID)
	if updated != nil {
		return updated, nil
	}
	return c, nil
}

func writeNginxCompatConfig(rootfs string, listenPort int) error {
	if strings.TrimSpace(rootfs) == "" || listenPort <= 0 {
		return nil
	}
	p := filepath.Join(rootfs, "etc", "nginx", "nginx-sidewhale.conf")
	content := fmt.Sprintf(`worker_processes auto;
error_log /dev/stderr notice;
pid /tmp/nginx.pid;
events {
  worker_connections 1024;
}
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /dev/stdout;
  sendfile on;
  keepalive_timeout 65;
  server {
    listen %d;
    listen [::]:%d;
    server_name localhost;
    location / {
      root /usr/share/nginx/html;
      index index.html index.htm;
    }
  }
}
`, listenPort, listenPort)
	return os.WriteFile(p, []byte(content), 0o644)
}

func applyNginxRuntimeCompatCommand(cmdArgs []string, listenPort int) []string {
	if listenPort <= 0 {
		return cmdArgs
	}
	return []string{
		"nginx",
		"-g",
		"daemon off;",
		"-c",
		"/etc/nginx/nginx-sidewhale.conf",
	}
}

func usesTini(cmdArgs []string) bool {
	for _, arg := range cmdArgs {
		base := strings.ToLower(filepath.Base(strings.TrimSpace(arg)))
		if base == "tini" || base == "tini-static" {
			return true
		}
	}
	return false
}
