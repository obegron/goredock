package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var version = "dev"

const extractorVersion = "v2"

func main() {
	var (
		listenAddr    = flag.String("listen", ":23750", "listen address")
		listenUnix    = flag.String("listen-unix", "", "unix socket path (empty = <state-dir>/docker.sock, '-' disables)")
		stateDir      = flag.String("state-dir", "/tmp/sidewhale", "state directory")
		maxConcurrent = flag.Int("max-concurrent", 4, "max concurrent containers (0 = unlimited)")
		maxRuntime    = flag.Duration("max-runtime", 30*time.Minute, "max runtime per container (0 = unlimited)")
		maxLogBytes   = flag.Int64("max-log-bytes", 50*1024*1024, "max log size in bytes (0 = unlimited)")
		maxMemBytes   = flag.Int64("max-mem-bytes", 0, "soft memory limit in bytes (0 = unlimited)")
		allowedImages = flag.String("allowed-images", "", "comma-separated allowed image prefixes")
		policyFile    = flag.String("image-policy-file", "", "YAML file with allowed image prefixes")
		imageMirrors  = flag.String("image-mirrors", "", "comma-separated image rewrite rules from=to")
		mirrorFile    = flag.String("image-mirror-file", "", "YAML file with image rewrite rules")
		trustInsecure = flag.Bool("trust-insecure", false, "skip TLS certificate verification for image pulls")
		printVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *printVersion {
		fmt.Println(version)
		return
	}
	if err := requireUnprivilegedRuntime(os.Geteuid()); err != nil {
		fmt.Fprintf(os.Stderr, "startup check failed: %v\n", err)
		os.Exit(1)
	}

	store := &containerStore{
		containers: make(map[string]*Container),
		execs:      make(map[string]*ExecInstance),
		stateDir:   *stateDir,
		proxies:    make(map[string][]*portProxy),
	}
	unixSocketPath := resolveUnixSocketPath(*listenUnix, *stateDir)
	allowedPrefixes, err := loadAllowedImagePrefixes(*allowedImages, *policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "image policy load failed: %v\n", err)
		os.Exit(1)
	}
	mirrorRules, err := loadImageMirrorRules(*imageMirrors, *mirrorFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "image mirror config load failed: %v\n", err)
		os.Exit(1)
	}

	if err := store.init(); err != nil {
		fmt.Fprintf(os.Stderr, "state init failed: %v\n", err)
		os.Exit(1)
	}

	m := &metrics{}
	limits := runtimeLimits{
		maxConcurrent: *maxConcurrent,
		maxRuntime:    *maxRuntime,
		maxLogBytes:   *maxLogBytes,
		maxMemBytes:   *maxMemBytes,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"Version":       version,
			"ApiVersion":    "1.41",
			"MinAPIVersion": "1.12",
			"Os":            "linux",
			"Arch":          "amd64",
		})
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		memTotal := readMemTotal()
		info := map[string]interface{}{
			"ID":              "sidewhale",
			"OperatingSystem": "linux",
			"OSType":          "linux",
			"Architecture":    "amd64",
			"ServerVersion":   version,
			"MemTotal":        memTotal,
			"NCPU":            runtime.NumCPU(),
			"Name":            "sidewhale",
			"Containers":      len(store.listContainers()),
			"Images":          0,
			"Driver":          "vfs",
		}
		if images, err := listImages(store.stateDir); err == nil {
			info["Images"] = len(images)
		}
		writeJSON(w, http.StatusOK, info)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "sidewhale_running_containers %d\n", m.running)
		fmt.Fprintf(w, "sidewhale_start_failures %d\n", m.startFailures)
		fmt.Fprintf(w, "sidewhale_pull_duration_ms %d\n", m.pullDurationMs)
		fmt.Fprintf(w, "sidewhale_execution_duration_ms %d\n", m.execDurationMs)
	})

	mux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		ref := r.URL.Query().Get("fromImage")
		if ref == "" {
			ref = r.URL.Query().Get("image")
		}
		tag := strings.TrimSpace(r.URL.Query().Get("tag"))
		if ref == "" {
			writeError(w, http.StatusBadRequest, "missing fromImage")
			return
		}
		if tag != "" && !strings.Contains(ref, "@") && !imageRefHasTag(ref) {
			ref = ref + ":" + tag
		}
		resolvedRef := rewriteImageReference(ref, mirrorRules)
		if !isImageAllowed(resolvedRef, allowedPrefixes) {
			writeError(w, http.StatusForbidden, "image not allowed by policy")
			return
		}
		if _, _, err := ensureImage(r.Context(), resolvedRef, store.stateDir, m, *trustInsecure); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/images/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		images, err := listImages(store.stateDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "image list failed")
			return
		}
		writeJSON(w, http.StatusOK, images)
	})

	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/containers/")
		if path == "create" && r.Method == http.MethodPost {
			handleCreate(w, r, store, allowedPrefixes, mirrorRules, unixSocketPath, *trustInsecure)
			return
		}
		parts := strings.Split(path, "/")
		if len(parts) < 1 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		id := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}
		switch action {
		case "start":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleStart(w, r, store, m, limits, id)
		case "kill":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleKill(w, r, store, id)
		case "exec":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleExecCreate(w, r, store, id)
		case "stop":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleStop(w, r, store, id)
		case "json":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleJSON(w, r, store, id)
		case "logs":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleLogs(w, r, store, id)
		case "stats":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleStats(w, r, store, id)
		case "archive":
			switch r.Method {
			case http.MethodGet:
				handleArchiveGet(w, r, store, id)
			case http.MethodPut:
				handleArchivePut(w, r, store, id)
			default:
				writeError(w, http.StatusNotFound, "not found")
			}
		case "wait":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleWait(w, r, store, id)
		default:
			if action == "" && r.Method == http.MethodDelete {
				handleDelete(w, r, store, id)
				return
			}
			writeError(w, http.StatusNotFound, "not found")
		}
	})
	mux.HandleFunc("/exec/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/exec/")
		parts := strings.Split(path, "/")
		if len(parts) < 1 || parts[0] == "" {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		id := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}
		switch action {
		case "start":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleExecStart(w, r, store, id)
		case "json":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleExecJSON(w, r, store, id)
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		list := store.listContainers()
		writeJSON(w, http.StatusOK, list)
	})

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           timeoutMiddleware(apiVersionMiddleware(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Keep write timeout disabled to avoid breaking long-lived Docker client streams.
		// Request-level API timeouts are already enforced by timeoutMiddleware.
		WriteTimeout: 0,
		// Docker clients commonly keep pooled HTTP connections for ~3 minutes.
		// Keep idle timeout above that to avoid NoHttpResponseException on reuse.
		IdleTimeout: 5 * time.Minute,
	}

	errCh := make(chan error, 2)
	started := 0

	tcpAddr := strings.TrimSpace(*listenAddr)
	if tcpAddr != "" && !strings.EqualFold(tcpAddr, "off") && tcpAddr != "-" {
		started++
		go func() {
			fmt.Printf("sidewhale listening on %s\n", tcpAddr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	if unixSocketPath != "" {
		ln, err := listenUnixSocket(unixSocketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unix socket setup failed: %v\n", err)
			os.Exit(1)
		}
		started++
		go func() {
			fmt.Printf("sidewhale listening on unix://%s\n", unixSocketPath)
			if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	if started == 0 {
		fmt.Fprintln(os.Stderr, "no listeners configured")
		os.Exit(1)
	}
	if err := <-errCh; err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func apiVersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rewritten, ok := rewriteVersionedPath(r.URL.Path); ok {
			r.URL.Path = rewritten
			r.URL.RawPath = rewritten
		}
		next.ServeHTTP(w, r)
	})
}

func rewriteVersionedPath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/v") {
		return "", false
	}
	rest := path[2:]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", false
	}
	versionPart := rest[:slash]
	if !isAPIVersion(versionPart) {
		return "", false
	}
	rewritten := rest[slash:]
	if rewritten == "" {
		return "/", true
	}
	return rewritten, true
}

func isAPIVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

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

	imageRootfs, meta, err := ensureImage(r.Context(), resolvedRef, store.stateDir, nil, trustInsecure)
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
	ports, err := resolvePortBindings(allExposed, req.HostConfig.PortBindings)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	c := &Container{
		ID:         id,
		Name:       name,
		Hostname:   hostname,
		User:       firstNonEmpty(strings.TrimSpace(req.User), strings.TrimSpace(meta.User)),
		Image:      req.Image,
		Rootfs:     rootfs,
		Created:    time.Now().UTC(),
		Running:    false,
		Ports:      ports,
		Env:        env,
		WorkingDir: workingDir,
		LogPath:    logPath,
		Cmd:        append(entrypoint, cmd...),
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
	// Deduplicate environment variables, favoring container env over host env
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
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Also log to server stdout
	fmt.Printf("sidewhale: starting container %s (id %s)\n", c.Name, c.ID)
	fmt.Printf("sidewhale: command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))

	if err := cmd.Start(); err != nil {
		logFile.Close()
		m.mu.Lock()
		m.startFailures++
		if reserved && m.running > 0 {
			m.running--
		}
		m.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}

	proxies, err := startPortProxies(c.Ports)
	if err != nil {
		_ = killProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		logFile.Close()
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
	if err := store.save(c); err != nil {
		_ = killProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		store.stopProxies(c.ID)
		logFile.Close()
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
		_ = cmd.Wait()
		logFile.Close()
		store.stopProxies(c.ID)
		store.markStopped(c.ID)
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
	store.markStopped(c.ID)
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
	store.markStopped(c.ID)
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
		store.markStopped(c.ID)
	}

	_ = os.RemoveAll(filepath.Dir(c.Rootfs))
	_ = os.Remove(c.LogPath)
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
	resp := map[string]interface{}{
		"Id":      c.ID,
		"Created": c.Created.Format(time.RFC3339Nano),
		"Path":    firstArg(c.Cmd),
		"Args":    restArgs(c.Cmd),
		"State": map[string]interface{}{
			"Status":     statusFromRunning(c.Running),
			"Running":    c.Running,
			"Paused":     false,
			"Restarting": false,
			"OOMKilled":  false,
			"Dead":       false,
			"Pid":        c.Pid,
			"ExitCode":   0,
			"Error":      "",
			"StartedAt":  c.Created.Format(time.RFC3339Nano),
			"FinishedAt": c.Created.Format(time.RFC3339Nano),
		},
		"Config": map[string]interface{}{
			"Image":    c.Image,
			"Env":      c.Env,
			"Cmd":      c.Cmd,
			"Hostname": c.Hostname,
			"User":     c.User,
		},
		"NetworkSettings": map[string]interface{}{
			"Ports": toDockerPorts(c.Ports),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

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
	stream := byte(1)
	if !includeStdout && includeStderr {
		stream = 2
	}

	logFile, err := os.Open(c.LogPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "log read failed")
		return
	}
	defer logFile.Close()

	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)

	flush := func() {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	offset := int64(0)
	writeNew := func() error {
		stat, err := logFile.Stat()
		if err != nil {
			return err
		}
		size := stat.Size()
		if size <= offset {
			return nil
		}
		chunk := make([]byte, size-offset)
		n, err := logFile.ReadAt(chunk, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		offset += int64(n)
		if n == 0 {
			return nil
		}
		_, _ = w.Write(frameDockerRawStream(stream, chunk[:n]))
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
			writeJSON(w, http.StatusOK, map[string]interface{}{"StatusCode": 0, "Error": nil})
			return
		}

		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func handleArchiveGet(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	queryPath := strings.TrimSpace(r.URL.Query().Get("path"))
	targetPath, err := resolvePathInContainerFS(c, queryPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid archive path")
		return
	}
	info, err := os.Lstat(targetPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "path not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "stat failed")
		return
	}

	linkTarget := ""
	if info.Mode()&os.ModeSymlink != 0 {
		if link, linkErr := os.Readlink(targetPath); linkErr == nil {
			linkTarget = link
		}
	}
	statPayload := map[string]interface{}{
		"name":       filepath.Base(strings.TrimRight(filepath.Clean(queryPath), string(os.PathSeparator))),
		"size":       info.Size(),
		"mode":       uint32(info.Mode()),
		"mtime":      info.ModTime().UTC().Format(time.RFC3339Nano),
		"linkTarget": linkTarget,
	}
	statJSON, err := json.Marshal(statPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stat encode failed")
		return
	}

	tarName := filepath.Base(filepath.Clean(queryPath))
	if tarName == "." || tarName == string(os.PathSeparator) {
		tarName = filepath.Base(targetPath)
	}
	if tarName == "." || tarName == string(os.PathSeparator) || tarName == "" {
		tarName = "archive"
	}
	tarName = path.Clean("/" + filepath.ToSlash(tarName))
	tarName = strings.TrimPrefix(tarName, "/")

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.WriteHeader(http.StatusOK)

	tw := tar.NewWriter(w)
	defer tw.Close()
	if err := writePathToTar(tw, targetPath, tarName); err != nil {
		return
	}
}

func handleArchivePut(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	queryPath := strings.TrimSpace(r.URL.Query().Get("path"))
	targetPath, err := resolvePathInContainerFS(c, queryPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid archive path")
		return
	}
	if err := extractArchiveToPath(r.Body, targetPath, func(dst string) string {
		return mapArchiveDestinationPath(c, dst)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "archive extract failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func resolvePathInContainerFS(c *Container, requested string) (string, error) {
	req := strings.TrimSpace(requested)
	if req == "" {
		return "", fmt.Errorf("path is required")
	}
	clean := path.Clean("/" + req)

	// Runtime binds a dedicated host path over /tmp, so archive operations must
	// target that bind-backed path to match what the process sees at execution.
	if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") {
		relTmp := strings.TrimPrefix(clean, "/tmp")
		relTmp = strings.TrimPrefix(relTmp, "/")
		return resolvePathUnder(containerTmpDir(c), relTmp)
	}

	relRoot := strings.TrimPrefix(clean, "/")
	if relRoot == "." || relRoot == "" {
		relRoot = ""
	}
	return resolvePathUnder(c.Rootfs, relRoot)
}

func resolvePathUnder(base string, rel string) (string, error) {
	full := filepath.Join(base, filepath.FromSlash(rel))
	baseClean := filepath.Clean(base)
	relCheck, err := filepath.Rel(baseClean, full)
	if err != nil {
		return "", err
	}
	if relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes base")
	}
	return full, nil
}

func extractArchiveToPath(r io.Reader, targetPath string, mapDst func(string) string) error {
	tmpDir, err := os.MkdirTemp("", "sidewhale-archive-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	top, err := untarToDir(r, tmpDir)
	if err != nil {
		return err
	}
	if len(top) == 0 {
		return nil
	}

	info, statErr := os.Stat(targetPath)
	targetExists := statErr == nil
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	if targetExists && info.IsDir() {
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(mapArchivePath(targetPath, mapDst), 0o755); err != nil {
			return err
		}
		for _, entry := range entries {
			src := filepath.Join(tmpDir, entry.Name())
			dst := filepath.Join(targetPath, entry.Name())
			if err := copyFSNode(src, mapArchivePath(dst, mapDst)); err != nil {
				return err
			}
		}
		return nil
	}
	if len(top) == 1 {
		return copyFSNode(filepath.Join(tmpDir, top[0]), mapArchivePath(targetPath, mapDst))
	}
	if err := os.MkdirAll(mapArchivePath(targetPath, mapDst), 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(tmpDir, entry.Name())
		dst := filepath.Join(targetPath, entry.Name())
		if err := copyFSNode(src, mapArchivePath(dst, mapDst)); err != nil {
			return err
		}
	}
	return nil
}

func mapArchivePath(path string, mapDst func(string) string) string {
	if mapDst == nil {
		return path
	}
	mapped := mapDst(path)
	if strings.TrimSpace(mapped) == "" {
		return path
	}
	return mapped
}

func mapArchiveDestinationPath(c *Container, dst string) string {
	if c == nil {
		return dst
	}
	rootTmp := filepath.Clean(filepath.Join(c.Rootfs, "tmp"))
	cleanDst := filepath.Clean(dst)
	if cleanDst != rootTmp && !strings.HasPrefix(cleanDst, rootTmp+string(filepath.Separator)) {
		return dst
	}
	rel, err := filepath.Rel(rootTmp, cleanDst)
	if err != nil {
		return dst
	}
	mapped, err := resolvePathUnder(containerTmpDir(c), rel)
	if err != nil {
		return dst
	}
	return mapped
}

func untarToDir(r io.Reader, dst string) ([]string, error) {
	tr := tar.NewReader(r)
	seenTop := map[string]struct{}{}
	var topOrder []string

	addTop := func(cleanName string) {
		first := strings.Split(cleanName, "/")[0]
		if first == "" {
			return
		}
		if _, ok := seenTop[first]; ok {
			return
		}
		seenTop[first] = struct{}{}
		topOrder = append(topOrder, first)
	}

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return topOrder, nil
		}
		if err != nil {
			return nil, err
		}
		if h == nil {
			continue
		}
		cleanName, ok := normalizeLayerPath(h.Name)
		if !ok {
			continue
		}
		addTop(cleanName)
		target := filepath.Join(dst, filepath.FromSlash(cleanName))

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs.FileMode(h.Mode)); err != nil {
				return nil, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			_ = os.RemoveAll(target)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(h.Mode))
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return nil, err
			}
			if err := f.Close(); err != nil {
				return nil, err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			_ = os.RemoveAll(target)
			if err := os.Symlink(h.Linkname, target); err != nil {
				return nil, err
			}
		case tar.TypeLink:
			linkName, ok := normalizeLayerPath(h.Linkname)
			if !ok {
				continue
			}
			linkTarget := filepath.Join(dst, filepath.FromSlash(linkName))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			_ = os.RemoveAll(target)
			if err := os.Link(linkTarget, target); err != nil {
				return nil, err
			}
		default:
			// Ignore unsupported tar entry types.
			continue
		}
	}
}

func copyDirContents(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())
		if err := copyFSNode(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyFSNode(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		link, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		return os.Symlink(link, dst)
	case info.IsDir():
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyFSNode(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return os.Chmod(dst, info.Mode().Perm())
	case info.Mode().IsRegular():
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Chmod(dst, info.Mode().Perm())
	default:
		return nil
	}
}

func writePathToTar(tw *tar.Writer, sourcePath, nameInTar string) error {
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}

	nameInTar = strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(nameInTar)), "/")
	if nameInTar == "." || nameInTar == "" {
		nameInTar = filepath.Base(sourcePath)
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		link, err := os.Readlink(sourcePath)
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = nameInTar
		return tw.WriteHeader(h)
	case info.IsDir():
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = nameInTar + "/"
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		entries, err := os.ReadDir(sourcePath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childSrc := filepath.Join(sourcePath, entry.Name())
			childTar := path.Join(nameInTar, entry.Name())
			if err := writePathToTar(tw, childSrc, childTar); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = nameInTar
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		f, err := os.Open(sourcePath)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	default:
		return nil
	}
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Message: msg})
}

// Placeholder for future port proxy implementation.
func ensureImage(ctx context.Context, ref string, stateDir string, m *metrics, trustInsecure bool) (string, imageMeta, error) {
	ref = strings.TrimSpace(ref)
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("invalid image reference: %w", err)
	}
	remoteOptions := []remote.Option{
		remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}),
	}
	if trustInsecure {
		remoteOptions = append(remoteOptions, remote.WithTransport(insecurePullTransport()))
	}
	image, err := remote.Image(parsed, remoteOptions...)
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("image pull failed: %w", err)
	}
	digest, err := image.Digest()
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("image digest failed: %w", err)
	}

	digestKey := strings.ReplaceAll(digest.String(), ":", "_")
	imageDir := filepath.Join(stateDir, "images", digestKey)
	rootfsDir := filepath.Join(imageDir, "rootfs")
	metaPath := filepath.Join(imageDir, "image.json")
	if _, err := os.Stat(rootfsDir); err == nil {
		meta := imageMeta{}
		if data, err := os.ReadFile(metaPath); err == nil {
			_ = json.Unmarshal(data, &meta)
		}
		if meta.Extractor == extractorVersion {
			if meta.DiskUsage == 0 {
				if usage, usageErr := dirSize(rootfsDir); usageErr == nil {
					meta.DiskUsage = usage
					if data, marshalErr := json.MarshalIndent(meta, "", "  "); marshalErr == nil {
						_ = os.WriteFile(metaPath, data, 0o644)
					}
				}
			}
			return rootfsDir, meta, nil
		}
		_ = os.RemoveAll(rootfsDir)
	}

	start := time.Now()
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return "", imageMeta{}, fmt.Errorf("image dir init failed: %w", err)
	}
	tmpRootfs := rootfsDir + ".tmp"
	_ = os.RemoveAll(tmpRootfs)
	if err := os.MkdirAll(tmpRootfs, 0o755); err != nil {
		return "", imageMeta{}, fmt.Errorf("temp rootfs init failed: %w", err)
	}

	layers, err := image.Layers()
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("layer list failed: %w", err)
	}
	var contentSize int64
	dirModes := map[string]dirAttributes{}
	for _, layer := range layers {
		if size, sizeErr := layer.Size(); sizeErr == nil && size > 0 {
			contentSize += size
		}
		if err := extractLayer(tmpRootfs, layer, dirModes); err != nil {
			_ = os.RemoveAll(tmpRootfs)
			return "", imageMeta{}, err
		}
	}
	if err := applyDirModes(dirModes); err != nil {
		_ = os.RemoveAll(tmpRootfs)
		return "", imageMeta{}, err
	}
	if err := os.Rename(tmpRootfs, rootfsDir); err != nil {
		_ = os.RemoveAll(tmpRootfs)
		return "", imageMeta{}, fmt.Errorf("rootfs finalize failed: %w", err)
	}
	diskUsage, _ := dirSize(rootfsDir)

	meta := imageMeta{
		Reference:   ref,
		Digest:      digest.String(),
		Extractor:   extractorVersion,
		ContentSize: contentSize,
		DiskUsage:   diskUsage,
	}
	if cfg, err := image.ConfigFile(); err == nil && cfg != nil {
		meta.Entrypoint = cfg.Config.Entrypoint
		meta.Cmd = cfg.Config.Cmd
		meta.Env = cfg.Config.Env
		meta.ExposedPorts = cfg.Config.ExposedPorts
		meta.WorkingDir = cfg.Config.WorkingDir
		meta.User = cfg.Config.User
	}
	if data, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(metaPath, data, 0o644)
	}

	if m != nil {
		m.mu.Lock()
		m.pullDurationMs = time.Since(start).Milliseconds()
		m.mu.Unlock()
	}
	return rootfsDir, meta, nil
}

func insecurePullTransport() http.RoundTripper {
	base, _ := http.DefaultTransport.(*http.Transport)
	if base == nil {
		return &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicitly enabled by --trust-insecure
		}
	}
	transport := base.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{} //nolint:gosec // explicit opt-in below
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // explicitly enabled by --trust-insecure
	return transport
}

func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

type dirAttributes struct {
	mode    fs.FileMode
	modTime time.Time
}

func extractLayer(rootfs string, layer v1.Layer, dirModes map[string]dirAttributes) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("layer read failed: %w", err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar read failed: %w", err)
		}
		if h == nil {
			continue
		}

		cleanName, ok := normalizeLayerPath(h.Name)
		if !ok {
			continue
		}
		targetPath := filepath.Join(rootfs, cleanName)

		base := filepath.Base(cleanName)
		dir := filepath.Dir(cleanName)

		if strings.HasPrefix(base, ".wh.") {
			if base == ".wh..wh..opq" {
				if err := removeAllChildren(filepath.Join(rootfs, dir)); err != nil {
					return fmt.Errorf("whiteout opaque failed: %w", err)
				}
				continue
			}
			removeTarget := filepath.Join(rootfs, dir, strings.TrimPrefix(base, ".wh."))
			_ = os.RemoveAll(removeTarget)
			continue
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("mkdir failed: %w", err)
			}
			dirModes[targetPath] = dirAttributes{mode: fs.FileMode(h.Mode), modTime: h.ModTime}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
			// Layer entries can replace an existing non-writable file from previous layers.
			// Remove first so create does not fail with EACCES on truncate/open.
			_ = os.RemoveAll(targetPath)
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(h.Mode))
			if err != nil {
				return fmt.Errorf("file create failed: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("file write failed: %w", err)
			}
			f.Close()
			_ = os.Chtimes(targetPath, time.Now(), h.ModTime)
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
			_ = os.RemoveAll(targetPath)
			if err := os.Symlink(h.Linkname, targetPath); err != nil {
				return fmt.Errorf("symlink failed: %w", err)
			}
		case tar.TypeLink:
			linkName, ok := normalizeLayerPath(h.Linkname)
			if !ok {
				continue
			}
			linkTarget := filepath.Join(rootfs, linkName)
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
			_ = os.RemoveAll(targetPath)
			if err := os.Link(linkTarget, targetPath); err != nil {
				// Fallback: copy content if hardlink creation fails.
				src, openErr := os.Open(linkTarget)
				if openErr != nil {
					return fmt.Errorf("hardlink source missing: %w", err)
				}
				dst, createErr := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
				if createErr != nil {
					src.Close()
					return fmt.Errorf("hardlink fallback create failed: %w", createErr)
				}
				if _, copyErr := io.Copy(dst, src); copyErr != nil {
					dst.Close()
					src.Close()
					return fmt.Errorf("hardlink fallback copy failed: %w", copyErr)
				}
				dst.Close()
				src.Close()
			}
		default:
			continue
		}
	}
}

func applyDirModes(dirModes map[string]dirAttributes) error {
	paths := make([]string, 0, len(dirModes))
	for path := range dirModes {
		paths = append(paths, path)
	}
	// Apply deeper directories first so parent mode tightening does not block children updates.
	sort.Slice(paths, func(i, j int) bool {
		return strings.Count(paths[i], string(os.PathSeparator)) > strings.Count(paths[j], string(os.PathSeparator))
	})
	for _, path := range paths {
		attr := dirModes[path]
		if err := os.Chmod(path, attr.mode); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Whiteouts in later layers can remove directories recorded earlier.
				continue
			}
			return fmt.Errorf("dir chmod failed: %w", err)
		}
		_ = os.Chtimes(path, time.Now(), attr.modTime)
	}
	return nil
}

func normalizeLayerPath(name string) (string, bool) {
	raw := strings.TrimSpace(name)
	if raw == "" {
		return "", false
	}
	cleanRaw := path.Clean(raw)
	if cleanRaw == "." || cleanRaw == ".." || strings.HasPrefix(cleanRaw, "../") {
		return "", false
	}
	clean := path.Clean("/" + raw)
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func removeAllChildren(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
	}
	return nil
}

func copyDir(src, dst string) error {
	type copiedDir struct {
		path    string
		mode    fs.FileMode
		modTime time.Time
	}
	var dirs []copiedDir

	if err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			dirs = append(dirs, copiedDir{path: target, mode: info.Mode(), modTime: info.ModTime()})
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.RemoveAll(target)
			return os.Symlink(link, target)
		}
		if info.Mode().IsRegular() {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.RemoveAll(target)
			if err := os.Link(path, target); err != nil {
				srcFile, openErr := os.Open(path)
				if openErr != nil {
					return openErr
				}
				// Use a closure or explicit Close to avoid leaking descriptors in WalkDir
				copyErr := func() error {
					defer srcFile.Close()
					dstFile, createErr := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
					if createErr != nil {
						return createErr
					}
					defer dstFile.Close()
					_, ioErr := io.Copy(dstFile, srcFile)
					return ioErr
				}()
				if copyErr != nil {
					return copyErr
				}
			}
			_ = os.Chtimes(target, time.Now(), info.ModTime())
			return nil
		}
		return nil
	}); err != nil {
		return err
	}

	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i].path, string(os.PathSeparator)) > strings.Count(dirs[j].path, string(os.PathSeparator))
	})
	for _, d := range dirs {
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		_ = os.Chtimes(d.path, time.Now(), d.modTime)
	}
	return nil
}
