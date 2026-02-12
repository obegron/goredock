package main

import (
	"archive/tar"
	"encoding/binary"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"gopkg.in/yaml.v3"
)

type Container struct {
	ID      string    `json:"Id"`
	Name    string    `json:"Name,omitempty"`
	Image   string    `json:"Image"`
	Rootfs  string    `json:"Rootfs"`
	Created time.Time `json:"Created"`
	Running bool      `json:"Running"`
	Ports   map[int]int
	Env     []string `json:"Env"`
	LogPath string   `json:"LogPath"`
	Pid     int      `json:"Pid"`
	Cmd     []string `json:"Cmd"`
}

type containerStore struct {
	mu         sync.Mutex
	containers map[string]*Container
	stateDir   string
	proxies    map[string][]*portProxy
}

type metrics struct {
	mu             sync.Mutex
	running        int
	startFailures  int
	pullDurationMs int64
	execDurationMs int64
}

type createRequest struct {
	Image        string              `json:"Image"`
	Cmd          []string            `json:"Cmd"`
	Env          []string            `json:"Env"`
	Entrypoint   []string            `json:"Entrypoint"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	HostConfig   hostConfig          `json:"HostConfig"`
}

type hostConfig struct {
	PortBindings map[string][]portBinding `json:"PortBindings"`
}

type portBinding struct {
	HostPort string `json:"HostPort"`
}

type createResponse struct {
	ID       string        `json:"Id"`
	Warnings []interface{} `json:"Warnings"`
}

type errorResponse struct {
	Message string `json:"message"`
}

type imageMeta struct {
	Reference  string   `json:"Reference"`
	Digest     string   `json:"Digest"`
	Entrypoint []string `json:"Entrypoint"`
	Cmd        []string `json:"Cmd"`
	Env        []string `json:"Env"`
	Extractor  string   `json:"Extractor,omitempty"`
}

type runtimeLimits struct {
	maxConcurrent int
	maxRuntime    time.Duration
	maxLogBytes   int64
	maxMemBytes   int64
}

type imagePolicyFile struct {
	AllowedImages        []string `yaml:"allowed_images"`
	AllowedImagePrefixes []string `yaml:"allowed_image_prefixes"`
	Images               []string `yaml:"images"`
}

type imageMirrorRule struct {
	FromPrefix string `yaml:"from"`
	ToPrefix   string `yaml:"to"`
}

type imageMirrorFile struct {
	ImageMirrors []imageMirrorRule `yaml:"image_mirrors"`
	Mirrors      []imageMirrorRule `yaml:"mirrors"`
}

type portProxy struct {
	ln   net.Listener
	stop chan struct{}
}

var version = "dev"

const extractorVersion = "v2"

func main() {
	var (
		listenAddr    = flag.String("listen", ":8080", "listen address")
		stateDir      = flag.String("state-dir", "/tmp/tcexecutor", "state directory")
		maxConcurrent = flag.Int("max-concurrent", 4, "max concurrent containers (0 = unlimited)")
		maxRuntime    = flag.Duration("max-runtime", 30*time.Minute, "max runtime per container (0 = unlimited)")
		maxLogBytes   = flag.Int64("max-log-bytes", 50*1024*1024, "max log size in bytes (0 = unlimited)")
		maxMemBytes   = flag.Int64("max-mem-bytes", 512*1024*1024, "soft memory limit in bytes (0 = unlimited)")
		allowedImages = flag.String("allowed-images", "", "comma-separated allowed image prefixes")
		policyFile    = flag.String("image-policy-file", "", "YAML file with allowed image prefixes")
		imageMirrors  = flag.String("image-mirrors", "", "comma-separated image rewrite rules from=to")
		mirrorFile    = flag.String("image-mirror-file", "", "YAML file with image rewrite rules")
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
		stateDir:   *stateDir,
		proxies:    make(map[string][]*portProxy),
	}
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
			"ID":              "tcexecutor",
			"OperatingSystem": "linux",
			"OSType":          "linux",
			"Architecture":    "amd64",
			"ServerVersion":   version,
			"MemTotal":        memTotal,
			"NCPU":            runtime.NumCPU(),
			"Name":            "tcexecutor",
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
		fmt.Fprintf(w, "tcexecutor_running_containers %d\n", m.running)
		fmt.Fprintf(w, "tcexecutor_start_failures %d\n", m.startFailures)
		fmt.Fprintf(w, "tcexecutor_pull_duration_ms %d\n", m.pullDurationMs)
		fmt.Fprintf(w, "tcexecutor_execution_duration_ms %d\n", m.execDurationMs)
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
		if ref == "" {
			writeError(w, http.StatusBadRequest, "missing fromImage")
			return
		}
		resolvedRef := rewriteImageReference(ref, mirrorRules)
		if !isImageAllowed(resolvedRef, allowedPrefixes) {
			writeError(w, http.StatusForbidden, "image not allowed by policy")
			return
		}
		if _, _, err := ensureImage(r.Context(), resolvedRef, store.stateDir, m); err != nil {
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
			handleCreate(w, r, store, allowedPrefixes, mirrorRules)
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
		default:
			if action == "" && r.Method == http.MethodDelete {
				handleDelete(w, r, store, id)
				return
			}
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
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Printf("tcexecutor listening on %s\n", *listenAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireUnprivilegedRuntime(euid int) error {
	if euid == 0 {
		return fmt.Errorf("refusing to run as root (uid 0)")
	}
	return nil
}

func buildContainerCommand(rootfs string, cmdArgs []string) (*exec.Cmd, error) {
	if len(cmdArgs) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	prootPath, err := findProotPath()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-0",
		"-R", rootfs,
		"-w", "/",
		"-b", "/proc",
		"-b", "/dev",
		"-b", "/tmp",
	}
	args = append(args, cmdArgs...)
	return exec.Command(prootPath, args...), nil
}

func findProotPath() (string, error) {
	if path, err := exec.LookPath("proot"); err == nil {
		return path, nil
	}
	if _, err := os.Stat("/proot"); err == nil {
		return "/proot", nil
	}
	return "", fmt.Errorf("missing proot binary (required for unprivileged image execution)")
}

func readMemTotal() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMemTotal(data)
}

func parseMemTotal(data []byte) int64 {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				break
			}
			return kb * 1024
		}
	}
	return 0
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

func handleCreate(w http.ResponseWriter, r *http.Request, store *containerStore, allowedPrefixes []string, mirrorRules []imageMirrorRule) {
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

	imageRootfs, meta, err := ensureImage(r.Context(), resolvedRef, store.stateDir, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, err := randomID(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
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
	logPath := filepath.Join(store.stateDir, "containers", id, "container.log")

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

	ports, err := resolvePortBindings(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	c := &Container{
		ID:      id,
		Name:    name,
		Image:   req.Image,
		Rootfs:  rootfs,
		Created: time.Now().UTC(),
		Running: false,
		Ports:   ports,
		Env:     env,
		LogPath: logPath,
		Cmd:     append(entrypoint, cmd...),
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
	cmdArgs = resolveCommandInRootfs(c.Rootfs, cmdArgs)

	cmd, err := buildContainerCommand(c.Rootfs, cmdArgs)
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
	cmd.Env = append(os.Environ(), c.Env...)

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
		_ = cmd.Process.Kill()
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
		_ = cmd.Process.Kill()
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

	_ = syscall.Kill(c.Pid, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(c.Pid) {
			store.stopProxies(c.ID)
			store.markStopped(c.ID)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(c.Pid, syscall.SIGKILL)
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
		_ = syscall.Kill(c.Pid, syscall.SIGTERM)
		_ = syscall.Kill(c.Pid, syscall.SIGKILL)
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
			"Image": c.Image,
			"Env":   c.Env,
			"Cmd":   c.Cmd,
		},
		"NetworkSettings": map[string]interface{}{
			"Ports": toDockerPorts(c.Ports),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleLogs(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	data, err := os.ReadFile(c.LogPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "log read failed")
		return
	}
	includeStdout := parseDockerBool(r.URL.Query().Get("stdout"), true)
	includeStderr := parseDockerBool(r.URL.Query().Get("stderr"), true)
	if !includeStdout && !includeStderr {
		w.WriteHeader(http.StatusOK)
		return
	}
	stream := byte(1)
	if !includeStdout && includeStderr {
		stream = 2
	}
	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(frameDockerRawStream(stream, data))
}

func (s *containerStore) init() error {
	if err := os.MkdirAll(filepath.Join(s.stateDir, "containers"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.stateDir, "images"), 0o755); err != nil {
		return err
	}
	return s.loadAll()
}

func (s *containerStore) loadAll() error {
	entries, err := os.ReadDir(filepath.Join(s.stateDir, "containers"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.stateDir, "containers", entry.Name()))
		if err != nil {
			continue
		}
		var c Container
		if err := json.Unmarshal(data, &c); err != nil {
			continue
		}
		s.containers[c.ID] = &c
	}
	return nil
}

func (s *containerStore) containerPath(id string) string {
	return filepath.Join(s.stateDir, "containers", id+".json")
}

func (s *containerStore) save(c *Container) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.containers[c.ID] = c
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.containerPath(c.ID), data, 0o644)
}

func (s *containerStore) get(id string) (*Container, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = normalizeContainerName(id)
	if c, ok := s.containers[id]; ok {
		return c, true
	}
	for _, c := range s.containers {
		if c.Name != "" && normalizeContainerName(c.Name) == id {
			return c, true
		}
	}
	for containerID, c := range s.containers {
		if strings.HasPrefix(containerID, id) {
			return c, true
		}
	}
	return nil, false
}

func (s *containerStore) markStopped(id string) {
	s.mu.Lock()
	c, ok := s.containers[id]
	if ok {
		c.Running = false
		c.Pid = 0
		_ = s.saveLocked(c)
	}
	s.mu.Unlock()
}

func (s *containerStore) saveLocked(c *Container) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.containerPath(c.ID), data, 0o644)
}

func (s *containerStore) listContainers() []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]interface{}, 0, len(s.containers))
	for _, c := range s.containers {
		out = append(out, map[string]interface{}{
			"Id":      c.ID,
			"Image":   c.Image,
			"Command": strings.Join(c.Cmd, " "),
			"Created": c.Created.Unix(),
			"State":   statusFromRunning(c.Running),
			"Status":  statusFromRunning(c.Running),
			"Ports":   toDockerPortSummaries(c.Ports),
			"Names":   []string{containerDisplayName(c)},
		})
	}
	return out
}

func normalizeContainerName(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "/")
}

func containerDisplayName(c *Container) string {
	name := normalizeContainerName(c.Name)
	if name == "" {
		name = c.ID
	}
	return "/" + name
}

func (s *containerStore) nameInUse(raw string) bool {
	name := normalizeContainerName(raw)
	if name == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.containers {
		if normalizeContainerName(c.Name) == name {
			return true
		}
	}
	return false
}

func (s *containerStore) setProxies(id string, proxies []*portProxy) {
	s.mu.Lock()
	s.proxies[id] = proxies
	s.mu.Unlock()
}

func (s *containerStore) stopProxies(id string) {
	s.mu.Lock()
	proxies := s.proxies[id]
	delete(s.proxies, id)
	s.mu.Unlock()
	for _, proxy := range proxies {
		proxy.stopProxy()
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

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func resolveCommandInRootfs(rootfs string, cmdArgs []string) []string {
	if len(cmdArgs) == 0 {
		return cmdArgs
	}
	cmd := strings.TrimSpace(cmdArgs[0])
	if cmd == "" || !strings.HasPrefix(cmd, "/") {
		return cmdArgs
	}
	joined := filepath.Join(rootfs, strings.TrimPrefix(cmd, "/"))
	if fileExists(joined) {
		return cmdArgs
	}
	base := filepath.Base(cmd)
	for _, dir := range []string{"/bin", "/usr/bin", "/usr/local/bin", "/app", "/"} {
		candidate := filepath.Join(rootfs, strings.TrimPrefix(dir, "/"), base)
		if fileExists(candidate) {
			adjusted := append([]string{}, cmdArgs...)
			adjusted[0] = filepath.Join(dir, base)
			return adjusted
		}
	}
	if found, ok := findExecutableByBase(rootfs, base); ok {
		adjusted := append([]string{}, cmdArgs...)
		adjusted[0] = found
		return adjusted
	}
	return cmdArgs
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() || (info.Mode()&os.ModeSymlink) != 0
}

func findExecutableByBase(rootfs string, base string) (string, bool) {
	if strings.TrimSpace(base) == "" {
		return "", false
	}
	var found string
	const maxEntries = 50000
	seen := 0
	_ = filepath.WalkDir(rootfs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen >= maxEntries {
			return fs.SkipAll
		}
		seen++
		if d.IsDir() {
			return nil
		}
		if filepath.Base(p) != base {
			return nil
		}
		rel, relErr := filepath.Rel(rootfs, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || strings.HasPrefix(rel, "../") {
			return nil
		}
		found = "/" + rel
		return fs.SkipAll
	})
	return found, found != ""
}

func firstArg(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}
	return cmd[0]
}

func restArgs(cmd []string) []string {
	if len(cmd) <= 1 {
		return nil
	}
	return cmd[1:]
}

func statusFromRunning(running bool) string {
	if running {
		return "running"
	}
	return "exited"
}

func loadAllowedImagePrefixes(flagList string, flagFile string) ([]string, error) {
	rawList := strings.TrimSpace(flagList)
	if rawList == "" {
		rawList = strings.TrimSpace(os.Getenv("TCEXECUTOR_ALLOWED_IMAGES"))
	}
	filePath := strings.TrimSpace(flagFile)
	if filePath == "" {
		filePath = strings.TrimSpace(os.Getenv("TCEXECUTOR_IMAGE_POLICY_FILE"))
	}

	prefixes := splitCSV(rawList)
	if filePath != "" {
		filePrefixes, err := readImagePolicyFile(filePath)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, filePrefixes...)
	}
	return normalizeUniquePrefixes(prefixes), nil
}

func loadImageMirrorRules(flagList string, flagFile string) ([]imageMirrorRule, error) {
	rawList := strings.TrimSpace(flagList)
	if rawList == "" {
		rawList = strings.TrimSpace(os.Getenv("TCEXECUTOR_IMAGE_MIRRORS"))
	}
	filePath := strings.TrimSpace(flagFile)
	if filePath == "" {
		filePath = strings.TrimSpace(os.Getenv("TCEXECUTOR_IMAGE_MIRROR_FILE"))
	}

	rules := parseMirrorCSV(rawList)
	if filePath != "" {
		fileRules, err := readImageMirrorFile(filePath)
		if err != nil {
			return nil, err
		}
		rules = append(rules, fileRules...)
	}
	return normalizeMirrorRules(rules), nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseMirrorCSV(raw string) []imageMirrorRule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]imageMirrorRule, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		from, to, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out = append(out, imageMirrorRule{FromPrefix: from, ToPrefix: to})
	}
	return out
}

func readImageMirrorFile(path string) ([]imageMirrorRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image mirror file: %w", err)
	}
	var asList []imageMirrorRule
	if err := yaml.Unmarshal(data, &asList); err == nil && len(asList) > 0 {
		return asList, nil
	}
	var cfg imageMirrorFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse image mirror file: %w", err)
	}
	merged := append([]imageMirrorRule{}, cfg.ImageMirrors...)
	merged = append(merged, cfg.Mirrors...)
	return merged, nil
}

func normalizeMirrorRules(in []imageMirrorRule) []imageMirrorRule {
	out := make([]imageMirrorRule, 0, len(in))
	seen := map[string]struct{}{}
	for _, rule := range in {
		from := normalizeImageToken(rule.FromPrefix)
		to := normalizeImageToken(rule.ToPrefix)
		if from == "" || to == "" {
			continue
		}
		key := from + "=>" + to
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, imageMirrorRule{FromPrefix: from, ToPrefix: to})
	}
	return out
}

func readImagePolicyFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image policy file: %w", err)
	}
	var asList []string
	if err := yaml.Unmarshal(data, &asList); err == nil && len(asList) > 0 {
		return asList, nil
	}
	var cfg imagePolicyFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse image policy file: %w", err)
	}
	merged := append([]string{}, cfg.AllowedImages...)
	merged = append(merged, cfg.AllowedImagePrefixes...)
	merged = append(merged, cfg.Images...)
	return merged, nil
}

func normalizeUniquePrefixes(prefixes []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		p := normalizeImageToken(prefix)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func isImageAllowed(ref string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, candidate := range imageMatchCandidates(ref) {
		for _, prefix := range prefixes {
			if strings.HasPrefix(candidate, prefix) {
				return true
			}
		}
	}
	return false
}

func rewriteImageReference(ref string, rules []imageMirrorRule) string {
	ref = normalizeImageToken(ref)
	if ref == "" || len(rules) == 0 {
		return ref
	}
	candidates := orderedImageCandidates(ref, false)
	for _, rule := range rules {
		for _, candidate := range candidates {
			if strings.HasPrefix(candidate, rule.FromPrefix) {
				return rule.ToPrefix + strings.TrimPrefix(candidate, rule.FromPrefix)
			}
		}
	}
	return ref
}

func imageMatchCandidates(ref string) []string {
	return orderedImageCandidates(ref, true)
}

func orderedImageCandidates(ref string, includeContext bool) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 6)
	add := func(s string) {
		s = normalizeImageToken(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
		for _, alias := range dockerHubAliases(s) {
			if _, ok := seen[alias]; ok {
				continue
			}
			seen[alias] = struct{}{}
			out = append(out, alias)
		}
	}
	add(ref)
	if parsed, err := name.ParseReference(strings.TrimSpace(ref)); err == nil {
		add(parsed.Name())
		if includeContext {
			add(parsed.Context().Name())
		}
	}
	return out
}

func normalizeImageToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func dockerHubAliases(s string) []string {
	s = normalizeImageToken(s)
	if s == "" {
		return nil
	}
	const dockerIO = "docker.io/"
	const indexDockerIO = "index.docker.io/"
	switch {
	case strings.HasPrefix(s, dockerIO):
		return []string{indexDockerIO + strings.TrimPrefix(s, dockerIO)}
	case strings.HasPrefix(s, indexDockerIO):
		return []string{dockerIO + strings.TrimPrefix(s, indexDockerIO)}
	default:
		return nil
	}
}

// Placeholder for future port proxy implementation.
func allocatePort() (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// Placeholder for future use when port bindings are added.
func parsePort(port string) (int, error) {
	port = strings.TrimSpace(strings.TrimSuffix(port, "/tcp"))
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	return p, nil
}

func resolvePortBindings(req createRequest) (map[int]int, error) {
	ports := map[int]int{}
	for port := range req.ExposedPorts {
		cp, err := parsePort(port)
		if err != nil {
			return nil, err
		}
		if _, ok := ports[cp]; !ok {
			hp, err := allocatePort()
			if err != nil {
				return nil, err
			}
			ports[cp] = hp
		}
	}
	for port, bindings := range req.HostConfig.PortBindings {
		cp, err := parsePort(port)
		if err != nil {
			return nil, err
		}
		hostPort := 0
		for _, binding := range bindings {
			if binding.HostPort == "" {
				continue
			}
			hp, err := strconv.Atoi(binding.HostPort)
			if err != nil {
				return nil, fmt.Errorf("invalid host port: %w", err)
			}
			hostPort = hp
			break
		}
		if hostPort == 0 {
			hp, err := allocatePort()
			if err != nil {
				return nil, err
			}
			hostPort = hp
		}
		ports[cp] = hostPort
	}
	return ports, nil
}

func toDockerPorts(ports map[int]int) map[string][]map[string]string {
	result := map[string][]map[string]string{}
	for containerPort, hostPort := range ports {
		key := fmt.Sprintf("%d/tcp", containerPort)
		result[key] = []map[string]string{
			{
				"HostIp":   "0.0.0.0",
				"HostPort": strconv.Itoa(hostPort),
			},
		}
	}
	return result
}

func toDockerPortSummaries(ports map[int]int) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(ports))
	for containerPort, hostPort := range ports {
		out = append(out, map[string]interface{}{
			"IP":          "0.0.0.0",
			"PrivatePort": containerPort,
			"PublicPort":  hostPort,
			"Type":        "tcp",
		})
	}
	return out
}

func frameDockerRawStream(stream byte, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	out[0] = stream
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:], payload)
	return out
}

func parseDockerBool(raw string, defaultValue bool) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return defaultValue
	}
	return raw == "1" || raw == "true"
}

func startPortProxies(ports map[int]int) ([]*portProxy, error) {
	var proxies []*portProxy
	for containerPort, hostPort := range ports {
		proxy, err := startPortProxy(hostPort, containerPort)
		if err != nil {
			for _, p := range proxies {
				p.stopProxy()
			}
			return nil, err
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}

func startPortProxy(hostPort, containerPort int) (*portProxy, error) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(hostPort))
	if err != nil {
		return nil, err
	}
	p := &portProxy{ln: ln, stop: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-p.stop:
					return
				default:
					return
				}
			}
			go proxyConn(conn, containerPort)
		}
	}()
	return p, nil
}

func (p *portProxy) stopProxy() {
	select {
	case <-p.stop:
		return
	default:
		close(p.stop)
		_ = p.ln.Close()
	}
}

func proxyConn(src net.Conn, containerPort int) {
	defer src.Close()
	dst, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(containerPort))
	if err != nil {
		return
	}
	defer dst.Close()
	go func() {
		_, _ = io.Copy(dst, src)
		_ = dst.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(src, dst)
	_ = src.(*net.TCPConn).CloseWrite()
}

func monitorContainer(id string, pid int, logPath string, store *containerStore, limits runtimeLimits) {
	if pid <= 0 {
		return
	}
	if limits.maxRuntime <= 0 && limits.maxLogBytes <= 0 && limits.maxMemBytes <= 0 {
		return
	}
	deadline := time.Now().Add(limits.maxRuntime)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !processAlive(pid) {
			return
		}
		if limits.maxRuntime > 0 && time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			store.markStopped(id)
			return
		}
		if limits.maxLogBytes > 0 {
			if info, err := os.Stat(logPath); err == nil && info.Size() > limits.maxLogBytes {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				store.markStopped(id)
				return
			}
		}
		if limits.maxMemBytes > 0 {
			if rss, err := readRSS(pid); err == nil && rss > limits.maxMemBytes {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				store.markStopped(id)
				return
			}
		}
	}
}

func readRSS(pid int) (int64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return val * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found")
}

func mergeEnv(base, override []string) []string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	out := make([]string, 0, len(base)+len(override))
	seen := map[string]int{}
	for _, env := range base {
		key, _ := splitEnv(env)
		if key == "" {
			continue
		}
		seen[key] = len(out)
		out = append(out, env)
	}
	for _, env := range override {
		key, _ := splitEnv(env)
		if key == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			out[idx] = env
			continue
		}
		seen[key] = len(out)
		out = append(out, env)
	}
	return out
}

func splitEnv(env string) (string, string) {
	parts := strings.SplitN(env, "=", 2)
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func listImages(stateDir string) ([]map[string]interface{}, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(imageRoot, entry.Name(), "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta imageMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"Id":       meta.Digest,
			"RepoTags": []string{meta.Reference},
		})
	}
	return out, nil
}

func ensureImage(ctx context.Context, ref string, stateDir string, m *metrics) (string, imageMeta, error) {
	ref = strings.TrimSpace(ref)
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("invalid image reference: %w", err)
	}
	image, err := remote.Image(parsed, remote.WithContext(ctx), remote.WithPlatform(v1.Platform{
		OS:           "linux",
		Architecture: "amd64",
	}))
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
	for _, layer := range layers {
		if err := extractLayer(tmpRootfs, layer); err != nil {
			_ = os.RemoveAll(tmpRootfs)
			return "", imageMeta{}, err
		}
	}
	if err := os.Rename(tmpRootfs, rootfsDir); err != nil {
		_ = os.RemoveAll(tmpRootfs)
		return "", imageMeta{}, fmt.Errorf("rootfs finalize failed: %w", err)
	}

	meta := imageMeta{
		Reference: ref,
		Digest:    digest.String(),
		Extractor: extractorVersion,
	}
	if cfg, err := image.ConfigFile(); err == nil && cfg != nil {
		meta.Entrypoint = cfg.Config.Entrypoint
		meta.Cmd = cfg.Config.Cmd
		meta.Env = cfg.Config.Env
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

func extractLayer(rootfs string, layer v1.Layer) error {
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
			if err := os.MkdirAll(targetPath, fs.FileMode(h.Mode)); err != nil {
				return fmt.Errorf("mkdir failed: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
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
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
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
			return os.MkdirAll(target, info.Mode())
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
			srcFile, err := os.Open(path)
			if err != nil {
				return err
			}
			defer srcFile.Close()
			dstFile, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
			if err != nil {
				return err
			}
			if _, err := io.Copy(dstFile, srcFile); err != nil {
				dstFile.Close()
				return err
			}
			dstFile.Close()
			return nil
		}
		return nil
	})
}
