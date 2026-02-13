package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
	"sort"
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
	ID         string    `json:"Id"`
	Name       string    `json:"Name,omitempty"`
	Hostname   string    `json:"Hostname,omitempty"`
	User       string    `json:"User,omitempty"`
	Image      string    `json:"Image"`
	Rootfs     string    `json:"Rootfs"`
	Created    time.Time `json:"Created"`
	Running    bool      `json:"Running"`
	Ports      map[int]int
	Env        []string `json:"Env"`
	LogPath    string   `json:"LogPath"`
	Pid        int      `json:"Pid"`
	Cmd        []string `json:"Cmd"`
	WorkingDir string   `json:"WorkingDir"`
}

type containerStore struct {
	mu         sync.Mutex
	containers map[string]*Container
	execs      map[string]*ExecInstance
	stateDir   string
	proxies    map[string][]*portProxy
}

type ExecInstance struct {
	ID          string
	ContainerID string
	Cmd         []string
	Running     bool
	ExitCode    int
	Output      []byte
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
	Hostname     string              `json:"Hostname"`
	User         string              `json:"User"`
	Cmd          []string            `json:"Cmd"`
	Env          []string            `json:"Env"`
	Entrypoint   []string            `json:"Entrypoint"`
	WorkingDir   string              `json:"WorkingDir"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	HostConfig   hostConfig          `json:"HostConfig"`
}

type execCreateRequest struct {
	Cmd          []string `json:"Cmd"`
	AttachStdout bool     `json:"AttachStdout"`
	AttachStderr bool     `json:"AttachStderr"`
}

type execCreateResponse struct {
	ID string `json:"Id"`
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
	Reference    string              `json:"Reference"`
	Digest       string              `json:"Digest"`
	Entrypoint   []string            `json:"Entrypoint"`
	Cmd          []string            `json:"Cmd"`
	Env          []string            `json:"Env"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	WorkingDir   string              `json:"WorkingDir"`
	User         string              `json:"User,omitempty"`
	Extractor    string              `json:"Extractor,omitempty"`
	ContentSize  int64               `json:"ContentSize,omitempty"`
	DiskUsage    int64               `json:"DiskUsage,omitempty"`
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
		listenAddr    = flag.String("listen", ":23750", "listen address")
		stateDir      = flag.String("state-dir", "/tmp/tcexecutor", "state directory")
		maxConcurrent = flag.Int("max-concurrent", 4, "max concurrent containers (0 = unlimited)")
		maxRuntime    = flag.Duration("max-runtime", 30*time.Minute, "max runtime per container (0 = unlimited)")
		maxLogBytes   = flag.Int64("max-log-bytes", 50*1024*1024, "max log size in bytes (0 = unlimited)")
		maxMemBytes   = flag.Int64("max-mem-bytes", 0, "soft memory limit in bytes (0 = unlimited)")
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
		execs:      make(map[string]*ExecInstance),
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

	fmt.Printf("tcexecutor listening on %s\n", *listenAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeout := requestTimeoutFor(r)
		if timeout <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestTimeoutFor(r *http.Request) time.Duration {
	path := r.URL.Path
	if rewritten, ok := rewriteVersionedPath(path); ok {
		path = rewritten
	}
	// Image pulls can take much longer than normal control-plane calls.
	if r.Method == http.MethodPost && path == "/images/create" {
		return 10 * time.Minute
	}
	// Rootfs clone for large images can also take longer than default.
	if r.Method == http.MethodPost && path == "/containers/create" {
		return 10 * time.Minute
	}
	// Docker clients may keep log follow streams open for long periods.
	if r.Method == http.MethodGet && strings.HasSuffix(path, "/logs") && parseDockerBool(r.URL.Query().Get("follow"), false) {
		return 0
	}
	// Wait endpoints are expected to block until exit.
	if r.Method == http.MethodPost && strings.HasSuffix(path, "/wait") {
		return 0
	}
	return 30 * time.Second
}

func requireUnprivilegedRuntime(euid int) error {
	if euid == 0 {
		return fmt.Errorf("refusing to run as root (uid 0)")
	}
	return nil
}

func buildContainerCommand(rootfs, tmpBind, workingDir, userSpec string, cmdArgs []string) (*exec.Cmd, error) {
	if len(cmdArgs) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	prootPath, err := findProotPath()
	if err != nil {
		return nil, err
	}
	if workingDir == "" {
		workingDir = "/"
	}
	if strings.TrimSpace(tmpBind) == "" {
		tmpBind = "/tmp"
	}
	// -r: explicit guest rootfs (avoiding -R auto-binds)
	// -b /proc, /dev, /tmp, /sys/fs/cgroup: explicit essential binds
	// -w: set working directory
	args := []string{
		"-r", rootfs,
		"-b", "/proc",
		"-b", "/dev",
		"-b", "/sys/fs/cgroup",
		"-b", tmpBind + ":/tmp",
		"-w", workingDir,
	}
	if identity, ok := resolveProotIdentity(rootfs, userSpec); ok {
		args = append(args, "-i", identity)
	}
	// Wrap with /usr/bin/env to ensure the guest environment is used for resolution
	// if /usr/bin/env exists in the guest, otherwise use the command directly.
	if fileExists(filepath.Join(rootfs, "/usr/bin/env")) {
		args = append(args, "/usr/bin/env")
	} else if fileExists(filepath.Join(rootfs, "/bin/env")) {
		args = append(args, "/bin/env")
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
	if !envHasKey(env, "HOSTNAME") && hostname != "" {
		env = append(env, "HOSTNAME="+hostname)
	}
	if isOracleImage(resolvedRef) || isOracleImage(req.Image) {
		if !envHasKey(env, "ORACLE_HOSTNAME") {
			env = append(env, "ORACLE_HOSTNAME="+hostname)
		}
	}
	if isRabbitMQImage(resolvedRef) || isRabbitMQImage(req.Image) {
		if !envHasKey(env, "RABBITMQ_NODENAME") {
			env = append(env, "RABBITMQ_NODENAME=rabbit@"+hostname)
		}
		if !envHasKey(env, "ERL_EPMD_PORT") {
			if epmdPort, epmdErr := allocatePort(); epmdErr == nil {
				env = append(env, "ERL_EPMD_PORT="+strconv.Itoa(epmdPort))
			}
		}
		if !envHasKey(env, "RABBITMQ_DIST_PORT") {
			if distPort, distErr := allocatePort(); distErr == nil {
				env = append(env, "RABBITMQ_DIST_PORT="+strconv.Itoa(distPort))
			}
		}
	}
	if isRyukImage(resolvedRef) || isRyukImage(req.Image) {
		env = mergeEnv(env, []string{"DOCKER_HOST=" + dockerHostForInnerClients(r.Host)})
	}
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

	cmd, err := buildContainerCommand(c.Rootfs, containerTmpDir(c), c.WorkingDir, c.User, cmdArgs)
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
	fmt.Printf("tcexecutor: starting container %s (id %s)\n", c.Name, c.ID)
	fmt.Printf("tcexecutor: command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))

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
	cmd, err := buildContainerCommand(c.Rootfs, containerTmpDir(c), c.WorkingDir, c.User, cmdArgs)
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
	if err := extractArchiveToPath(r.Body, targetPath); err != nil {
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

func extractArchiveToPath(r io.Reader, targetPath string) error {
	tmpDir, err := os.MkdirTemp("", "tcexecutor-archive-*")
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
		return copyDirContents(tmpDir, targetPath)
	}
	if len(top) == 1 {
		return copyFSNode(filepath.Join(tmpDir, top[0]), targetPath)
	}
	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		return err
	}
	return copyDirContents(tmpDir, targetPath)
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

func containerTmpDir(c *Container) string {
	if c == nil {
		return "/tmp"
	}
	return filepath.Join(filepath.Dir(c.Rootfs), "tmp")
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

func (s *containerStore) saveExec(inst *ExecInstance) {
	s.mu.Lock()
	s.execs[inst.ID] = inst
	s.mu.Unlock()
}

func (s *containerStore) getExec(id string) (*ExecInstance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.execs[id]
	return inst, ok
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

func resolveCommandInRootfs(rootfs string, env []string, cmdArgs []string) []string {
	if len(cmdArgs) == 0 {
		return cmdArgs
	}
	adjusted := append([]string{}, cmdArgs...)
	if resolved, ok := resolveBinaryPathInRootfs(rootfs, env, adjusted[0]); ok {
		adjusted[0] = resolved
	}
	adjusted = rewriteShebangCommand(rootfs, env, adjusted)
	return rewriteKnownEntrypointCompat(adjusted)
}

func rewriteKnownEntrypointCompat(cmdArgs []string) []string {
	if len(cmdArgs) >= 3 && strings.HasSuffix(cmdArgs[0], "/bash") && strings.HasSuffix(cmdArgs[1], "/opt/mssql/bin/launch_sqlservr.sh") {
		// In proot 5.1.0, bash `test -x` inside launch_sqlservr.sh can fail with false ENOENT.
		// Running sqlservr directly avoids this check and starts successfully.
		return append([]string{cmdArgs[2]}, cmdArgs[3:]...)
	}
	if len(cmdArgs) >= 2 && strings.HasSuffix(cmdArgs[0], "/opt/mssql/bin/launch_sqlservr.sh") {
		return append([]string{cmdArgs[1]}, cmdArgs[2:]...)
	}
	return cmdArgs
}

func resolveBinaryPathInRootfs(rootfs string, env []string, cmd string) (string, bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", false
	}

	// If absolute path provided, check it directly.
	if strings.HasPrefix(cmd, "/") {
		joined := filepath.Join(rootfs, strings.TrimPrefix(cmd, "/"))
		if fileExists(joined) {
			return cmd, true
		}
	}

	// Try searching in PATH from env.
	pathVal := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			pathVal = strings.TrimPrefix(e, "PATH=")
			break
		}
	}
	base := filepath.Base(cmd)
	searchDirs := strings.Split(pathVal, ":")
	searchDirs = append(searchDirs, "/app", "/")
	for _, dir := range searchDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		candidate := filepath.Join(rootfs, strings.TrimPrefix(dir, "/"), base)
		if fileExists(candidate) {
			return filepath.Join(dir, base), true
		}
	}

	// Exhaustive search as a last resort.
	if found, ok := findExecutableByBase(rootfs, base); ok {
		return found, true
	}

	return "", false
}

func rewriteShebangCommand(rootfs string, env []string, cmdArgs []string) []string {
	if len(cmdArgs) == 0 {
		return cmdArgs
	}
	if !strings.HasPrefix(cmdArgs[0], "/") {
		return cmdArgs
	}

	scriptPath := filepath.Join(rootfs, strings.TrimPrefix(cmdArgs[0], "/"))
	line, err := readFirstLine(scriptPath)
	if err != nil || !strings.HasPrefix(line, "#!") {
		return cmdArgs
	}

	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return cmdArgs
	}

	interpreter := fields[0]
	interpArgs := fields[1:]
	if interpreter == "/usr/bin/env" || interpreter == "/bin/env" {
		if len(interpArgs) == 0 {
			return cmdArgs
		}
		interpreter = interpArgs[0]
		interpArgs = interpArgs[1:]
	}

	resolvedInterp, ok := resolveBinaryPathInRootfs(rootfs, env, interpreter)
	if !ok {
		return cmdArgs
	}

	rewritten := []string{resolvedInterp}
	rewritten = append(rewritten, interpArgs...)
	rewritten = append(rewritten, cmdArgs...)
	return rewritten
}

func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if n == 0 {
		return "", io.EOF
	}
	line := string(buf[:n])
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSuffix(line, "\r"), nil
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return info.Mode().IsRegular()
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

func imageRefHasTag(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	return colon > slash
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

func resolvePortBindings(exposedPorts map[string]struct{}, hostBindings map[string][]portBinding) (map[int]int, error) {
	ports := map[int]int{}
	for port := range exposedPorts {
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
	for port, bindings := range hostBindings {
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
	dst, err := dialContainerPort(containerPort)
	if err != nil {
		fmt.Printf("tcexecutor: proxy dial failed containerPort=%d err=%v\n", containerPort, err)
		return
	}
	defer dst.Close()
	done := make(chan struct{})
	var c2sBytes int64
	var c2sSample string
	var c2sErr error
	go func() {
		c2sBytes, c2sSample, c2sErr = proxyCopy(dst, src)
		if c2sErr != nil {
			fmt.Printf("tcexecutor: proxy c->s copy error containerPort=%d bytes=%d err=%v\n", containerPort, c2sBytes, c2sErr)
		}
		_ = closeWrite(dst)
		close(done)
	}()
	s2cBytes, s2cSample, s2cErr := proxyCopy(src, dst)
	if s2cErr != nil {
		fmt.Printf("tcexecutor: proxy s->c copy error containerPort=%d bytes=%d err=%v\n", containerPort, s2cBytes, s2cErr)
	}
	_ = closeWrite(src)
	<-done
	if c2sErr != nil || s2cErr != nil {
		fmt.Printf("tcexecutor: proxy closed containerPort=%d c2s=%d s2c=%d c2sErr=%v s2cErr=%v c2sSample=%s s2cSample=%s\n", containerPort, c2sBytes, s2cBytes, c2sErr, s2cErr, c2sSample, s2cSample)
	}
}

// proxyCopy intentionally avoids io.Copy to prevent splice/zero-copy quirks in long-lived protocol streams.
func proxyCopy(dst net.Conn, src net.Conn) (int64, string, error) {
	buf := make([]byte, 32*1024)
	var written int64
	sample := make([]byte, 0, 64)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if len(sample) < cap(sample) {
				take := nr
				remaining := cap(sample) - len(sample)
				if take > remaining {
					take = remaining
				}
				sample = append(sample, buf[:take]...)
			}
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, hex.EncodeToString(sample), ew
			}
			if nw != nr {
				return written, hex.EncodeToString(sample), io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, hex.EncodeToString(sample), nil
			}
			return written, hex.EncodeToString(sample), er
		}
	}
}

func closeWrite(conn net.Conn) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	return tcp.CloseWrite()
}

func dialContainerPort(containerPort int) (net.Conn, error) {
	port := strconv.Itoa(containerPort)
	endpoints := []string{
		"127.0.0.1:" + port,
		"[::1]:" + port,
	}
	var lastErr error
	for _, ep := range endpoints {
		conn, err := net.DialTimeout("tcp", ep, 2*time.Second)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoint candidates")
	}
	return nil, lastErr
}

func monitorContainer(id string, pid int, logPath string, store *containerStore, limits runtimeLimits) {
	if pid <= 0 {
		return
	}
	c, ok := store.get(id)
	checkOracleFatal := ok && isOracleImage(c.Image)
	if limits.maxRuntime <= 0 && limits.maxLogBytes <= 0 && limits.maxMemBytes <= 0 && !checkOracleFatal {
		return
	}
	deadline := time.Now().Add(limits.maxRuntime)
	var scannedOffset int64
	var scannedCarry string
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !processAlive(pid) {
			return
		}
		if limits.maxRuntime > 0 && time.Now().After(deadline) {
			fmt.Printf("tcexecutor: monitor killed container id=%s pid=%d reason=max_runtime limit=%s\n", id, pid, limits.maxRuntime)
			_ = killProcessGroup(pid, syscall.SIGKILL)
			store.markStopped(id)
			return
		}
		if limits.maxLogBytes > 0 {
			if info, err := os.Stat(logPath); err == nil && info.Size() > limits.maxLogBytes {
				fmt.Printf("tcexecutor: monitor killed container id=%s pid=%d reason=max_log_bytes size=%d limit=%d\n", id, pid, info.Size(), limits.maxLogBytes)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				store.markStopped(id)
				return
			}
		}
		if limits.maxMemBytes > 0 {
			if rss, err := readRSS(pid); err == nil && rss > limits.maxMemBytes {
				fmt.Printf("tcexecutor: monitor killed container id=%s pid=%d reason=max_mem_bytes rss=%d limit=%d\n", id, pid, rss, limits.maxMemBytes)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				store.markStopped(id)
				return
			}
		}
		if checkOracleFatal {
			matched, sig, nextOffset, nextCarry := scanFatalLogSignatures(logPath, scannedOffset, scannedCarry, oracleFatalLogSignatures)
			scannedOffset = nextOffset
			scannedCarry = nextCarry
			if matched {
				fmt.Printf("tcexecutor: monitor killed container id=%s pid=%d reason=fatal_log signature=%q\n", id, pid, sig)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				store.markStopped(id)
				return
			}
		}
	}
}

var oracleFatalLogSignatures = []string{
	"ora-27300: os system dependent operation:pr_set_dumpable failed",
	"ora-27301: os failure message: function not implemented",
	"ora-27302: failure occurred at: sskgp_mod_fd",
	"sp2-0157: unable to connect to oracle",
}

func scanFatalLogSignatures(logPath string, offset int64, carry string, signatures []string) (bool, string, int64, string) {
	info, err := os.Stat(logPath)
	if err != nil {
		return false, "", offset, carry
	}
	if info.Size() < offset {
		offset = 0
		carry = ""
	}
	if info.Size() == offset {
		return false, "", offset, carry
	}

	f, err := os.Open(logPath)
	if err != nil {
		return false, "", offset, carry
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return false, "", offset, carry
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return false, "", offset, carry
	}
	offset += int64(len(data))

	text := strings.ToLower(carry + string(data))
	for _, sig := range signatures {
		if strings.Contains(text, sig) {
			return true, sig, offset, carry
		}
	}

	const maxCarry = 4096
	if len(text) > maxCarry {
		carry = text[len(text)-maxCarry:]
	} else {
		carry = text
	}
	return false, "", offset, carry
}

func terminateProcessTree(pid int, grace time.Duration) {
	if pid <= 0 {
		return
	}
	_ = killProcessGroup(pid, syscall.SIGTERM)
	if grace <= 0 {
		_ = killProcessGroup(pid, syscall.SIGKILL)
		return
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = killProcessGroup(pid, syscall.SIGKILL)
}

func killProcessGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, sig)
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

func envHasKey(env []string, key string) bool {
	for _, e := range env {
		k, _ := splitEnv(e)
		if k == key {
			return true
		}
	}
	return false
}

func deduplicateEnv(env []string) []string {
	out := make([]string, 0, len(env))
	seen := map[string]int{}
	for _, e := range env {
		key, _ := splitEnv(e)
		if key == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			out[idx] = e
			continue
		}
		seen[key] = len(out)
		out = append(out, e)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resolveProotIdentity(rootfs, userSpec string) (string, bool) {
	spec := strings.TrimSpace(userSpec)
	if spec == "" {
		return "", false
	}

	userPart := spec
	groupPart := ""
	if i := strings.Index(spec, ":"); i >= 0 {
		userPart = spec[:i]
		groupPart = spec[i+1:]
	}

	uid, defaultGID, ok := resolveUserToken(rootfs, userPart)
	if !ok {
		return "", false
	}
	gid := defaultGID
	if strings.TrimSpace(groupPart) != "" {
		groupID, gok := resolveGroupToken(rootfs, groupPart)
		if !gok {
			return "", false
		}
		gid = groupID
	}
	if gid == "" {
		gid = uid
	}
	return uid + ":" + gid, true
}

func resolveUserToken(rootfs, token string) (uid, gid string, ok bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", "", false
	}
	if isDigits(t) {
		if gid, found := lookupGIDForUID(rootfs, t); found {
			return t, gid, true
		}
		return t, t, true
	}
	return lookupUserByName(rootfs, t)
}

func resolveGroupToken(rootfs, token string) (string, bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", false
	}
	if isDigits(t) {
		return t, true
	}
	return lookupGroupByName(rootfs, t)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func lookupUserByName(rootfs, name string) (uid, gid string, ok bool) {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] != name {
			continue
		}
		if !isDigits(fields[2]) || !isDigits(fields[3]) {
			return "", "", false
		}
		return fields[2], fields[3], true
	}
	return "", "", false
}

func lookupGIDForUID(rootfs, uid string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[2] != uid {
			continue
		}
		if !isDigits(fields[3]) {
			return "", false
		}
		return fields[3], true
	}
	return "", false
}

func lookupGroupByName(rootfs, name string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "group"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[0] != name {
			continue
		}
		if !isDigits(fields[2]) {
			return "", false
		}
		return fields[2], true
	}
	return "", false
}

func defaultContainerHostname(id string) string {
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

func normalizeContainerHostname(hostname string) string {
	h := strings.TrimSpace(hostname)
	if h == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range h {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return ""
	}
	return out
}

func writeContainerIdentityFiles(rootfs, hostname string) error {
	if strings.TrimSpace(hostname) == "" {
		return nil
	}
	etcDir := filepath.Join(rootfs, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(etcDir, "hostname"), []byte(hostname+"\n"), 0o644); err != nil {
		return err
	}
	hostsPath := filepath.Join(etcDir, "hosts")
	current, _ := os.ReadFile(hostsPath)
	if hostsFileHasHostname(current, hostname) {
		return nil
	}
	var content strings.Builder
	if len(current) == 0 {
		content.WriteString("127.0.0.1\tlocalhost\n")
		content.WriteString("::1\tlocalhost ip6-localhost ip6-loopback\n")
	} else {
		content.Write(current)
		if len(current) > 0 && current[len(current)-1] != '\n' {
			content.WriteByte('\n')
		}
	}
	content.WriteString("127.0.1.1\t")
	content.WriteString(hostname)
	content.WriteByte('\n')
	return os.WriteFile(hostsPath, []byte(content.String()), 0o644)
}

func hostsFileHasHostname(data []byte, hostname string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, f := range fields[1:] {
			if f == hostname {
				return true
			}
		}
	}
	return false
}

func isRyukImage(image string) bool {
	norm := strings.ToLower(strings.TrimSpace(image))
	norm = strings.TrimPrefix(norm, "docker.io/")
	return strings.Contains(norm, "testcontainers/ryuk")
}

func isRabbitMQImage(image string) bool {
	norm := strings.ToLower(strings.TrimSpace(image))
	norm = strings.TrimPrefix(norm, "docker.io/")
	return strings.Contains(norm, "rabbitmq")
}

func isOracleImage(image string) bool {
	norm := strings.ToLower(strings.TrimSpace(image))
	norm = strings.TrimPrefix(norm, "docker.io/")
	return strings.Contains(norm, "oracle")
}

func dockerHostForInnerClients(requestHost string) string {
	host := strings.TrimSpace(requestHost)
	if host == "" {
		return "tcp://127.0.0.1:23750"
	}
	if strings.Contains(host, "://") {
		return host
	}
	return "tcp://" + host
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
		if meta.DiskUsage == 0 {
			if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
				meta.DiskUsage = size
			}
		}
		out = append(out, map[string]interface{}{
			"Id":          meta.Digest,
			"RepoTags":    []string{meta.Reference},
			"Size":        meta.ContentSize,
			"VirtualSize": meta.DiskUsage,
			"SharedSize":  0,
		})
	}
	return out, nil
}

func mergeExposedPorts(base, override map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
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
