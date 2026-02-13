package main

import (
	"archive/tar"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
