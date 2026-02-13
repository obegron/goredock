package main

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

func newRouter(store *containerStore, m *metrics, cfg appConfig, probes *probeState) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/healthz", probes.handleHealthz)
	mux.HandleFunc("/readyz", probes.handleReadyz)
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
		handleImagesCreate(w, r, store, m, cfg, ensureImage)
	})
	mux.HandleFunc("/images/prune", handleImagesPrune)
	mux.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
		handleImageInspect(w, r, store.stateDir, cfg.mirrorRules)
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
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		handleEvents(w, r)
	})
	mux.HandleFunc("/networks/prune", handleNetworksPrune)
	mux.HandleFunc("/volumes/prune", handleVolumesPrune)

	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/containers/")
		if path == "prune" {
			handleContainersPrune(w, r)
			return
		}
		if path == "create" && r.Method == http.MethodPost {
			handleCreate(w, r, store, cfg.allowedPrefixes, cfg.mirrorRules, cfg.unixSocketPath, cfg.trustInsecure)
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
			handleStart(w, r, store, m, cfg.limits, id)
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
		case "top":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleTop(w, r, store, id)
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
	return mux
}
