package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type imageEnsureFunc func(context.Context, string, string, *metrics, bool) (string, imageMeta, error)

func handleImagesCreate(w http.ResponseWriter, r *http.Request, store *containerStore, m *metrics, cfg appConfig, ensure imageEnsureFunc) {
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
		if imageTagLooksLikeDigest(tag) {
			ref = ref + "@" + tag
		} else {
			ref = ref + ":" + tag
		}
	}
	resolvedRef := rewriteImageReference(ref, cfg.mirrorRules)
	if !isImageAllowed(resolvedRef, cfg.allowedPrefixes) {
		writeError(w, http.StatusForbidden, "image not allowed by policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flush := func() {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	writeStatus := func(status string) {
		_ = enc.Encode(map[string]string{
			"status": status,
		})
		flush()
	}
	writeErrorLine := func(message string) {
		_ = enc.Encode(map[string]interface{}{
			"error": message,
			"errorDetail": map[string]string{
				"message": message,
			},
		})
		flush()
	}

	writeStatus("Pulling from " + resolvedRef)
	if _, meta, err := ensure(r.Context(), resolvedRef, store.stateDir, m, cfg.trustInsecure); err != nil {
		writeErrorLine(err.Error())
		return
	} else {
		writeStatus("Digest: " + meta.Digest)
		writeStatus("Status: Downloaded newer image for " + resolvedRef)
	}
}

func imageTagLooksLikeDigest(tag string) bool {
	tag = strings.TrimSpace(strings.ToLower(tag))
	algo, value, ok := strings.Cut(tag, ":")
	if !ok || algo == "" || value == "" {
		return false
	}
	for _, ch := range algo {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '+' && ch != '-' && ch != '_' && ch != '.' {
			return false
		}
	}
	for _, ch := range value {
		if (ch < 'a' || ch > 'f') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

func handleImageInspect(w http.ResponseWriter, r *http.Request, stateDir string, mirrorRules []imageMirrorRule) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/images/")
	if !strings.HasSuffix(raw, "/json") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw = strings.TrimSuffix(raw, "/json")
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	ref, err := url.PathUnescape(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid image name")
		return
	}
	resolvedRef := rewriteImageReference(ref, mirrorRules)
	meta, ok, err := findImageMetaByReference(stateDir, ref, resolvedRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "image inspect failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "No such image: "+ref)
		return
	}
	repoDigest := meta.Reference + "@" + meta.Digest
	if strings.Contains(meta.Reference, "@") {
		repoDigest = meta.Reference
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"Id":           meta.Digest,
		"RepoTags":     []string{ref, meta.Reference},
		"RepoDigests":  []string{repoDigest},
		"Size":         meta.ContentSize,
		"VirtualSize":  meta.DiskUsage,
		"Os":           "linux",
		"Architecture": "amd64",
		"ContainerConfig": map[string]interface{}{
			"Env": meta.Env,
			"Cmd": meta.Cmd,
		},
		"Config": map[string]interface{}{
			"Env":        meta.Env,
			"Cmd":        meta.Cmd,
			"Entrypoint": meta.Entrypoint,
			"WorkingDir": meta.WorkingDir,
		},
	})
}
