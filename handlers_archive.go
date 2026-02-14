package main

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

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
	tmpBase := filepath.Join(filepath.Dir(c.Rootfs), "tmp")
	if err := extractArchiveToPath(r.Body, targetPath, tmpBase, func(dst string) string {
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

func extractArchiveToPath(r io.Reader, targetPath, tmpBase string, mapDst func(string) string) error {
	base := strings.TrimSpace(tmpBase)
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp(base, "sidewhale-archive-*")
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
			continue
		}
	}
}
