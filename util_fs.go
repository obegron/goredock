package main

import (
	"archive/tar"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
		}
		return nil
	}); err != nil {
		return err
	}

	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i].path, string(os.PathSeparator)) > strings.Count(dirs[j].path, string(os.PathSeparator))
	})
	for _, d := range dirs {
		if err := os.Chmod(d.path, d.mode.Perm()); err != nil {
			return err
		}
		_ = os.Chtimes(d.path, time.Now(), d.modTime)
	}
	return nil
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
