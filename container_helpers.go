package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
	if env == "" {
		return "", ""
	}
	key, value, ok := strings.Cut(env, "=")
	if !ok {
		return strings.TrimSpace(env), ""
	}
	return strings.TrimSpace(key), value
}

func envHasKey(env []string, key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	for _, item := range env {
		k, _ := splitEnv(item)
		if k == key {
			return true
		}
	}
	return false
}

func ensureEnvContainsToken(env []string, key, token string) []string {
	key = strings.TrimSpace(key)
	token = strings.TrimSpace(token)
	if key == "" || token == "" {
		return env
	}
	out := append([]string{}, env...)
	for i, item := range out {
		k, v := splitEnv(item)
		if k != key {
			continue
		}
		if strings.Contains(v, token) {
			return out
		}
		v = strings.TrimSpace(v)
		if v == "" {
			out[i] = key + "=" + token
		} else {
			out[i] = key + "=" + v + " " + token
		}
		return out
	}
	return append(out, key+"="+token)
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

func defaultContainerHostname(id string) string {
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

func normalizeContainerHostname(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range hostname {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-':
			b.WriteRune(r)
		case r == '_' || r == ' ':
			b.WriteByte('-')
		default:
		}
	}
	return strings.Trim(b.String(), "-")
}

func writeContainerIdentityFiles(rootfs, hostname string) error {
	return writeContainerIdentityFilesWithAliases(rootfs, hostname, nil)
}

func writeContainerIdentityFilesWithAliases(rootfs, hostname string, aliases []string) error {
	hostname = normalizeContainerHostname(hostname)
	if hostname == "" {
		return nil
	}
	etcDir := filepath.Join(rootfs, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(etcDir, "hostname"), []byte(hostname+"\n"), 0o644); err != nil {
		return err
	}

	var content strings.Builder
	content.WriteString("127.0.0.1\tlocalhost\n")
	content.WriteString("::1\tlocalhost ip6-localhost ip6-loopback\n")
	content.WriteString("127.0.1.1\t" + hostname + "\n")
	// In proot we share host UTS hostname; add it so JVM services can resolve local host.
	if hostName, err := os.Hostname(); err == nil {
		hostName = normalizeContainerHostname(hostName)
		if hostName != "" && hostName != hostname {
			content.WriteString("127.0.1.1\t" + hostName + "\n")
		}
	}

	uniq := map[string]struct{}{}
	for _, alias := range aliases {
		alias = normalizeContainerHostname(alias)
		if alias == "" || alias == hostname {
			continue
		}
		if _, ok := uniq[alias]; ok {
			continue
		}
		uniq[alias] = struct{}{}
	}
	if len(uniq) > 0 {
		names := make([]string, 0, len(uniq))
		for alias := range uniq {
			names = append(names, alias)
		}
		sort.Strings(names)
		for _, alias := range names {
			// Sidewhale runs in a shared host network namespace, so aliases route via loopback.
			content.WriteString("127.0.0.1\t" + alias + "\n")
		}
	}
	hostsPath := filepath.Join(etcDir, "hosts")
	return os.WriteFile(hostsPath, []byte(content.String()), 0o644)
}

func hostsFileHasHostname(data []byte, hostname string) bool {
	target := strings.TrimSpace(hostname)
	if target == "" {
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields[1:] {
			if field == target {
				return true
			}
		}
	}
	return false
}

func isRyukImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "/ryuk:") || strings.HasSuffix(image, "/ryuk")
}

func isRabbitMQImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "rabbitmq")
}

func isOracleImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "oracle")
}

func isConfluentKafkaImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "confluentinc/cp-kafka")
}

func isRedisImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "redis")
}

func isLLdapImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "lldap/lldap")
}

func isZookeeperImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "/zookeeper:") ||
		strings.HasSuffix(image, "/zookeeper") ||
		strings.Contains(image, "cp-zookeeper")
}

func dockerHostForInnerClients(unixSocketPath, requestHost string) string {
	if strings.TrimSpace(unixSocketPath) != "" {
		return "unix://" + unixSocketPath
	}
	host := strings.TrimSpace(requestHost)
	if host == "" {
		host = "127.0.0.1:23750"
	}
	if strings.HasPrefix(host, "tcp://") || strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	return "tcp://" + host
}

func unixSocketPathFromContainerEnv(env []string) string {
	for _, kv := range env {
		if !strings.HasPrefix(kv, "DOCKER_HOST=") {
			continue
		}
		val := strings.TrimPrefix(kv, "DOCKER_HOST=")
		if strings.HasPrefix(val, "unix://") {
			return strings.TrimPrefix(val, "unix://")
		}
	}
	return ""
}

func dockerSocketBindsForContainer(c *Container, socketPath string) ([]string, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || c == nil {
		return nil, nil
	}
	binds := []string{socketPath + ":" + socketPath}
	if socketPath != "/var/run/docker.sock" {
		binds = append(binds, socketPath+":/var/run/docker.sock")
	}
	if socketPath != "/run/docker.sock" {
		binds = append(binds, socketPath+":/run/docker.sock")
	}
	return binds, nil
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
		created := int64(0)
		if info, statErr := os.Stat(metaPath); statErr == nil {
			created = info.ModTime().Unix()
		}
		out = append(out, map[string]interface{}{
			"Id":          meta.Digest,
			"RepoTags":    []string{meta.Reference},
			"Created":     created,
			"Size":        meta.ContentSize,
			"VirtualSize": meta.DiskUsage,
			"SharedSize":  0,
		})
	}
	return out, nil
}

func findImageMetaByReference(stateDir string, refs ...string) (imageMeta, bool, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return imageMeta{}, false, nil
		}
		return imageMeta{}, false, err
	}
	wanted := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		wanted[ref] = struct{}{}
	}
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
		if _, ok := wanted[meta.Reference]; ok {
			if meta.DiskUsage == 0 {
				if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
					meta.DiskUsage = size
				}
			}
			return meta, true, nil
		}
	}
	return imageMeta{}, false, nil
}

func findImageMetaByReferenceOrDigest(stateDir string, refs []string, digests []string) (imageMeta, bool, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return imageMeta{}, false, nil
		}
		return imageMeta{}, false, err
	}
	wantedRefs := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		wantedRefs[ref] = struct{}{}
	}
	wantedDigests := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		digest = strings.TrimSpace(digest)
		if digest == "" {
			continue
		}
		wantedDigests[digest] = struct{}{}
	}
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
		if _, ok := wantedRefs[meta.Reference]; ok {
			if meta.DiskUsage == 0 {
				if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
					meta.DiskUsage = size
				}
			}
			return meta, true, nil
		}
		if _, ok := wantedDigests[meta.Digest]; ok {
			if meta.DiskUsage == 0 {
				if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
					meta.DiskUsage = size
				}
			}
			return meta, true, nil
		}
	}
	return imageMeta{}, false, nil
}

type imageRecord struct {
	imageDir  string
	rootfsDir string
	metaPath  string
	meta      imageMeta
}

func findImageRecordByReferenceOrDigest(stateDir string, refs []string, digests []string) (imageRecord, bool, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return imageRecord{}, false, nil
		}
		return imageRecord{}, false, err
	}
	wantedRefs := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		wantedRefs[ref] = struct{}{}
	}
	wantedDigests := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		digest = strings.TrimSpace(digest)
		if digest == "" {
			continue
		}
		wantedDigests[digest] = struct{}{}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		imageDir := filepath.Join(imageRoot, entry.Name())
		metaPath := filepath.Join(imageDir, "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta imageMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		_, refMatch := wantedRefs[meta.Reference]
		_, digestMatch := wantedDigests[meta.Digest]
		if !refMatch && !digestMatch {
			continue
		}
		rootfsDir := filepath.Join(imageDir, "rootfs")
		if meta.DiskUsage == 0 {
			if size, sizeErr := dirSize(rootfsDir); sizeErr == nil {
				meta.DiskUsage = size
			}
		}
		return imageRecord{
			imageDir:  imageDir,
			rootfsDir: rootfsDir,
			metaPath:  metaPath,
			meta:      meta,
		}, true, nil
	}
	return imageRecord{}, false, nil
}

func imageAliasKey(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "ref_" + hex.EncodeToString(sum[:12])
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
