package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

func (s *containerStore) stopAllRunning(grace time.Duration) int {
	type stopTarget struct {
		id      string
		running bool
		pid     int
	}

	s.mu.Lock()
	targets := make([]stopTarget, 0, len(s.containers))
	extraProxyIDs := make([]string, 0, len(s.proxies))
	for _, c := range s.containers {
		targets = append(targets, stopTarget{
			id:      c.ID,
			running: c.Running,
			pid:     c.Pid,
		})
	}
	for id := range s.proxies {
		extraProxyIDs = append(extraProxyIDs, id)
	}
	s.mu.Unlock()

	stopped := 0
	knownIDs := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		knownIDs[target.id] = struct{}{}
		s.stopProxies(target.id)
		if target.running {
			if target.pid > 0 {
				terminateProcessTree(target.pid, grace)
			}
			s.markStopped(target.id)
			stopped++
		}
	}
	for _, id := range extraProxyIDs {
		if _, ok := knownIDs[id]; ok {
			continue
		}
		s.stopProxies(id)
	}
	return stopped
}
