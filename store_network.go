package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const builtInBridgeNetworkID = "bridge"

func (s *containerStore) ensureNetworksMapLocked() {
	if s.networks == nil {
		s.networks = make(map[string]*Network)
	}
}

func (s *containerStore) networkPath(id string) string {
	return filepath.Join(s.stateDir, "networks", id+".json")
}

func (s *containerStore) loadNetworks() error {
	s.ensureNetworksMapLocked()
	entries, err := os.ReadDir(filepath.Join(s.stateDir, "networks"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.stateDir, "networks", entry.Name()))
		if err != nil {
			continue
		}
		var n Network
		if err := json.Unmarshal(data, &n); err != nil {
			continue
		}
		if n.Containers == nil {
			n.Containers = map[string]*NetworkEndpoint{}
		}
		s.networks[n.ID] = &n
	}
	return nil
}

func (s *containerStore) ensureDefaultNetworkLocked() error {
	s.ensureNetworksMapLocked()
	if _, ok := s.networks[builtInBridgeNetworkID]; ok {
		return nil
	}
	n := &Network{
		ID:         builtInBridgeNetworkID,
		Name:       "bridge",
		Driver:     "bridge",
		Scope:      "local",
		Created:    time.Now().UTC().Format(time.RFC3339Nano),
		Containers: map[string]*NetworkEndpoint{},
		IPAM: map[string]interface{}{
			"Driver":  "default",
			"Config":  []interface{}{},
			"Options": map[string]string{},
		},
		Options: map[string]string{},
		Labels:  map[string]string{},
	}
	s.networks[n.ID] = n
	return s.saveNetworkLocked(n)
}

func (s *containerStore) saveNetworkLocked(n *Network) error {
	s.ensureNetworksMapLocked()
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.networkPath(n.ID), data, 0o644)
}

func (s *containerStore) saveNetwork(n *Network) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	s.networks[n.ID] = n
	return s.saveNetworkLocked(n)
}

func (s *containerStore) getNetwork(ref string) (*Network, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	ref = normalizeContainerName(ref)
	if ref == "" {
		return nil, false
	}
	if n, ok := s.networks[ref]; ok {
		return n, true
	}
	for _, n := range s.networks {
		if strings.EqualFold(n.Name, ref) {
			return n, true
		}
	}
	for id, n := range s.networks {
		if strings.HasPrefix(id, ref) {
			return n, true
		}
	}
	return nil, false
}

func (s *containerStore) listNetworks() []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	out := make([]map[string]interface{}, 0, len(s.networks))
	ids := make([]string, 0, len(s.networks))
	for id := range s.networks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := s.networks[id]
		out = append(out, map[string]interface{}{
			"Name":       n.Name,
			"Id":         n.ID,
			"Created":    n.Created,
			"Scope":      firstNonEmpty(n.Scope, "local"),
			"Driver":     firstNonEmpty(n.Driver, "bridge"),
			"EnableIPv6": n.EnableIPv6,
			"Internal":   n.Internal,
			"Attachable": n.Attachable,
			"Ingress":    n.Ingress,
			"Labels":     n.Labels,
		})
	}
	return out
}

func (s *containerStore) connectContainerToNetwork(networkID string, c *Container, aliases []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	n, ok := s.networks[networkID]
	if !ok || c == nil {
		return nil
	}
	if n.Containers == nil {
		n.Containers = map[string]*NetworkEndpoint{}
	}
	ep := n.Containers[c.ID]
	if ep == nil {
		endpointID, _ := randomID(12)
		ep = &NetworkEndpoint{
			Name:     normalizeContainerName(c.Name),
			Endpoint: endpointID,
			Aliases:  []string{},
		}
	}
	if ep.Name == "" {
		ep.Name = c.ID
	}
	aliasSet := map[string]struct{}{}
	for _, a := range ep.Aliases {
		if a = strings.TrimSpace(a); a != "" {
			aliasSet[a] = struct{}{}
		}
	}
	for _, a := range aliases {
		if a = strings.TrimSpace(a); a != "" {
			aliasSet[a] = struct{}{}
		}
	}
	if c.Hostname != "" {
		aliasSet[c.Hostname] = struct{}{}
	}
	if ep.Name != "" {
		aliasSet[ep.Name] = struct{}{}
	}
	ep.Aliases = ep.Aliases[:0]
	for a := range aliasSet {
		ep.Aliases = append(ep.Aliases, a)
	}
	sort.Strings(ep.Aliases)
	n.Containers[c.ID] = ep
	return s.saveNetworkLocked(n)
}

func (s *containerStore) disconnectContainerFromNetwork(networkID, containerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	n, ok := s.networks[networkID]
	if !ok {
		return nil
	}
	delete(n.Containers, containerID)
	return s.saveNetworkLocked(n)
}

func (s *containerStore) disconnectContainerFromAllNetworks(containerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	for _, n := range s.networks {
		if n.Containers == nil {
			continue
		}
		if _, ok := n.Containers[containerID]; !ok {
			continue
		}
		delete(n.Containers, containerID)
		_ = s.saveNetworkLocked(n)
	}
}

func (s *containerStore) networkSettingsForContainer(containerID string) map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	out := map[string]interface{}{}
	for _, n := range s.networks {
		ep, ok := n.Containers[containerID]
		if !ok {
			continue
		}
		out[n.Name] = map[string]interface{}{
			"NetworkID":           n.ID,
			"EndpointID":          ep.Endpoint,
			"Gateway":             "",
			"IPAddress":           "",
			"IPPrefixLen":         0,
			"IPv6Gateway":         "",
			"GlobalIPv6Address":   "",
			"GlobalIPv6PrefixLen": 0,
			"MacAddress":          ep.Mac,
			"Aliases":             ep.Aliases,
		}
	}
	return out
}

func (s *containerStore) peerAliasesForContainer(containerID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureNetworksMapLocked()
	aliases := map[string]struct{}{}
	for _, n := range s.networks {
		if _, attached := n.Containers[containerID]; !attached {
			continue
		}
		for peerID, ep := range n.Containers {
			if peerID == containerID || ep == nil {
				continue
			}
			for _, alias := range ep.Aliases {
				if alias = strings.TrimSpace(alias); alias != "" {
					aliases[alias] = struct{}{}
				}
			}
			if ep.Name != "" {
				aliases[ep.Name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(aliases))
	for alias := range aliases {
		out = append(out, alias)
	}
	sort.Strings(out)
	return out
}
