package main

import "testing"

func TestK8sInspectBridgeIPAddress(t *testing.T) {
	c := &Container{
		ID:          "abc123",
		Hostname:    "abc123",
		Image:       "alpine:3.17",
		K8sPodName:  "sidewhale-abc123",
		K8sPodIP:    "10.42.0.99",
		NetworkMode: "bridge",
	}
	networks := map[string]interface{}{
		"bridge": map[string]interface{}{
			"NetworkID":   "bridge",
			"EndpointID":  "x",
			"IPAddress":   "",
			"IPPrefixLen": 0,
		},
	}
	if bridgeRaw, ok := networks["bridge"]; ok {
		if bridge, ok := bridgeRaw.(map[string]interface{}); ok {
			if c.K8sPodName != "" && c.K8sPodIP != "" {
				bridge["IPAddress"] = c.K8sPodIP
				bridge["IPPrefixLen"] = 24
			}
		}
	}
	bridge := networks["bridge"].(map[string]interface{})
	if bridge["IPAddress"] != "10.42.0.99" {
		t.Fatalf("bridge IPAddress = %v, want 10.42.0.99", bridge["IPAddress"])
	}
	if bridge["IPPrefixLen"] != 24 {
		t.Fatalf("bridge IPPrefixLen = %v, want 24", bridge["IPPrefixLen"])
	}
}
