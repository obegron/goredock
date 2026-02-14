package main

import (
	"net"
	"sync"
	"time"
)

type Container struct {
	ID           string    `json:"Id"`
	Name         string    `json:"Name,omitempty"`
	Hostname     string    `json:"Hostname,omitempty"`
	User         string    `json:"User,omitempty"`
	Image        string    `json:"Image"`
	Rootfs       string    `json:"Rootfs"`
	Created      time.Time `json:"Created"`
	StartedAt    time.Time `json:"StartedAt,omitempty"`
	FinishedAt   time.Time `json:"FinishedAt,omitempty"`
	Running      bool      `json:"Running"`
	ExitCode     int       `json:"ExitCode"`
	Ports        map[int]int
	PortTargets  map[int]string      `json:"PortTargets,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string            `json:"Env"`
	LogPath      string              `json:"LogPath"`
	StdoutPath   string              `json:"StdoutPath,omitempty"`
	StderrPath   string              `json:"StderrPath,omitempty"`
	Pid          int                 `json:"Pid"`
	Cmd          []string            `json:"Cmd"`
	WorkingDir   string              `json:"WorkingDir"`
	LoopbackIP   string              `json:"LoopbackIP,omitempty"`
	NetworkMode  string              `json:"NetworkMode,omitempty"`
}

type containerStore struct {
	mu         sync.Mutex
	containers map[string]*Container
	networks   map[string]*Network
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
	Stdout      []byte
	Stderr      []byte
}

type metrics struct {
	mu             sync.Mutex
	running        int
	startFailures  int
	pullDurationMs int64
	execDurationMs int64
}

type createRequest struct {
	Image            string              `json:"Image"`
	Hostname         string              `json:"Hostname"`
	User             string              `json:"User"`
	Cmd              []string            `json:"Cmd"`
	Env              []string            `json:"Env"`
	Entrypoint       []string            `json:"Entrypoint"`
	WorkingDir       string              `json:"WorkingDir"`
	ExposedPorts     map[string]struct{} `json:"ExposedPorts"`
	NetworkingConfig networkingConfig    `json:"NetworkingConfig"`
	HostConfig       hostConfig          `json:"HostConfig"`
}

type networkingConfig struct {
	EndpointsConfig map[string]endpointConfig `json:"EndpointsConfig"`
}

type endpointConfig struct {
	Aliases []string `json:"Aliases"`
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
	NetworkMode  string                   `json:"NetworkMode"`
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
	maxDiskBytes  int64
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

type Network struct {
	ID         string                      `json:"Id"`
	Name       string                      `json:"Name"`
	Driver     string                      `json:"Driver"`
	Scope      string                      `json:"Scope"`
	Created    string                      `json:"Created"`
	Internal   bool                        `json:"Internal"`
	Attachable bool                        `json:"Attachable"`
	Ingress    bool                        `json:"Ingress"`
	EnableIPv6 bool                        `json:"EnableIPv6,omitempty"`
	Labels     map[string]string           `json:"Labels,omitempty"`
	Options    map[string]string           `json:"Options,omitempty"`
	IPAM       map[string]interface{}      `json:"IPAM,omitempty"`
	Containers map[string]*NetworkEndpoint `json:"Containers,omitempty"`
}

type NetworkEndpoint struct {
	Name     string   `json:"Name"`
	Endpoint string   `json:"EndpointID"`
	Mac      string   `json:"MacAddress"`
	IPv4     string   `json:"IPv4Address"`
	IPv6     string   `json:"IPv6Address"`
	Aliases  []string `json:"Aliases,omitempty"`
}

type networkCreateRequest struct {
	Name           string                 `json:"Name"`
	CheckDuplicate bool                   `json:"CheckDuplicate"`
	Driver         string                 `json:"Driver"`
	Internal       bool                   `json:"Internal"`
	Attachable     bool                   `json:"Attachable"`
	Ingress        bool                   `json:"Ingress"`
	EnableIPv6     bool                   `json:"EnableIPv6"`
	IPAM           map[string]interface{} `json:"IPAM"`
	Options        map[string]string      `json:"Options"`
	Labels         map[string]string      `json:"Labels"`
}

type networkConnectRequest struct {
	Container      string `json:"Container"`
	EndpointConfig struct {
		Aliases []string `json:"Aliases"`
	} `json:"EndpointConfig"`
}

type networkDisconnectRequest struct {
	Container string `json:"Container"`
	Force     bool   `json:"Force"`
}
