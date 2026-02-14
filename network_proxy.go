package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func allocatePort() (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

func isTCPPortInUse(port int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

func parsePort(port string) (int, error) {
	port = strings.TrimSpace(port)
	port = strings.TrimSuffix(port, "/tcp")
	port = strings.TrimSpace(port)
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	return p, nil
}

func resolvePortBindings(exposedPorts map[string]struct{}, requestedExposed map[string]struct{}, hostBindings map[string][]portBinding) (map[int]int, error) {
	ports := map[int]int{}
	published := map[int]struct{}{}

	if len(requestedExposed) == 0 && len(hostBindings) == 0 {
		// Backward-compatible default: publish all EXPOSEd image ports when no explicit publish list exists.
		for port := range exposedPorts {
			cp, err := parsePort(port)
			if err != nil {
				return nil, err
			}
			published[cp] = struct{}{}
		}
	} else {
		for port := range requestedExposed {
			cp, err := parsePort(port)
			if err != nil {
				return nil, err
			}
			published[cp] = struct{}{}
		}
	}
	for port, bindings := range hostBindings {
		cp, err := parsePort(port)
		if err != nil {
			return nil, err
		}
		hostPort := 0
		for _, binding := range bindings {
			if binding.HostPort == "" {
				continue
			}
			hp, err := strconv.Atoi(binding.HostPort)
			if err != nil {
				return nil, fmt.Errorf("invalid host port: %w", err)
			}
			hostPort = hp
			break
		}
		if hostPort == 0 {
			hp, err := allocatePort()
			if err != nil {
				return nil, err
			}
			hostPort = hp
		}
		ports[cp] = hostPort
		published[cp] = struct{}{}
	}
	for cp := range published {
		if _, ok := ports[cp]; ok {
			continue
		}
		hp, err := allocatePort()
		if err != nil {
			return nil, err
		}
		ports[cp] = hp
	}
	return ports, nil
}

func toDockerPorts(ports map[int]int) map[string][]map[string]string {
	result := map[string][]map[string]string{}
	for containerPort, hostPort := range ports {
		key := fmt.Sprintf("%d/tcp", containerPort)
		result[key] = []map[string]string{
			{
				"HostIp":   "0.0.0.0",
				"HostPort": strconv.Itoa(hostPort),
			},
		}
	}
	return result
}

func toDockerPortSummaries(ports map[int]int) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(ports))
	for containerPort, hostPort := range ports {
		out = append(out, map[string]interface{}{
			"IP":          "0.0.0.0",
			"PrivatePort": containerPort,
			"PublicPort":  hostPort,
			"Type":        "tcp",
		})
	}
	return out
}

func frameDockerRawStream(stream byte, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	out[0] = stream
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:], payload)
	return out
}

func parseDockerBool(raw string, defaultValue bool) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return defaultValue
	}
	return raw == "1" || raw == "true"
}

func startPortProxies(ports map[int]int, targets map[int]string) ([]*portProxy, error) {
	var proxies []*portProxy
	for containerPort, hostPort := range ports {
		proxy, err := startPortProxy(hostPort, containerPort, targets[containerPort])
		if err != nil {
			for _, p := range proxies {
				p.stopProxy()
			}
			return nil, err
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}

func startPortProxy(hostPort, containerPort int, target string) (*portProxy, error) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(hostPort))
	if err != nil {
		return nil, err
	}
	p := &portProxy{ln: ln, stop: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-p.stop:
					return
				default:
					return
				}
			}
			go proxyConn(conn, containerPort, target)
		}
	}()
	return p, nil
}

func (p *portProxy) stopProxy() {
	select {
	case <-p.stop:
		return
	default:
		close(p.stop)
		_ = p.ln.Close()
	}
}

func proxyConn(src net.Conn, containerPort int, target string) {
	defer src.Close()
	dst, err := dialContainerPort(containerPort, target)
	if err != nil {
		fmt.Printf("sidewhale: proxy dial failed containerPort=%d err=%v\n", containerPort, err)
		return
	}
	defer dst.Close()
	done := make(chan struct{})
	var c2sBytes int64
	var c2sSample string
	var c2sErr error
	go func() {
		c2sBytes, c2sSample, c2sErr = proxyCopy(dst, src)
		if c2sErr != nil {
			fmt.Printf("sidewhale: proxy c->s copy error containerPort=%d bytes=%d err=%v\n", containerPort, c2sBytes, c2sErr)
		}
		_ = closeWrite(dst)
		close(done)
	}()
	s2cBytes, s2cSample, s2cErr := proxyCopy(src, dst)
	if s2cErr != nil {
		fmt.Printf("sidewhale: proxy s->c copy error containerPort=%d bytes=%d err=%v\n", containerPort, s2cBytes, s2cErr)
	}
	_ = closeWrite(src)
	<-done
	if c2sErr != nil || s2cErr != nil {
		fmt.Printf("sidewhale: proxy closed containerPort=%d c2s=%d s2c=%d c2sErr=%v s2cErr=%v c2sSample=%s s2cSample=%s\n", containerPort, c2sBytes, s2cBytes, c2sErr, s2cErr, c2sSample, s2cSample)
	}
}

func proxyCopy(dst net.Conn, src net.Conn) (int64, string, error) {
	buf := make([]byte, 32*1024)
	var written int64
	sample := make([]byte, 0, 64)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if len(sample) < cap(sample) {
				take := nr
				remaining := cap(sample) - len(sample)
				if take > remaining {
					take = remaining
				}
				sample = append(sample, buf[:take]...)
			}
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, hex.EncodeToString(sample), ew
			}
			if nw != nr {
				return written, hex.EncodeToString(sample), io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, hex.EncodeToString(sample), nil
			}
			return written, hex.EncodeToString(sample), er
		}
	}
}

func closeWrite(conn net.Conn) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	return tcp.CloseWrite()
}

func dialContainerPort(containerPort int, target string) (net.Conn, error) {
	if strings.TrimSpace(target) != "" {
		return net.DialTimeout("tcp", target, 2*time.Second)
	}
	port := strconv.Itoa(containerPort)
	endpoints := []string{
		"127.0.0.1:" + port,
		"[::1]:" + port,
	}
	var lastErr error
	for _, ep := range endpoints {
		conn, err := net.DialTimeout("tcp", ep, 2*time.Second)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoint candidates")
	}
	return nil, lastErr
}
