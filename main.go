package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

const extractorVersion = "v2"

func main() {
	cfg, printVersion, err := initConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config init failed: %v\n", err)
		os.Exit(1)
	}
	if printVersion {
		fmt.Println(version)
		return
	}

	if err := requireUnprivilegedRuntime(os.Geteuid()); err != nil {
		fmt.Fprintf(os.Stderr, "startup check failed: %v\n", err)
		os.Exit(1)
	}

	store := &containerStore{
		containers: make(map[string]*Container),
		execs:      make(map[string]*ExecInstance),
		stateDir:   cfg.stateDir,
		proxies:    make(map[string][]*portProxy),
	}
	if err := store.init(); err != nil {
		fmt.Fprintf(os.Stderr, "state init failed: %v\n", err)
		os.Exit(1)
	}

	m := &metrics{}
	probes := &probeState{}
	mux := newRouter(store, m, cfg, probes)

	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           timeoutMiddleware(apiVersionMiddleware(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       5 * time.Minute,
	}

	errCh := make(chan error, 2)
	started := 0

	tcpAddr := strings.TrimSpace(cfg.listenAddr)
	if tcpAddr != "" && !strings.EqualFold(tcpAddr, "off") && tcpAddr != "-" {
		started++
		go func() {
			fmt.Printf("sidewhale listening on %s\n", tcpAddr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	if cfg.unixSocketPath != "" {
		ln, err := listenUnixSocket(cfg.unixSocketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unix socket setup failed: %v\n", err)
			os.Exit(1)
		}
		started++
		go func() {
			fmt.Printf("sidewhale listening on unix://%s\n", cfg.unixSocketPath)
			if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	if started == 0 {
		fmt.Fprintln(os.Stderr, "no listeners configured")
		os.Exit(1)
	}

	probes.setReady(true)
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	select {
	case <-signalCtx.Done():
		probes.setReady(false)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "graceful shutdown failed: %v\n", err)
			_ = server.Close()
		}
		stopped := store.stopAllRunning(2 * time.Second)
		fmt.Printf("sidewhale stopped %d running containers\n", stopped)
	case err := <-errCh:
		probes.setReady(false)
		_ = server.Close()
		stopped := store.stopAllRunning(2 * time.Second)
		fmt.Fprintf(os.Stderr, "server error: %v (stopped %d containers)\n", err, stopped)
		os.Exit(1)
	}
}

func apiVersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rewritten, ok := rewriteVersionedPath(r.URL.Path); ok {
			r.URL.Path = rewritten
			r.URL.RawPath = rewritten
		}
		next.ServeHTTP(w, r)
	})
}

func rewriteVersionedPath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/v") {
		return "", false
	}
	rest := path[2:]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", false
	}
	versionPart := rest[:slash]
	if !isAPIVersion(versionPart) {
		return "", false
	}
	rewritten := rest[slash:]
	if rewritten == "" {
		return "/", true
	}
	return rewritten, true
}

func isAPIVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}
