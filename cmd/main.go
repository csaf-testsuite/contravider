package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/csaf-testsuite/contravider/pkg/config"
	"github.com/csaf-testsuite/contravider/pkg/version"
	"github.com/csaf-testsuite/contravider/pkg/web"
)

func check(err error) {
	if err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGKILL, syscall.SIGTERM)
	defer stop()

	ctrl, err := web.NewController(cfg)
	if err != nil {
		return err
	}

	// Require TLS certificate and key to be set. Abort if not configured.
	if cfg.Web.TLSCertFile == "" {
		return fmt.Errorf("web server requires TLS certificate to be set")
	} else if cfg.Web.TLSKeyFile == "" {
		return fmt.Errorf("web server requires TLS key to be set")
	}

	addr := cfg.Web.Addr()
	slog.Info("Starting HTTPS server", "address", addr)
	srv := &http.Server{
		Addr:    addr,
		Handler: ctrl.Bind(),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Check if we should serve on an unix domain socket.
	var listener net.Listener
	if host := cfg.Web.Host; filepath.IsAbs(host) {
		host = strings.ReplaceAll(host, "{port}", strconv.Itoa(cfg.Web.Port))
		l, err := net.Listen("unix", host)
		if err != nil {
			return fmt.Errorf("cannot listen on domain socket: %w", err)
		}
		defer func() {
			l.Close()
			// Cleanup socket file
			os.Remove(host)
		}()
		// Enable writing to socket
		if err := os.Chmod(host, 0777); err != nil {
			return fmt.Errorf("cannot change rights on socket: %w", err)
		}
		listener = l
	}

	srvErrors := make(chan error)

	done := make(chan struct{})
	go func() {
		defer close(done)
		serve := srv.ListenAndServe
		if listener != nil {
			// Local unix socket, not TLS required
			serve = func() error { return srv.Serve(listener) }
		} else {
			// Serve TLS
			serve = func() error {
				return srv.ListenAndServeTLS(cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile)
			}
		}
		if err := serve(); err != http.ErrServerClosed {
			srvErrors <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("Shutting down")
		srv.Shutdown(ctx)
	case err = <-srvErrors:
	}
	<-done
	return err
}

func main() {
	var (
		cfgFile     string
		showVersion bool
	)
	flag.StringVar(&cfgFile, "config", config.DefaultConfigFile, "configuration file")
	flag.StringVar(&cfgFile, "c", config.DefaultConfigFile, "configuration file (shorthand)")
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.BoolVar(&showVersion, "V", false, "show version (shorthand)")
	flag.Parse()
	if showVersion {
		fmt.Printf("%s version: %s\n", os.Args[0], version.SemVersion)
		os.Exit(0)
	}
	cfg, err := config.Load(cfgFile)
	check(err)
	check(cfg.Log.Config())
	cfg.PresetDefaults()
	check(run(cfg))
}
