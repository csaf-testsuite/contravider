// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

// Package main is the starting point of the contravider.
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
	"github.com/csaf-testsuite/contravider/pkg/providers"
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

	sys, err := providers.NewSystem(cfg)
	if err != nil {
		return fmt.Errorf("booting system failed: %w", err)
	}
	go sys.Run(ctx)

	ctrl, err := web.NewController(cfg, sys)
	if err != nil {
		return err
	}

	addr := cfg.Web.Addr()
	slog.Info("Starting web server", "address", addr)
	srv := &http.Server{
		Addr:    addr,
		Handler: ctrl.Bind(),
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
	} else if c, k := cfg.Web.CertFile, cfg.Web.KeyFile; c != " " && k != "" {
		// TLS server?
		cert, err := tls.LoadX509KeyPair(c, k)
		if err != nil {
			return fmt.Errorf("cannot load certificate: %w", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		addr := net.JoinHostPort(host, strconv.Itoa(cfg.Web.Port))
		l, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("cannot listen to tls: %w", err)
		}
		defer l.Close()
		listener = l
	}

	srvErrors := make(chan error)

	done := make(chan struct{})
	go func() {
		defer close(done)
		serve := srv.ListenAndServe
		if listener != nil {
			serve = func() error { return srv.Serve(listener) }
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
	check(run(cfg))
}
