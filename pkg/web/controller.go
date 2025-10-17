// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

// Package web contains the web controller logic.
package web

import (
	"net/http"
	"path/filepath"

	"github.com/csaf-testsuite/contravider/pkg/config"
	"github.com/csaf-testsuite/contravider/pkg/middleware"
	"github.com/csaf-testsuite/contravider/pkg/providers"
)

// Controller binds the endpoints to the internal logic.
type Controller struct {
	cfg *config.Config
	sys *providers.System
}

// NewController returns a new Controller.
func NewController(
	cfg *config.Config,
	sys *providers.System,
) (*Controller, error) {
	return &Controller{
		cfg: cfg,
		sys: sys,
	}, nil
}

// validate checks the supplied credentials.
// Replace this with a real lookup (config file, DB, etc.).
func (c *Controller) validate(user, pass string) bool {
	return user == c.cfg.Web.Username && pass == c.cfg.Web.Password
}

// Bind returns an http.Handler to be used in a web server.
func (c *Controller) Bind() http.Handler {
	router := http.NewServeMux()
	mw := middleware.NewMiddleware(c.cfg)

	for _, route := range []struct {
		pattern string
		handler http.Handler
	}{
		// public files
		{"/.well-known/csaf/provider-metadata.json",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join(c.cfg.Providers.Result, r.URL.Path[1:]))
			}),
		},
		{"/.well-known/csaf/service.json",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join(c.cfg.Providers.Result, r.URL.Path[1:]))
			}),
		},
		{"/.well-known/security.txt",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join(c.cfg.Providers.Result, r.URL.Path[1:]))
			}),
		},
		// public folders
		{
			"/.well-known/csaf/white/",
			http.StripPrefix("/.well-known/csaf/white/", http.FileServer(http.Dir(c.cfg.Providers.Result))),
		},
		{
			"/.well-known/csaf/green/",
			http.StripPrefix("/.well-known/csaf/green/", http.FileServer(http.Dir(c.cfg.Providers.Result))),
		},
		// protected folders using basic auth (middleware)
		{
			"/.well-known/csaf/amber/",
			mw.BasicAuth(
				http.FileServer(http.Dir(c.cfg.Providers.Result)),
				c.validate,
			),
		},
		{
			"/.well-known/csaf/red/",
			mw.BasicAuth(
				http.FileServer(http.Dir(c.cfg.Providers.Result)),
				c.validate,
			),
		},
	} {
		router.Handle(route.pattern, route.handler)
	}

	return router
}
