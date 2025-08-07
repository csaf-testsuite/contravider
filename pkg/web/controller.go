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
	"fmt"
	"net/http"
	"path/filepath"
	"text/template"

	"github.com/csaf-testsuite/contravider/pkg/config"
	"github.com/csaf-testsuite/contravider/pkg/providers"
)

// Controller binds the endpoints to the internal logic.
type Controller struct {
	cfg   *config.Config
	sys   *providers.System
	tmpls *template.Template
}

// templateFuncs are the functions usable in the templates.
var templateFuncs = template.FuncMap{}

// NewController returns a new Controller.
func NewController(
	cfg *config.Config,
	sys *providers.System,
) (*Controller, error) {
	path := filepath.Join(cfg.Web.Root, "templates", "*.tmpl")

	tmpls, err := template.New("index").Funcs(templateFuncs).ParseGlob(path)
	if err != nil {
		return nil, fmt.Errorf("loading templates failed: %w", err)
	}

	return &Controller{
		cfg:   cfg,
		sys:   sys,
		tmpls: tmpls,
	}, nil
}

// requireAuth enforces HTTP Basic Auth for protected paths
func (c *Controller) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !c.validate(user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Credentials are valid → continue.
		next.ServeHTTP(w, r)
	})
}

// validate checks the supplied credentials.
// Replace this with a real lookup (config file, DB, etc.).
func (c *Controller) validate(user, pass string) bool {
	return user == c.cfg.Web.Username && pass == c.cfg.Web.Password
}

// Bind return a http handler to be used in a web server.
func (c *Controller) Bind() http.Handler {
	router := http.NewServeMux()

	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		// public files
		{"/.well-known/csaf/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(c.cfg.Web.Root, r.URL.Path[1:]))
		}},
		{"/.well-known/csaf/service.json", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(c.cfg.Web.Root, r.URL.Path[1:]))
		}},
		{"/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(c.cfg.Web.Root, r.URL.Path[1:]))
		}},
	} {
		router.HandleFunc(route.pattern, route.handler)
	}

	// public folder
	white := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/.well-known/csaf/white/", white)

	green := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/.well-known/csaf/green/", green)

	// protected folder
	router.Handle("/.well-known/csaf/amber/", c.requireAuth(http.FileServer(http.Dir(c.cfg.Web.Root))))

	router.Handle("/.well-known/csaf/red/", c.requireAuth(http.FileServer(http.Dir(c.cfg.Web.Root))))
	return router
}
