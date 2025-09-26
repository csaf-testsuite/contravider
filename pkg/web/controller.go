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
	"github.com/csaf-testsuite/contravider/pkg/middleware"
)

// Controller binds the endpoints to the internal logic.
type Controller struct {
	cfg   *config.Config
	tmpls *template.Template
}

// templateFuncs are the functions usable in the templates.
var templateFuncs = template.FuncMap{}

// NewController returns a new Controller.
func NewController(
	cfg *config.Config,
) (*Controller, error) {
	path := filepath.Join(cfg.Web.Root, "templates", "*.tmpl")

	tmpls, err := template.New("index").Funcs(templateFuncs).ParseGlob(path)
	if err != nil {
		return nil, fmt.Errorf("loading templates failed: %w", err)
	}

	return &Controller{
		cfg:   cfg,
		tmpls: tmpls,
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

	// public folders
	white := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/.well-known/csaf/white/", white)

	green := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/.well-known/csaf/green/", green)

	// protected folders using RequireAuth middleware.
	router.Handle("/.well-known/csaf/amber/", middleware.BasicAuth(http.FileServer(http.Dir(c.cfg.Web.Root)), c.validate))
	router.Handle("/.well-known/csaf/red/", middleware.BasicAuth(http.FileServer(http.Dir(c.cfg.Web.Root)), c.validate))

	// Wrap the router with middleware that adds headers and intercepts status codes.
	finalHandler := middleware.AddCustomHeader(router)

	return finalHandler
}
