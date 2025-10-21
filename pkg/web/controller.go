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
	"errors"
	"net/http"
	"strings"

	"github.com/csaf-testsuite/contravider/pkg/config"
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

/*
// validate checks the supplied credentials.
// Replace this with a real lookup (config file, DB, etc.).
func (c *Controller) validate(user, pass string) bool {
	return user == c.cfg.Web.Username && pass == c.cfg.Web.Password
}
*/

// profiles serves profiles.
func (c *Controller) profiles(rw http.ResponseWriter, req *http.Request) {
	path := strings.TrimLeft(req.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 {
		http.NotFound(rw, req)
		return
	}
	switch err := c.sys.Serve(parts[0]); {
	case errors.Is(err, providers.ErrProfileNotFound):
		http.NotFound(rw, req)
		return
	case err != nil:
		http.Error(rw,
			"internal server error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	http.FileServer(http.Dir(c.cfg.Web.Root)).ServeHTTP(rw, req)
}

// Bind returns an http.Handler to be used in a web server.
func (c *Controller) Bind() http.Handler {
	router := http.NewServeMux()

	/*
		mw := middleware.NewMiddleware(c.cfg)

		for _, route := range []struct {
			pattern string
			handler http.Handler
		}{
			// public files
			{"/.well-known/csaf/provider-metadata.json",
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, filepath.Join(c.cfg.Web.Root, r.URL.Path[1:]))
				}),
			},
			{"/.well-known/csaf/service.json",
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, filepath.Join(c.cfg.Web.Root, r.URL.Path[1:]))
				}),
			},
			{"/.well-known/security.txt",
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, filepath.Join(c.cfg.Web.Root, r.URL.Path[1:]))
				}),
			},
			// public folders
			{
				"/.well-known/csaf/white/",
				http.StripPrefix("/.well-known/csaf/white/", http.FileServer(http.Dir(c.cfg.Web.Root))),
			},
			{
				"/.well-known/csaf/green/",
				http.StripPrefix("/.well-known/csaf/green/", http.FileServer(http.Dir(c.cfg.Web.Root))),
			},
			// protected folders using basic auth (middleware)
			{
				"/.well-known/csaf/amber/",
				mw.BasicAuth(
					http.FileServer(http.Dir(c.cfg.Web.Root)),
					c.validate,
				),
			},
			{
				"/.well-known/csaf/red/",
				mw.BasicAuth(
					http.FileServer(http.Dir(c.cfg.Web.Root)),
					c.validate,
				),
			},
		} {
			router.Handle(route.pattern, route.handler)
		}
	*/
	router.HandleFunc("/", c.profiles)

	return router
}
