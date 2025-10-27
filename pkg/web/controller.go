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
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

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

// validate checks the supplied credentials based on the route.
func (c *Controller) validate(route, user, pass string) bool {
	switch route {
	case "/.well-known/csaf/amber/":
		return user == c.cfg.Web.UsernameAmber && pass == c.cfg.Web.PasswordAmber
	case "/.well-known/csaf/red/":
		return user == c.cfg.Web.UsernameRed && pass == c.cfg.Web.PasswordRed
	default:
		return false
	}
}

// indexTmplText is a HTML template listing the available profiles.
const indexTmplText = `<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Contravider</title>
  </head>
  <body>
    <h1>Contravider</h1>
    <p>
      <h2>Available profiles:</h2>
      <ul>
      {{ range .Profiles }}
      <li><a href="{{ . }}">{{ . }}</a></li>
      {{ end }}
      </ul>
    </p>
  </body>
</html>
`

var indexTmpl = template.Must(template.New("index").Parse(indexTmplText))

// profiles serves profiles.
func (c *Controller) profiles(rw http.ResponseWriter, req *http.Request) {
	path := strings.TrimLeft(req.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		// List available profiles.
		profiles := slices.Collect(maps.Keys(c.cfg.Providers.Profiles))
		slices.Sort(profiles)
		if err := indexTmpl.Execute(rw, struct {
			Profiles []string
		}{
			Profiles: profiles,
		}); err != nil {
			slog.Error("cannot write index template", "error", err)
		}
		return
	}
	// Don't leak the directories file.
	if parts[len(parts)-1] == ".directories.json" {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Request the profile to get instantiated.
	profile := parts[0]
	switch err := c.sys.Serve(profile); {
	case errors.Is(err, providers.ErrProfileNotFound):
		http.NotFound(rw, req)
		return
	case err != nil:
		http.Error(rw,
			"internal server error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	// Check for directories.
	dirFile := filepath.Join(c.cfg.Web.Root, profile, ".directories.json")
	dir, err := providers.LoadDirectory(dirFile)
	if err != nil {
		slog.Error("cannot load directory", "profile", profile, "error", err)
		http.Error(rw,
			"internal server error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	// Check if an authentication is needed.
	if protection := dir.FindProtection(parts[1:]); protection != nil {
		user, password, ok := req.BasicAuth()
		if !ok || !protection.Validate(user, password) {
			rw.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	http.FileServer(http.Dir(c.cfg.Web.Root)).ServeHTTP(rw, req)
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
			mw.ServeFile(c.cfg.Providers.Result),
		},
		{"/.well-known/csaf/service.json",
			mw.ServeFile(c.cfg.Providers.Result),
		},
		{"/.well-known/security.txt",
			mw.ServeFile(c.cfg.Providers.Result),
		},
		// public folders
		{
			"/.well-known/csaf/white/",
			http.FileServer(http.Dir(c.cfg.Providers.Result)),
		},
		{
			"/.well-known/csaf/green/",
			http.FileServer(http.Dir(c.cfg.Providers.Result)),
		},
		// protected folders using basic auth (middleware)
		{
			"/.well-known/csaf/amber/",
			mw.BasicAuth(
				http.FileServer(http.Dir(c.cfg.Providers.Result)),
				func(user, pass string) bool {
					return c.validate("/.well-known/csaf/amber/", user, pass)
				},
				"amber-realm",
			),
		},
		{
			"/.well-known/csaf/red/",
			mw.BasicAuth(
				http.FileServer(http.Dir(c.cfg.Providers.Result)),
				func(user, pass string) bool {
					return c.validate("/.well-known/csaf/red/", user, pass)
				},
				"red-realm",
			),
		},
	} {
		router.Handle(route.pattern, route.handler)
	}

	return router
}
