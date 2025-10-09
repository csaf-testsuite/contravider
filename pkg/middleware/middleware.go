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

package middleware

import (
	"net/http"
)

// CustomResponseWriter wraps http.ResponseWriter to intercept status codes.
type CustomResponseWriter struct {
	http.ResponseWriter
	StatusCode int
}

// BasicAuth enforces HTTP Basic Auth for protected paths
// The validate function should check the credentials (for example, using configuration values).
func BasicAuth(next http.Handler, validate func(user, pass string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !validate(user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Credentials are valid -> continue.
		next.ServeHTTP(w, r)
	})
}

// AddCustomHeader adds custom headers and wraps the ResponseWriter.
func AddCustomHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Middleware", "applied")
		crw := &CustomResponseWriter{ResponseWriter: w, StatusCode: http.StatusOK}
		next.ServeHTTP(crw, r)
	})
}
