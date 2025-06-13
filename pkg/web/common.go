package web

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
)

// args is used in templates to construct maps of key/value pairs.
func args(args ...any) (any, error) {
	n := len(args)
	if n%2 == 1 {
		return nil, errors.New("number of args have to be even")
	}
	m := make(map[any]any, n/2)
	for i := 0; i < n; i += 2 {
		key, value := args[i], args[i+1]
		m[key] = value
	}
	return m, nil
}

var durationRe = regexp.MustCompile(`^\s*(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*$`)

// checkParam checks a list of errors if there are any.
// In this case it issues a bad request into the given response writer.
func checkParam(w http.ResponseWriter, errs ...error) bool {
	if err := errors.Join(errs...); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// check checks a given error, logs it and issues an internal server error
// into the given response writer.
func check(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {
		slog.ErrorContext(r.Context(), "internal error", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return false
	}
	return true
}
