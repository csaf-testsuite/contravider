package config

import (
	"log/slog"
	"os"
)

// envStore maps an env to a store function.
type envStore struct {
	name  string
	store func(string) error
}

func storeLevel(s string) (slog.Level, error) {
	var level slog.Level
	return level, level.UnmarshalText([]byte(s))
}

// noparse returns an unparsed string.
func noparse(s string) (string, error) {
	return s, nil
}

// store returns a function to parse a string to return a function to store a value.
func store[T any](parse func(string) (T, error)) func(*T) func(string) error {
	return func(dst *T) func(string) error {
		return func(s string) error {
			x, err := parse(s)
			if err != nil {
				return err
			}
			*dst = x
			return nil
		}
	}
}

// fill iterates over the mapping and calls the store function
// of every env var that is found.
func storeFromEnv(stores ...envStore) error {
	for _, es := range stores {
		if v, ok := os.LookupEnv(es.name); ok {
			if err := es.store(v); err != nil {
				return err
			}
		}
	}
	return nil
}
