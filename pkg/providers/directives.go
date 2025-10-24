// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

type (
	// Protection are the user credentials og a folder.
	Protection struct {
		User     string `toml:"user" json:"user"`
		Password string `toml:"password" json:"password"`
	}
	// Directives are the directives applied to a folder.
	Directives struct {
		Protection *Protection `toml:"protection"`
	}
)

type (
	// Directory is recursive structure to model a directory tree.
	Directory struct {
		Name       string       `json:"name"`
		Folders    []*Directory `json:"folders,omitempty"`
		Protection *Protection  `json:"protection,omitempty"`
	}
)

// DirectoryBuilder helps contructing a directory tree.
type DirectoryBuilder struct {
	root *Directory
}

// addDirectives adds directives to the virtual tree.
func (tb *DirectoryBuilder) addDirectives(path []string, r io.Reader) error {
	var d Directives
	if _, err := toml.NewDecoder(r).Decode(&d); err != nil {
		return fmt.Errorf(
			"parsing directives %q failed: %w",
			strings.Join(path, "/"), err)
	}
	curr := tb.root
	if curr == nil {
		curr = &Directory{}
		tb.root = curr
	}
	for _, part := range path[:len(path)-1] {
		if idx := slices.IndexFunc(curr.Folders, func(f *Directory) bool {
			return f.Name == part
		}); idx == -1 {
			folder := &Directory{Name: part}
			curr.Folders = append(curr.Folders, folder)
			curr = folder
		} else {
			curr = curr.Folders[idx]
		}
	}
	curr.Protection = d.Protection
	return nil
}

// Directories returns the root node od the directory tree.
func (tb *DirectoryBuilder) Directories() *Directory {
	return tb.root
}

// WriteToFile serializes a directory tree to a file.
func (d *Directory) WriteToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating directories file %q failed: %w", path, err)
	}
	return errors.Join(json.NewEncoder(f).Encode(d), f.Close())
}

// LoadDirectory loads a directory tree from a file.
func LoadDirectory(path string) (*Directory, error) {
	f, err := os.Open(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &Directory{}, nil
	case err != nil:
		return nil, fmt.Errorf("opening directory failed: %w", err)
	}
	defer f.Close()
	var dir Directory
	if err := json.NewDecoder(f).Decode(&dir); err != nil {
		return nil, fmt.Errorf("loading directory failed: %w", err)
	}
	return &dir, nil
}

// FindProtection traverses the given path and returns the first
// directory with a valid protection.
func (d *Directory) FindProtection(path []string) *Protection {
	for _, part := range path {
		if part == "" {
			continue
		}
		idx := slices.IndexFunc(d.Folders, func(f *Directory) bool {
			return f.Name == part
		})
		if idx == -1 {
			return nil
		}
		next := d.Folders[idx]
		if next.Protection != nil {
			return next.Protection
		}
		d = next
	}
	return nil
}

// Validate checks if user and password match the configured ones.
func (p *Protection) Validate(user, password string) bool {
	return p.User == user && p.Password == password
}
