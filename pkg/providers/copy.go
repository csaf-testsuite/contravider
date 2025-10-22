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
	"archive/tar"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// TemplateData is a collection of strings which need to
// be defined when building the system
type TemplateData struct {
	BaseURL             string
	PublicOpenPGPKeyURL string
}

type (
	// Action is a function to be applied to files matching a regex.
	Action func(path string, info os.FileInfo) error
	// PatternAction describes functions are applied on which regex.
	PatternAction struct {
		Pattern *regexp.Regexp
		Actions []Action
	}
	// PatternActions is a slice of PatternAction.
	PatternActions []PatternAction
)

// templateFromTar deserializes files from a tar stream as templates
// and instantiate them with the given template data.
func templateFromTar(targetDir string, data *TemplateData) func(io.Reader) error {
	return func(r io.Reader) error {
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("untaring failed: %w", err)
			}
			parts := strings.Split(hdr.Name, "/")
			if len(parts) < 3 || parts[0] != "data" {
				slog.Debug("ignore tar entry", "name", hdr.Name)
				continue
			}
			parts[0] = targetDir // prefix with targetDir
			switch name := path.Join(parts...); hdr.Typeflag {
			case tar.TypeReg:
				slog.Debug("create file", "file", name)
				content, err := io.ReadAll(tr)
				if err != nil {
					return fmt.Errorf("cannot read data of %q: %w", hdr.Name, err)
				}
				// Parse the template data.
				tmpl, err := template.New(parts[len(parts)-1]).
					Delims("$((", "))$").
					Parse(string(content))
				if err != nil {
					return fmt.Errorf("parsing %q as template failed: %w", hdr.Name, err)
				}
				f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode))
				if err != nil {
					return fmt.Errorf("cannot create file %q: %w", name, err)
				}
				if err := errors.Join(tmpl.Execute(f, data), f.Close()); err != nil {
					return fmt.Errorf("writing templated data to %q failed: %w", name, err)
				}

			case tar.TypeDir:
				slog.Debug("create directory", "dir", name)
				if err := os.MkdirAll(name, os.FileMode(hdr.Mode)); err != nil {
					return fmt.Errorf("creating directory %q failed: %w", name, err)
				}
			}
		}
		return nil
	}
}

// Apply walks recursively over a given directory and
// applies all matching actions to the files.
func (pa PatternActions) Apply(inputDir string) error {
	return filepath.Walk(
		inputDir,
		func(path string, info os.FileInfo, err error,
		) error {
			if err != nil {
				return err
			}
			// Ignore none regular files.
			if !info.Mode().IsRegular() {
				return nil
			}
			fname := info.Name()
			for _, p := range pa {
				if p.Pattern.MatchString(fname) {
					for _, action := range p.Actions {
						if err := action(path, info); err != nil {
							return fmt.Errorf(
								"apply pattern %q failed: %w", p.Pattern, err)
						}
					}
					break
				}
			}
			return nil
		})
}
