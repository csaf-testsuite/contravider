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
	"path/filepath"
	"regexp"
	"strings"
)

// templateData is a collection of strings which need to
// be defined when building the system
type templateData struct {
	BaseURL                     string
	PublicOpenPGPKeyFingerprint string
	PublicOpenPGPKeyURL         string
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

// applyTemplateFromTar deserializes files from a tar stream as templates
// and instantiate them with the given template data. (copied from old templateFromTar).
func applyTemplateFromTar(targetDir string, data *templateData, r io.Reader) error {
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
		switch name := filepath.Join(parts...); hdr.Typeflag {
		case tar.TypeReg:
			// Handle directives files
			if parts[len(parts)-1] == ".directives.toml" {
				slog.Debug("directives found", "path", hdr.Name)
				// Do nothing here, walk and apply directives later
				// continue
			}

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

// templateFromTar deserializes files from a tar stream as templates
// and instantiates them with the given template data. It also applies more transformations
// if directive files are found
func templateFromTar(
	targetDir string,
	data *templateData,
	directives func([]string, io.Reader) error,
) func(io.Reader) error {
	return func(r io.Reader) error {

		tmpDir, err := os.MkdirTemp("", "contravider-*")
		if err != nil {
			return fmt.Errorf("creating temp dir failed: %w", err)
		}
		defer func() {
			if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
				slog.Error("failed to remove temp dir", "dir", tmpDir, "error", removeErr)
			}
		}()
		if err := applyTemplateFromTar(tmpDir, data, r); err != nil {
			return fmt.Errorf("extracting to temp failed: %w", err)

		}
		// New Directives function, TODO
		if err := applyDirectives(tmpDir, directives); err != nil {
			return fmt.Errorf("processing directives in temp dir failed: %w", err)
		}

		// Copy into final destination
		if err := copyDirectoryExcludingDirectives(tmpDir, targetDir); err != nil {
			return fmt.Errorf("copying from temp to target failed: %w", err)
		}
		return nil
	}
}

// applyDirectives walks the temp dir and applies all found directives
func applyDirectives(tmpDir string, directives func([]string, io.Reader) error) error {
	return filepath.Walk(tmpDir, func(p string, info os.FileInfo, err error) error {
		// TODO
		return nil
	})
}

// copyDirectoryExcludingDirectives copies all files from the input directory inputDir and all files in all subfolders
// into the output directory outputDir using the Walk function.
func copyDirectoryExcludingDirectives(inputDir string, outputDir string) error {

	err := filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Directories are created as necessary later,
		// so no need to create explicitely possible unused directories via walk.
		if info.IsDir() {
			return nil
		}
		// Don't copy .directives.toml files into the final destination
		if info.Name() == ".directives.toml" {
			slog.Debug("not copying directives.toml file", "path", path)
			return nil
		}
		// save relative path in the structure
		relPath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return err
		}

		// Create absolute destination path by joining the output directory
		// with the relative path in the structure.
		outPath := filepath.Join(outputDir, relPath)

		// Make sure destination directory exists.
		// If not, create with rwxr-xr-x permissions.
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return err
		}
		inputFile, err := os.Open(path)
		if err != nil {
			return err
		}
		copyErr := copyFile(inputFile, outPath, info)
		return copyErr
	})
	// for error handling
	return err
}

// copyFile copies a singular file onto a given path
func copyFile(inputFile *os.File, outPath string, info os.FileInfo) error {
	// Read input file

	// Close it again
	defer inputFile.Close()
	// Create output file
	outputFile, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}

	// copy the data bytes from source to destination
	_, err = io.Copy(outputFile, inputFile)
	if err != nil {
		return err
	}
	// always close file to prevent many opened files at once
	closingError := outputFile.Close()
	// handle error in closing file
	return closingError
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
