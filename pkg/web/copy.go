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
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
)

// TemplateData is a collection of strings which need to
// be defined when building the system
type TemplateData struct {
	CanonicalURL          string
	DirectoryURL          string
	DistributionURL       string
	FeedURL               string
	PublicOpenPGPKeyURL   string
	RolieFeedURL          string
	ServiceCollectionURL  string
	PublisherNamespaceURL string
}

// CopyDirectory copies all files from the input directory inputDir and all files in all subfolders
// into the output directory outputDir using the Walk function while executing the templates.
func copyDirectory(inputDir string, outputDir string, data TemplateData) error {

	err := filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Directories are created as necessary later,
		// so no need to create explicitely possible unused directories via walk.
		if info.IsDir() {
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

		// Parse the template file.
		tmpl, err := template.New(filepath.Base(path)).
			Delims("$((", "))$").
			ParseFiles(path)
		if err != nil {
			return err
		}

		// Create output file
		outputFile, err := os.Create(outPath)
		if err != nil {
			return err
		}
		// Execute template with data
		exerr := tmpl.Execute(outputFile, data)
		// always close file to prevent many opened files at once
		closingError := outputFile.Close()
		// handle error in template execute
		if exerr != nil {
			return exerr
		}
		// handle error in closing file
		return closingError
	})
	// for error handling
	return err
}

type (
	// Action are functions to be applied to files fitting a regex.
	Action func(path string, info os.FileInfo) error
	// PatternAction describe which functions are applied on which regex.
	PatternAction struct {
		Pattern *regexp.Regexp
		Actions []Action
	}
	// PatternActions is a slice of PatternAction.
	PatternActions []PatternAction
)

// buildPatternActions builds a PatternActions slice allowing to
// insert additional info if necessary.
func buildPatternActions(signingKeyRing *crypto.KeyRing) PatternActions {
	return PatternActions{
		{regexp.MustCompile(`.json$`), []Action{hashFile, encloseSignFile(signingKeyRing)}},
	}
}

// Apply walks through a given directory and applies all Actions as defined in PatternAction
func (pa PatternActions) Apply(inputDir string) error {

	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Directories are created as necessary later,
		// so no need to create explicitely possible unused directories via walk.
		if info.IsDir() {
			return nil
		}

		fname := info.Name()

		for _, p := range pa {
			if p.Pattern.MatchString(fname) {
				for _, action := range p.Actions {
					if err := action(path, info); err != nil {
						return fmt.Errorf("apply pattern %q failed: %w", p.Pattern, err)
					}
				}
			}
		}

		return nil
	})
}
