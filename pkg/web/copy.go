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
	"html/template"
	"os"
	"path/filepath"
)

// CopyDirectory copies all files from the input directory inputDir and all files in all subfolders
// into the output directory outputDir using the Walk function while executing the templates.
func (c *Controller) copyDirectory(inputDir string, outputDir string, data any) error {

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
