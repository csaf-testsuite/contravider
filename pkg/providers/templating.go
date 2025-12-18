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
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

func renderTemplates(inputDir string, data *templateData) error {
	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %q failed: %w", path, readErr)
		}
		tmpl, parseErr := template.New(info.Name()).
			Delims("$((", "))$").
			Parse(string(content))
		if parseErr != nil {
			return fmt.Errorf("parse %q as template failed: %w", path, parseErr)
		}
		dir := filepath.Dir(path)
		tmp, createErr := os.CreateTemp(dir, "."+info.Name()+".*.tmp")
		if createErr != nil {
			return fmt.Errorf("create temp for %q failed: %w", path, createErr)
		}
		// Ensure cleanup on error.
		defer os.Remove(tmp.Name())
		if chmodErr := os.Chmod(tmp.Name(), info.Mode()); chmodErr != nil {
			_ = tmp.Close()
			return fmt.Errorf("chmod temp %q failed: %w", tmp.Name(), chmodErr)
		}
		if execErr := tmpl.Execute(tmp, data); execErr != nil {
			_ = tmp.Close()
			return fmt.Errorf("render %q failed: %w", path, execErr)
		}
		if closeErr := tmp.Close(); closeErr != nil {
			return fmt.Errorf("close temp for %q failed: %w", path, closeErr)
		}
		if renameErr := os.Rename(tmp.Name(), path); renameErr != nil {
			return fmt.Errorf("replace %q failed: %w", path, renameErr)
		}
		return nil
	})
}
