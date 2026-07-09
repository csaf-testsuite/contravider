// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025, 2026 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

package providers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func Apply(
	src, dst string,
	dir *Directory,
) error {
	var recurse func(path []string) error

	var context any // TODO: make useful.

	recurse = func(path []string) (callErr error) {
		fmt.Printf("entering %v\n", path)
		scripts := dir.FindScripts(path)
		for _, script := range scripts {
			if err := script.Enter(context); err != nil {
				return err
			}
			defer func() {
				callErr = errors.Join(callErr, script.Leave(context))
			}()
		}

		srcPath := filepath.Join(append([]string{src}, path...)...)
		entries, err := os.ReadDir(srcPath)
		if err != nil {
			return fmt.Errorf("read dir failed: %w", err)
		}

		// Create dst folder.
		dstDirPath := filepath.Join(append([]string{dst}, path...)...)
		if err := os.MkdirAll(dstDirPath, 0777); err != nil {
			return err
		}

		for _, entry := range entries {
			subPath := append(slices.Clone(path), entry.Name())
			if entry.IsDir() {
				if err := recurse(subPath); err != nil {
					return err
				}
			} else { // File
				filePath := filepath.Join(append([]string{src}, subPath...)...)
				data, err := os.ReadFile(filePath)
				if err != nil {
					return err
				}
				// Apply context before custom scripts.
				if ndata, err := applyBefore(context, data); err != nil {
					return err
				} else {
					data = ndata
				}
				// Apply the custom scripts.
				for _, script := range scripts {
					ndata, err := script.Apply(context, subPath, data)
					if err != nil {
						return err
					}
					data = ndata
				}
				// Apply context after custom scripts.
				if ndata, err := applyAfter(context, data); err != nil {
					return err
				} else {
					data = ndata
				}
				dstPath := filepath.Join(dstDirPath, entry.Name())
				if err := os.WriteFile(dstPath, data, 0666); err != nil {
					return err
				}
			}
		}
		return nil
	}

	return recurse(nil)
}

func applyBefore(context any, data []byte) ([]byte, error) {
	// TODO:
	_ = context
	return data, nil
}

func applyAfter(context any, data []byte) ([]byte, error) {
	// TODO:
	_ = context
	return data, nil
}
