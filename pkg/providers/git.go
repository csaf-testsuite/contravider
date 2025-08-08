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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

func initialCheckout(url, directory string, branches []string) error {
	create := false
	cloneDir := filepath.Join(directory, "checkout")
	if _, err := os.Stat(cloneDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		create = true
	}

	if create {
		cmd := exec.Command("git", "clone", url, cloneDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("clone failed", "msg", output)
			return fmt.Errorf("clone failed: %w", err)
		}
	}

	//TODO: Checkout the branches.
	_ = branches

	return nil
}
