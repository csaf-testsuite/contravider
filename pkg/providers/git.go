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

func initialCheckout(url, workdir string, branches []string) error {

	absWorkDir, err := filepath.Abs(workdir)
	if err != nil {
		return fmt.Errorf("abs failed: %w", err)
	}
	workdir = absWorkDir
	cloneDir := filepath.Join(workdir, "main")

	if _, err := os.Stat(workdir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(workdir, 0777); err != nil {
			return fmt.Errorf("creating workdir failed: %w", err)
		}
	}

	clone := false
	if _, err := os.Stat(cloneDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		clone = true
	}

	if clone { // Fresh checkout
		cmd := exec.Command("git", "clone", url, cloneDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("clone failed", "msg", output)
			return fmt.Errorf("clone failed: %w", err)
		}
	} else { // Only update
		cmd := exec.Command("git", "pull")
		cmd.Dir = cloneDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("git pull failed", "msg", output, "err", err)
			return fmt.Errorf("git pull failed: %w", err)
		}
	}

	for _, branch := range branches {
		if branch == "main" {
			// Ignore main as it already there.
			continue
		}
		branchDir := filepath.Join(workdir, branch)
		if _, err := os.Stat(branchDir); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			// Create
			cmd := exec.Command("git", "worktree", "add", branchDir, branch)
			cmd.Dir = cloneDir
			output, err := cmd.CombinedOutput()
			if err != nil {
				slog.Error("worktree add failed", "msg", output, "err", err)
				return fmt.Errorf("worktree add failed: %w", err)
			}
		} else { // Only update
			cmd := exec.Command("git", "pull")
			cmd.Dir = branchDir
			output, err := cmd.CombinedOutput()
			if err != nil {
				slog.Error("git pull failed", "msg", output, "err", err)
				return fmt.Errorf("git pull failed: %w", err)
			}
		}
	}

	return nil
}
