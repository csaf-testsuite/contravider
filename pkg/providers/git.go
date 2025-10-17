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
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
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

// allRevisionsHash returns a hash over all revisions of the given branches.
func allRevisionsHash(workdir string, branches []string) (string, error) {
	hash := sha1.New()
	for _, branch := range branches {
		rev, err := currentRevision(workdir, branch)
		if err != nil {
			return "", fmt.Errorf("allRevisions failed for %q: %w", branch, err)
		}
		io.WriteString(hash, rev)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// currentRevision returns the current revision of a checked out branch.
func currentRevision(workdir, branch string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = path.Join(workdir, branch)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("git rev-parse failed", "msg", output, "err", err)
		return "", fmt.Errorf("git rev-parse failed: %w", err)
	}
	rev := strings.TrimSpace(string(output))
	slog.Debug("current revision", "branch", branch, "revision", rev)
	return rev, nil
}
