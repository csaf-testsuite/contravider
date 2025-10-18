// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

// Package providers fuses caches Git branches to servable provider directories.
package providers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-testsuite/contravider/pkg/config"
)

// System manages the sync between the git repo, the local checkouts
// and the served providers.
type System struct {
	cfg  *config.Config
	key  *crypto.KeyRing
	done bool
	fns  chan func(*System)
}

// NewSystem create a new System.
func NewSystem(cfg *config.Config) (*System, error) {
	key, err := prepareKeyRing(cfg.Signing.Key, cfg.Signing.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("cannot load signing key: %w", err)
	}
	if err := initialCheckout(
		cfg.Providers.GitURL,
		cfg.Providers.WorkDir,
		cfg.Providers.Profiles.AllBranches(),
	); err != nil {
		return nil, fmt.Errorf("initial checkout failed %w", err)
	}
	return &System{
		cfg: cfg,
		key: key,
		fns: make(chan func(*System)),
	}, nil
}

// Run drives the system. Meant to be run in a Go routine.
func (s *System) Run(ctx context.Context) {
	for !s.done {
		select {
		case <-ctx.Done():
			s.done = true
		case fn := <-s.fns:
			fn(s)
		}
	}
}

// Kill stops the system.
func (s *System) Kill() {
	s.fns <- func(s *System) { s.done = true }
}

// Serve prepares the serving of a given profile.
func (s *System) Serve(profile string) error {
	branches := s.cfg.Providers.Profiles[profile]
	if len(branches) == 0 {
		return fmt.Errorf("no such profile: %q", profile)
	}
	result := make(chan error)
	s.fns <- func(s *System) {
		profileDir := path.Join(s.cfg.Web.Root, profile)
		profileDir, err := filepath.Abs(profileDir)
		if err != nil {
			result <- fmt.Errorf("unable to get abs path for %q: %w", profile, err)
			return
		}

		slog.Debug("profile dir", "dir", profileDir)

		// Check if we already have instantiated this profile.
		switch _, err := os.Stat(profileDir); {
		case errors.Is(err, os.ErrNotExist):
			slog.Debug("profile does not exists", "profile", profile)
		case err != nil:
			result <- fmt.Errorf(
				"stating profile %q failed: %w", profile, err)
			return
		default:
			// We already have it.
			result <- nil
			return
		}

		// The hash over all branch revisions will be the destination folder.
		hash, err := allRevisionsHash(s.cfg.Providers.WorkDir, branches)
		if err != nil {
			result <- fmt.Errorf(
				"calculating hash of the branches of %q failed: %w",
				profile, err)
			return
		}
		slog.Debug("current hash", "profile", profile, "hash", hash)

		targetDir := path.Join(s.cfg.Web.Root, hash)
		if targetDir, err = filepath.Abs(targetDir); err != nil {
			result <- fmt.Errorf("unable to get abs path for %q: %w", profile, err)
			return
		}

		// Create target directory to write the export into.
		if err := os.MkdirAll(targetDir, 0777); err != nil {
			result <- fmt.Errorf("creating profile directory failed: %w", err)
			return
		}

		// TODO: Pass templates in.
		data := &TemplateData{
			// TODO: Fill me!
		}
		untar := templateFromTar(targetDir, data)

		if err := mergeBranches(s.cfg.Providers.WorkDir, branches, untar); err != nil {
			os.RemoveAll(targetDir)
			result <- fmt.Errorf("merging profile %q failed: %w", profile, err)
			return
		}

		// Store the public key in the exported directory.
		if err := s.writePublicKey(targetDir); err != nil {
			result <- fmt.Errorf("signing failed: %w", err)
			return
		}

		// TODO: Do signing.

		// Create a symlink for the profile.
		if err := os.Symlink(targetDir, profileDir); err != nil {
			os.RemoveAll(targetDir)
			result <- fmt.Errorf("symlinking profile %q failed: %w", profile, err)
			return
		}

		result <- nil
	}
	return <-result
}

// writePublicKey writes the public key into the target directory.
func (s *System) writePublicKey(targetDir string) error {
	key, err := s.key.GetKey(0)
	if err != nil {
		return fmt.Errorf("cannot extract private key: %w", err)
	}
	asc, err := key.GetArmoredPublicKey()
	if err != nil {
		return fmt.Errorf("cannot get public key: %w", err)
	}
	path := path.Join(targetDir, "public.asc")
	if err := os.WriteFile(path, []byte(asc), 0666); err != nil {
		return fmt.Errorf("cannot write public key to %q: %w", path, err)
	}
	return nil
}
