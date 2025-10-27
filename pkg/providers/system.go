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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/csaf-testsuite/contravider/pkg/config"
)

// System manages the sync between the git repo, the local checkouts
// and the served providers.
type System struct {
	cfg  *config.Config
	key  *crypto.Key
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
	ticker := time.NewTicker(s.cfg.Providers.Update)
	defer ticker.Stop()
	for !s.done {
		select {
		case <-ctx.Done():
			s.done = true
		case fn := <-s.fns:
			fn(s)
		case <-ticker.C:
			s.update()
		}
	}
}

// Kill stops the system.
func (s *System) Kill() {
	s.fns <- func(s *System) { s.done = true }
}

// ErrProfileNotFound is returned if a profile was not found.
var ErrProfileNotFound = errors.New("profile not found")

// Serve prepares the serving of a given profile.
func (s *System) Serve(profile string) error {
	branches := s.cfg.Providers.Profiles[profile]
	if len(branches) == 0 {
		return ErrProfileNotFound
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
		h, err := allRevisionsHash(s.cfg.Providers.WorkDir, branches)
		if err != nil {
			result <- fmt.Errorf(
				"calculating hash of the branches of %q failed: %w",
				profile, err)
			return
		}
		hash := hex.EncodeToString(h)
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

		errExit := func(err error) {
			// Ensure that the debris is always removed.
			os.RemoveAll(targetDir)
			result <- err
		}

		directivesBuilder := &DirectoryBuilder{}

		untar := templateFromTar(
			targetDir,
			s.fillTemplateData(profile),
			directivesBuilder.addDirectives)

		if err := mergeBranches(s.cfg.Providers.WorkDir, branches, untar); err != nil {
			errExit(fmt.Errorf("merging profile %q failed: %w", profile, err))
			return
		}

		// If we have directives store them in the root folder of the export.
		if directories := directivesBuilder.Directories(); directories != nil {
			directoriesFile := path.Join(targetDir, ".directories.json")
			slog.Debug("writing directories file", "file", directoriesFile)
			if err := directories.WriteToFile(directoriesFile); err != nil {
				errExit(fmt.Errorf(
					"storing directories file for profile %q failed: %w",
					profile, err))
				return
			}
		}

		// Store the public key in the exported directory.
		if err := writePublicKey(s.key, targetDir); err != nil {
			errExit(fmt.Errorf("signing failed: %w", err))
			return
		}

		// Sign and hash the relevant files.
		patterns, err := s.buildPatternActions()
		if err != nil {
			errExit(fmt.Errorf("building patterns failed: %w", err))
			return
		}
		if err := patterns.Apply(targetDir); err != nil {
			errExit(fmt.Errorf("applying actions failed: %w", err))
			return
		}

		// Create a symlink for the profile.
		if err := os.Symlink(targetDir, profileDir); err != nil {
			errExit(fmt.Errorf("symlinking profile %q failed: %w", profile, err))
			return
		}

		result <- nil
	}
	return <-result
}

// buildPatternActions builds a PatternActions slice allowing to
// insert additional info if necessary.
func (s *System) buildPatternActions() (PatternActions, error) {
	signing, err := encloseSignFile(s.key)
	if err != nil {
		return nil, fmt.Errorf("creating signing failed: %w", err)
	}
	return PatternActions{
		{regexp.MustCompile(`csaf-feed-tlp-[^\.]*\.json$`), nil},
		{regexp.MustCompile(`(\.directories|provider-metadata|service|category)[^\.]*\.json$`), nil},
		{regexp.MustCompile(`\.json$`), []Action{hashFile, signing}},
	}, nil
}

// update checks the git repo for update and invalidates providers
// which need regeneration.
func (s *System) update() {
	refreshed, err := updateBranches(
		s.cfg.Providers.WorkDir,
		s.cfg.Providers.Profiles.AllBranches())
	if err != nil {
		slog.Error("updating branches failed", "error", err)
	}
	// Even if there where errors there might be some links to delete.
	profiles := s.cfg.Providers.Profiles.DependingProfiles(refreshed)
	for _, profile := range profiles {
		link := path.Join(s.cfg.Web.Root, profile)
		info, err := os.Lstat(link)
		// Delete only the exported profile with symlinks to them.
		if err != nil || info.Mode()&os.ModeSymlink != os.ModeSymlink {
			continue
		}
		exported, err := filepath.EvalSymlinks(link)
		if err != nil {
			slog.Error("evaluating symlink failed", "error", err)
			continue
		}
		// Remove the linked profile export.
		if err := os.RemoveAll(exported); err != nil {
			slog.Error("removing symlinked dir failed", "error", err, "branch", profile)
		}
		// Remove the link itself.
		if err := os.Remove(link); err != nil {
			slog.Error("removing link to profile failed", "error", err, "branch", profile)
		}
	}
}

// fillTemplateData fills in the data needed to be interpolated into the templates.
func (s *System) fillTemplateData(profile string) *templateData {
	var (
		r = strings.NewReplacer(
			"{protocol}", s.cfg.Web.Protocol,
			"{host}", s.cfg.Web.Host,
			"{port}", strconv.Itoa(s.cfg.Web.Port),
			"{profile}", profile,
		)
		baseURL     = r.Replace(s.cfg.Providers.BaseURL)
		fingerprint = s.key.GetFingerprint()
		keyURL      = baseURL + "/" + s.key.GetHexKeyID() + ".asc"
	)
	return &templateData{
		BaseURL:                     baseURL,
		PublicOpenPGPKeyFingerprint: fingerprint,
		PublicOpenPGPKeyURL:         keyURL,
	}
}
