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

	"github.com/csaf-testsuite/contravider/pkg/config"
)

// System manages the sync between the git repo, the local checkouts
// and the served providers.
type System struct {
	cfg  *config.Config
	done bool
	fns  chan func(*System)
}

// NewSystem create a new System.
func NewSystem(cfg *config.Config) (*System, error) {
	if err := initialCheckout(
		cfg.Providers.GitURL,
		cfg.Providers.WorkDir,
		cfg.Providers.Profiles.AllBranches(),
	); err != nil {
		return nil, fmt.Errorf("initial checkout failed %w", err)
	}
	return &System{
		cfg: cfg,
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

func (s *System) serve(profile string) error {
	//TODO: Implement me!
	_ = profile
	// Check if profile already exists (git worktree branch).
	// If not create it (merge branches in new branch).
	// If it exists check its up-to-date. Hash of revisions (git describe).
	// Create copy with templating.
	return errors.New("not implemented, yet")
}

// Serve prepares the serving of a given profile.
func (s *System) Serve(profile string) error {
	if _, ok := s.cfg.Providers.Profiles[profile]; !ok {
		return fmt.Errorf("profile %q not found", profile)
	}
	err := make(chan error)
	s.fns <- func(s *System) { err <- s.serve(profile) }
	return <-err
}
