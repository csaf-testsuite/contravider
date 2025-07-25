// Package providers fuses caches Git branches to servable provider directories.
package providers

import (
	"context"
	"errors"
	"fmt"

	"github.com/csaf-testsuite/contravider/pkg/config"
)

type System struct {
	cfg  *config.Config
	done bool
	fns  chan func(*System)
}

// NewSystem create a new System.
func NewSystem(cfg *config.Config) (*System, error) {
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
