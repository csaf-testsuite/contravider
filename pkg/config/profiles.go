// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

package config

import (
	"fmt"
	"slices"
	"strings"
)

// Profiles are the profiles served by this contravider.
type Profiles map[string][]string

// UnmarshalTOML implements [toml.Unmarshaler].
func (p *Profiles) UnmarshalTOML(data any) error {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected type %T", data)
	}
	pr := make(Profiles, len(m))
	for k, v := range m {
		l, ok := v.([]any)
		if !ok {
			return fmt.Errorf("unexpected type %T", v)
		}
		list := make([]string, 0, len(l))
		for _, s := range l {
			str, ok := s.(string)
			if !ok {
				return fmt.Errorf("unexpected type %T", s)
			}
			list = append(list, str)
		}
		pr[k] = list
	}
	if err := pr.check(); err != nil {
		return err
	}
	*p = pr
	return nil
}

// check checks for cyclic and undefined definitions.
func (p Profiles) check() error {
	checkProfile := func(name string, branches []string) error {
		seen := map[string]bool{name: true}
		var resolve func(string) error
		resolve = func(def string) error {
			if !strings.HasPrefix(def, "#") {
				return nil
			}
			// its a reference.
			def = def[1:]
			if seen[def] {
				return fmt.Errorf("self recursive definition %q", def)
			}
			seen[def] = true
			branches, ok := p[def]
			if !ok {
				return fmt.Errorf("undefined defintion %q", def)
			}
			for _, branch := range branches {
				if err := resolve(branch); err != nil {
					return err
				}
			}
			return nil
		}
		for _, branch := range branches {
			if err := resolve(branch); err != nil {
				return err
			}
		}
		return nil
	}
	for name, branches := range p {
		if err := checkProfile(name, branches); err != nil {
			return err
		}
	}
	return nil
}

func (p Profiles) collectBranches(all, branches []string) []string {
	var collect func(branches []string)
	collect = func(branches []string) {
		for _, branch := range branches {
			if strings.HasPrefix(branch, "#") {
				collect(p[branch[1:]])
			} else if !slices.Contains(all, branch) {
				all = append(all, branch)
			}
		}
	}
	collect(branches)
	return all
}

// Branches returns the branches for a given profile.
func (p Profiles) Branches(name string) []string {
	return p.collectBranches(nil, p[name])
}

// AllBranches returns a list of all branches which are relevant for the contravider.
func (p Profiles) AllBranches() []string {
	var all []string
	for _, branches := range p {
		all = p.collectBranches(all, branches)
	}
	slices.Sort(all) // to make it deterimistic.
	return all
}
