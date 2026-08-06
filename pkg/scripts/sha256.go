// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2026 Intevation GmbH <https://intevation.de>
// * 2026 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

package scripts

import (
	"github.com/csaf-testsuite/contravider/pkg/providers"
)

type (
	sha256Factory struct{}
	sha256Script  struct{ scriptAdapter }
)

// Create implements [providers.ScriptFactory].
func (sha256Factory) Create(providers.Directive) (providers.Script, error) {
	return sha256Script{}, nil
}
