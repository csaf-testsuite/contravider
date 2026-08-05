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

type scriptAdapter struct{}

func (scriptAdapter) Enter(any) error {
	return nil
}

func (scriptAdapter) Apply(_ any, _ []string, data []byte) ([]byte, error) {
	return data, nil
}

func (scriptAdapter) Leave(any) error {
	return nil
}
