<!--
// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>
-->

## Requirements
 - [Latest Go](https://go.dev/doc/install)
 - [git](https://git-scm.com/install/linux)

## How to start

- Step 1: Prepare a configuration file. E.g. copy the example-contraviderd.toml and adjust to your needs:
  - `cp docs/example-contraviderd.toml contraviderd.toml`
  - See [the our config documentation](./config.md) on how to configure your toml file
- Step 2: Build the contravider executable:
  - `go build ./cmd/contraviderd/`

- Step 3: Start the contraviderd either from the directory containing the toml configuration file or while pointing towards it:
  - `./cmd/contraviderd/contraviderd -c contraviderd.toml` 
  - Note that if you don't explicitely point towards the toml file, then it needs to be named `contraviderd.toml` and be in your current working directory.
