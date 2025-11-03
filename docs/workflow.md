<!--
// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bs>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.>
-->

## Building the contraviderd

The contravider is based on Go. Simply build it using ```go build```, e.g. while being in /cmd/contraviderd:
```go build ./... ```

## Profiles

The contravider is build on profiles. Each profile represents a provider. 
The simplest profiles simply represent a single branch,
either representing a completely valid provider (e.g. profiles.VALID_MAIN) or
a singular violated requirement (e.g. profiles.STANDARD_ERROR_VALID_CSAF_DOCUMENT, which contains
an invalid CSAF document).

How to locate the sources for the branches is outlined within the [config documentation](./config.md).
The default the contravider is build for uses the [contravider distribution](https://github.com/csaf-testsuite/distribution).


To generate the provider you want to test, you need to build a profile which contains all branches whose changes you want to include.

For example (while the default examples follow a naming convention, it’s not required):

 - ```profiles.STANDARD_ERROR_VALID_CSAF_DOCUMENT = ["7.1.1_Requirement_1_Valid_CSAF_Document"]``` contains a provider based on the ```7.1.1_Requirement_1_Valid_CSAF_Document``` branch
 - ```profiles.STANDARD_ERROR_VALID_CSAF_DOCUMENT_AND_FILENAME = ["7.1.1_Requirement_1_Valid_CSAF_Document", "7.1.2_Requirement_2_Filename"]``` contains a provider based on the branches ```7.1.1_Requirement_1_Valid_CSAF_Document``` and ```7.1.2_Requirement_2_Filename``` and violates both constraints.


There are still limitations on what providers the profiles can build and which branches can be merged. See [the limitations config](./limitations.md) for more explanations.

When your adjusted toml file contains the profile you want, simply start the contraviderd either from the directory containing the toml configuration file or while pointing towards it:
  - `./cmd/contraviderd/contraviderd -c contraviderd.toml` 
  - Note that if you don't explicitely point towards the toml file, then it needs to be named `contraviderd.toml` and be in your current working directory or the application won't start.
