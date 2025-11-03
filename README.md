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

# Contravider

The [CSAF](csaf.io) Contravider is a utility designed to generate varied implementations of [CSAF Providers](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#722-role-csaf-provider).
It helps developers and testers validate tools that are intended to check CSAF Providers for standard compliance. 

The contravider takes a git repository containing multiple mergable branches and serves them via a web server. Using a [dedicated git repository](https://github.com/csaf-testsuite/distribution), it can
easily and conveniently mock a CSAF Provider

See the [documentation to learn how to get started](./docs)

## License

The Contravider is Free Software.

Source code written for the Contravider was placed under the
[Apache License, Version 2.0](./LICENSES/Apache-2.0.txt).

```
 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering:	 2025 Intevation GmbH <https://intevation.de>
			2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

```

The contravider depends on third party Free Software components which have their
own right holders and licenses. To our best knowledge
(at the time when they were added)
the dependencies are upwards compatible with the contravider main license.

### Dependencies

The top level dependencies can be seen from

- [go.mod](./go.mod) for the backend and server tools.
- The build and setup descriptions (linked above).

Use one of several available Free Software tools to examine indirect
dependencies and get a more complete list of component names and licenses.
