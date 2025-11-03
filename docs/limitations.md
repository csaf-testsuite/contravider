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

## Limitations

The current contravider is still in development and we're still considering different approaches to solve various problems.

Currently, the serverside protection is handled with HTTP Basic Auth via `.directives.toml` files.

Any protected directory may contains a .directives.toml
with the following structure:

```[protection]
user     = $user
password = $password
```

where $user and $password are the user and password required respectively.
Folders inside the folder inherit this protection.

How DNS and similar are handled is still a subject of discussion.
