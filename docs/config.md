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

## Explanation of the `example-contraviderd.toml` configuration file

The setup of the provider is configured with a [TOML v1.0.0](https://toml.io/en/v1.0.0) file.
An example file can be found [here](./example-contraviderd.toml)
(with the default values as comments).

## Sections

The configuration consists of the following sections:

- [`[log]`](#section_log) Logging configuration
- [`[signing]`](#section_signing) Signing Key
- [`[web]`](#section_web) Web server configuration
- [`[providers]`](#section_providers) Providerstructure

### <a name="section_log"></a> Section `[log]` Logging configuration
- `file`: File to log to. An empty string logs to stderr. Defaults to `"isduba.log"`.
- `level`: Log level. Possible values are `"debug"`, `"info"`, `"warn"` and `"error"`. Defaults to `"info"`.
- `source`: Add source reference to log output. Defaults to `false`.
- `json`: Log as JSON lines. Defaults to `false`.

### <a name="section_signing"></a> Section `[signing]` Signing Key
- `key`: Location of the openpgp private key. Defaults to `privatekey.asc`.
- `passphrase`: Passphrase of the openpgp private key. Defaults to "".

### <a name="section_web"></a> Section `[web]` Web server configuration
- `host`: Interface the web server listens on. Defaults to `"localhost"`.
If the value starts with a slash (`/`) it is assumed to serve on an unix domain socket.
In this case all appearance of `{port}` in ths `host` string are replaced by the `port` number.
- `port`: Port the web server listens on. Defaults to `8081`.
- `protocol`: The assumed protocol the web server is using. Currently only affects the URLs within the documents. Defaults to `"https"`.
- `root`: The location for the provider to be served. Defaults to `"web"`.
- `cert_file`: Public key of the server. Defaults to `""` (not set. Set if you want to run a HTTPS server).
- `key_file`: Private key of the server. Defaults to `""` (not set. Set if you want to run a TLS server).

### <a name="section_providers"></a> Section `[providers]` Providerstructure
- `git_url`: The url of the git repository containing the various good and bad branches. Defaults to `"https://github.com/csaf-testsuite/distribution.git"` 
- `update`: How often to check for new commits within the git repository. Defaults to `"5m"` (5 minutes).
- `base_url`: The base url serving the .well-known directory according to the advisories. Defaults to `"{protocol}://{host}:{port}/{profile}"`.
- `workdir`: The checkout directory of the git repository. Defaults to `"checkout"`.
- `profiles`: Building profiles to be served by the contravider. Each profile is either a branch of the git repository or a merge of other profiles
profiles: The following three types of identifiers are available for the classification of the profiles
- VALID_: This prefix indicates configurations that are set up correctly and comply with established requirements.
- STANDARD_ERROR_: This prefix is used for misconfigurations that do not meet the requirements of the CSAF standard.
- KNOWN_ISSUE_: This prefix designates misconfigurations that have already been identified in existing systems.

The structure is as follows:
`profiles.Identifier = [profile1, profile2, ...]`

Some default examples:
- `profiles.STANDARD_ERROR_VALID_CSAF_DOCUMENT = ["main", "7.1.1_Requirement_1_Valid_CSAF_Document"]`
- `profiles.STANDARD_ERROR_FILENAME = ["main", "7.1.2_Requirement_2_Filename"]`
- `profiles.STANDARD_ERROR_TLP_WHITE = ["main", "7.1.4_Requirement_4_TLP_WHITE"]`

