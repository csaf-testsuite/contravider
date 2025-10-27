// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

// Package config contains the configuration of the contravider.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultConfigFile is the name of the default config file.
const DefaultConfigFile = "contraviderd.toml"

const (
	defaultLogFile   = "contravider.log"
	defaultLogLevel  = slog.LevelInfo
	defaultLogSource = false
	defaultLogJSON   = false
)

const (
	defaultWebHost     = "localhost"
	defaultWebPort     = 8083
	defaultWebProtocol = "https"
	defaultWebRoot     = "web"
	defaultWebCertFile = ""
	defaultWebKeyFile  = ""
)

const (
	defaultProvidersGitURL  = "https://github.com/csaf-testsuite/distribution.git"
	defaultProvidersBaseURL = "{protocol}://{host}:{port}/{profile}"
	defaultProvidersWorkDir = "checkout"
	defaultProvidersUpdate  = 5 * time.Minute
)

const (
	defaultSigningKey      = "privatekey.asc"
	defaultPassphrase      = ""
	deafultProvidersResult = "."
)

// Log are the config options for the logging.
type Log struct {
	File   string     `toml:"file"`
	Level  slog.Level `toml:"level"`
	Source bool       `toml:"source"`
	JSON   bool       `toml:"json"`
}

// Web are the config options for the web interface.
type Web struct {
	Host          string `toml:"host"`
	Port          int    `toml:"port"`
	Protocol      string `toml:"protocol"`
	Root          string `toml:"root"`
	CertFile      string `toml:"cert_file"`
	UsernameAmber string `toml:"username_amber"`
	PasswordAmber string `toml:"password_amber"`
	UsernameRed   string `toml:"username_red"`
	PasswordRed   string `toml:"password_red"`
	KeyFile       string `toml:"key_file"`
}

// Signing are the options needed to sign the advisories.
type Signing struct {
	Key        string `toml:"key"`
	Passphrase string `toml:"passphrase"`
}

// Providers are the config options for the served provider profiles.
type Providers struct {
	GitURL   string        `toml:"git_url"`
	BaseURL  string        `toml:"base_url"`
	Profiles Profiles      `toml:"profiles"`
	WorkDir  string        `toml:"workdir"`
	Update   time.Duration `toml:"update"`
	Result   string        `toml:"result"`
}

// Config are all the configuration options.
type Config struct {
	Log       Log       `toml:"log"`
	Web       Web       `toml:"web"`
	Signing   Signing   `toml:"signing"`
	Providers Providers `toml:"providers"`
}

// Addr returns the combined address the web server should bind to.
func (w *Web) Addr() string {
	return net.JoinHostPort(w.Host, strconv.Itoa(w.Port))
}

// Load loads the configuration from a given file. An empty string
// resorts to the default configuration.
func Load(file string) (*Config, error) {
	cfg := &Config{
		Log: Log{
			File:   defaultLogFile,
			Level:  defaultLogLevel,
			Source: defaultLogSource,
			JSON:   defaultLogJSON,
		},
		Web: Web{
			Host:     defaultWebHost,
			Port:     defaultWebPort,
			Protocol: defaultWebProtocol,
			Root:     defaultWebRoot,
			CertFile: defaultWebCertFile,
			KeyFile:  defaultWebKeyFile,
		},
		Signing: Signing{
			Key:        defaultSigningKey,
			Passphrase: defaultPassphrase,
		},
		Providers: Providers{
			GitURL:  defaultProvidersGitURL,
			BaseURL: defaultProvidersBaseURL,
			WorkDir: defaultProvidersWorkDir,
			Result:  deafultProvidersResult,
			Update:  defaultProvidersUpdate,
		},
	}
	if file != "" {
		md, err := toml.DecodeFile(file, cfg)
		if err != nil {
			return nil, err
		}
		// Don't accept unknown entries in config file.
		if undecoded := md.Undecoded(); len(undecoded) != 0 {
			return nil, fmt.Errorf("config: could not parse %q", undecoded)
		}
	}
	if err := cfg.fillFromEnv(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) fillFromEnv() error {
	var (
		storeString   = store(noparse)
		storeInt      = store(strconv.Atoi)
		storeBool     = store(strconv.ParseBool)
		storeLevel    = store(storeLevel)
		storeDuration = store(time.ParseDuration)
	)
	return storeFromEnv(
		envStore{"CONTRAVIDER_LOG_FILE", storeString(&cfg.Log.File)},
		envStore{"CONTRAVIDER_LOG_LEVEL", storeLevel(&cfg.Log.Level)},
		envStore{"CONTRAVIDER_LOG_JSON", storeBool(&cfg.Log.JSON)},
		envStore{"CONTRAVIDER_LOG_SOURCE", storeBool(&cfg.Log.Source)},
		envStore{"CONTRAVIDER_WEB_HOST", storeString(&cfg.Web.Host)},
		envStore{"CONTRAVIDER_WEB_PORT", storeInt(&cfg.Web.Port)},
		envStore{"CONTRAVIDER_WEB_PROTOCOL", storeString(&cfg.Web.Protocol)},
		envStore{"CONTRAVIDER_WEB_ROOT", storeString(&cfg.Web.Root)},
		envStore{"CONTRAVIDER_WEB_CERT_FILE", storeString(&cfg.Web.CertFile)},
		envStore{"CONTRAVIDER_WEB_KEY_FILE", storeString(&cfg.Web.KeyFile)},
		envStore{"CONTRAVIDER_SIGNING_KEY", storeString(&cfg.Signing.Key)},
		envStore{"CONTRAVIDER_PROVIDERS_GIT_URL", storeString(&cfg.Providers.GitURL)},
		envStore{"CONTRAVIDER_PROVIDERS_BASE_URL", storeString(&cfg.Providers.BaseURL)},
		envStore{"CONTRAVIDER_PROVIDERS_UPDATE", storeDuration(&cfg.Providers.Update)},
	)
}
