package config

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/BurntSushi/toml"
)

// DefaultConfigFile is the name of the default config file.
const DefaultConfigFile = "docs/example-contravider-config.toml"

const (
	defaultLogFile   = "contravider.log"
	defaultLogLevel  = slog.LevelInfo
	defaultLogSource = false
	defaultLogJSON   = false
)

const (
	defaultWebHost = "localhost"
	defaultWebPort = 8083
	defaultWebRoot = "web"
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
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Root     string `toml:"root"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// Config are all the configuration options.
type Config struct {
	Log      Log      `toml:"log"`
	Web      Web      `toml:"web"`
	Sessions Sessions `toml:"sessions"`
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
			Host: defaultWebHost,
			Port: defaultWebPort,
			Root: defaultWebRoot,
		},
		Sessions: Sessions{
			Secret: nil,
			MaxAge: defaultSessionMaxAge,
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

// PresetDefaults initializes unset values.
func (cfg *Config) PresetDefaults() {
	cfg.Sessions.presetDefaults()
}

func (cfg *Config) fillFromEnv() error {
	var (
		storeString = store(noparse)
		storeInt    = store(strconv.Atoi)
		storeBool   = store(strconv.ParseBool)
		storeLevel  = store(storeLevel)
	)
	return storeFromEnv(
		envStore{"OQC_LOG_FILE", storeString(&cfg.Log.File)},
		envStore{"OQC_LOG_LEVEL", storeLevel(&cfg.Log.Level)},
		envStore{"OQC_LOG_JSON", storeBool(&cfg.Log.JSON)},
		envStore{"OQC_LOG_SOURCE", storeBool(&cfg.Log.Source)},
		envStore{"OQC_WEB_HOST", storeString(&cfg.Web.Host)},
		envStore{"OQC_WEB_PORT", storeInt(&cfg.Web.Port)},
		envStore{"OQC_WEB_ROOT", storeString(&cfg.Web.Root)},
	)
}
