package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type directiveFile struct {
	ProviderMetadata struct {
		CanonicalURL string `toml:"canonical_url"`
	} `toml:"provider_metadata"`
}

// applyProviderMetadataOverrides reads .well-known/csaf/.directives.toml (if present)
// and overrides fields (currently canonical_url) in provider-metadata.json.
func applyProviderMetadataOverrides(root string) error {
	dirToml := filepath.Join(root, ".well-known", "csaf", ".directives.toml")
	info, err := os.Stat(dirToml)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil // nothing to do
	case err != nil:
		return fmt.Errorf("stat .directives.toml failed: %w", err)
	case info.IsDir():
		return fmt.Errorf(".directives.toml path is a directory")
	}

	var df directiveFile
	if _, err := toml.DecodeFile(dirToml, &df); err != nil {
		return fmt.Errorf("parsing .directives.toml failed: %w", err)
	}

	if df.ProviderMetadata.CanonicalURL == "" {
		return nil // no patch requested
	}

	metaPath := filepath.Join(root, ".well-known", "csaf", "provider-metadata.json")
	f, err := os.Open(metaPath)
	if err != nil {
		return fmt.Errorf("open provider-metadata.json failed: %w", err)
	}
	var meta map[string]any
	if err := json.NewDecoder(f).Decode(&meta); err != nil {
		f.Close()
		return fmt.Errorf("decode provider-metadata.json failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close provider-metadata.json failed: %w", err)
	}

	// Override canonical_url from .directives.toml.
	meta["canonical_url"] = df.ProviderMetadata.CanonicalURL

	tmp := metaPath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp provider-metadata failed: %w", err)
	}
	if err := json.NewEncoder(out).Encode(meta); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("encode patched provider-metadata failed: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp provider-metadata failed: %w", err)
	}
	if err := os.Rename(tmp, metaPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace provider-metadata failed: %w", err)
	}

	return nil
}
