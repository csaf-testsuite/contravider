// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

package providers

import (
	"archive/tar"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// TemplateData is a collection of strings which need to
// be defined when building the system
type TemplateData struct {
	CanonicalURL          string
	DirectoryURL          string
	DistributionURL       string
	FeedURL               string
	PublicOpenPGPKeyURL   string
	RolieFeedURL          string
	ServiceCollectionURL  string
	PublisherNamespaceURL string
}

// asMap converts the template data to an upper case key map.
func (td *TemplateData) asMap() map[string]string {
	return map[string]string{
		"CANONICAL_URL":           td.CanonicalURL,
		"DIRECTORY_URL":           td.DirectoryURL,
		"DISTRIBUTION_URL":        td.DistributionURL,
		"FEED_URL":                td.FeedURL,
		"PUBLIC_OPENPGP_KEY_URL":  td.PublicOpenPGPKeyURL,
		"ROLIE_FEED_URL":          td.RolieFeedURL,
		"SERVICE_COLLECTION_URL":  td.ServiceCollectionURL,
		"PUBLISHER_NAMESPACE_URL": td.PublisherNamespaceURL,
	}
}

// templateFromTar deserializes files from a tar from a stream as templates
// and instantiate them with the given template data.
func templateFromTar(targetDir string, data *TemplateData) func(io.Reader) error {
	return func(r io.Reader) error {
		tmplMap := data.asMap()
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("untaring failed: %w", err)
			}
			parts := strings.Split(hdr.Name, "/")
			if len(parts) < 3 || parts[0] != "www" || parts[1] != "html" {
				slog.Debug("ignore tar entry", "name", hdr.Name)
				continue
			}
			parts[1] = targetDir // prefix with targetDir
			switch name := path.Join(parts[1:]...); hdr.Typeflag {
			case tar.TypeReg:
				slog.Debug("create file", "file", name)
				content, err := io.ReadAll(tr)
				if err != nil {
					return fmt.Errorf("cannot read data of %q: %w", hdr.Name, err)
				}
				// Parse the template data.
				tmpl, err := template.New(parts[len(parts)-1]).
					Delims("$((", "))$").
					Parse(string(content))
				if err != nil {
					return fmt.Errorf("parsing %q as template failed: %w", hdr.Name, err)
				}
				f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode))
				if err != nil {
					return fmt.Errorf("cannot create file %q: %w", name, err)
				}
				if err := errors.Join(tmpl.Execute(f, tmplMap), f.Close()); err != nil {
					return fmt.Errorf("writing templated data to %q failed: %w", name, err)
				}

			case tar.TypeDir:
				slog.Debug("create directory", "dir", name)
				if err := os.MkdirAll(name, os.FileMode(hdr.Mode)); err != nil {
					return fmt.Errorf("creating directory %q failed: %w", name, err)
				}
			}
		}
		return nil
	}
}

type (
	// Action are functions to be applied to files fitting a regex.
	Action func(path string, info os.FileInfo) error
	// PatternAction describe which functions are applied on which regex.
	PatternAction struct {
		Pattern *regexp.Regexp
		Actions []Action
	}
	// PatternActions is a slice of PatternAction.
	PatternActions []PatternAction
)

// buildPatternActions builds a PatternActions slice allowing to
// insert additional info if necessary.
func buildPatternActions(signingKeyRing *crypto.KeyRing) PatternActions {
	return PatternActions{
		{regexp.MustCompile(`.json$`), []Action{hashFile, encloseSignFile(signingKeyRing)}},
	}
}

// Apply walks through a given directory and applies all Actions as defined in PatternAction
func (pa PatternActions) Apply(inputDir string) error {

	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Directories are created as necessary later,
		// so no need to create explicitely possible unused directories via walk.
		if info.IsDir() {
			return nil
		}

		fname := info.Name()

		for _, p := range pa {
			if p.Pattern.MatchString(fname) {
				for _, action := range p.Actions {
					if err := action(path, info); err != nil {
						return fmt.Errorf("apply pattern %q failed: %w", p.Pattern, err)
					}
				}
			}
		}

		return nil
	})
}
