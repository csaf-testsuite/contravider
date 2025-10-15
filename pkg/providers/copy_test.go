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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPatternActions(t *testing.T) {
	// Create a dummy keyring for encloseSignFile
	// No error when creating keyring expected
	key, err := crypto.GenerateKey("Test", "test@example.com", "rsa", 2048)
	require.NoError(t, err)

	keyRing, err := crypto.NewKeyRing(key)
	require.NoError(t, err)

	// Create 1 PatternActions slice
	actions := buildPatternActions(keyRing)
	require.Len(t, actions, 1)

	// Test that the first string checks for JSON files. Add more checks when more regex are added
	patternAction := actions[0]
	assert.Equal(t, regexp.MustCompile(`.json$`).String(), patternAction.Pattern.String())
	// Adjust length as more functions are added
	require.Len(t, patternAction.Actions, 2)

	// Check that actions are callable
	for _, action := range patternAction.Actions {
		err := action("nonexistent.json", nil)
		assert.Error(t, err)
	}
}

func TestCopyDirectory(t *testing.T) {
	// Create inputDir, outputDir and data
	// Create temp directory
	tempDir := t.TempDir()
	inputDir := filepath.Join(tempDir, "inputDir")
	outputDir := filepath.Join(tempDir, "outputDir")
	if err := os.Mkdir(inputDir, 0755); err != nil {
		t.Fatalf("failed to create inputDir: %v", err)
	}
	if err := os.Mkdir(outputDir, 0755); err != nil {
		t.Fatalf("failed to create outputDir: %v", err)
	}
	content := []byte(`$((.FeedURL))$`)

	inputFile := filepath.Join(inputDir, "test.txt")
	outputFile := filepath.Join(outputDir, "test.txt")

	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	// Only FeedURL is used for now. Adjust if test is expanded
	// TODO: Evaluate: Maybe clone entire distribution into TempDir? Expensive, but extensive
	data := TemplateData{
		CanonicalURL:          "Failure",
		DirectoryURL:          "Failure",
		DistributionURL:       "Failure",
		FeedURL:               "Success",
		PublicOpenPGPKeyURL:   "Failure",
		RolieFeedURL:          "Failure",
		ServiceCollectionURL:  "Failure",
		PublisherNamespaceURL: "Failure",
	}
	// Copy inputDir/test.txt into outputDir/test.txt while executing it's templating with data
	err := copyDirectory(inputDir, outputDir, data)
	require.NoError(t, err)

	_, err = os.Stat(outputFile)
	require.NoError(t, err)

	fileContent, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	fileContentString := strings.TrimSpace(string(fileContent))

	require.Equal(t, "Success", fileContentString, "file content should match exactly")
}

func TestPatternActions_Apply(t *testing.T) {
	tempDir := t.TempDir()

	// Create two files, one matching, one not
	matchingFile := filepath.Join(tempDir, "match.txt")
	nonMatchingFile := filepath.Join(tempDir, "ignore.log")

	content := []byte("test")

	if err := os.WriteFile(matchingFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if err := os.WriteFile(nonMatchingFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Track which files had an action applied on them
	var appliedOn []string
	action := func(path string, _ os.FileInfo) error {
		appliedOn = append(appliedOn, filepath.Base(path))
		return nil
	}

	// Build the PatternActions: only *.txt should trigger
	pattern := regexp.MustCompile(`\.txt$`)
	pa := PatternActions{
		{
			Pattern: pattern,
			Actions: []Action{action},
		},
	}

	// Run Apply
	err := pa.Apply(tempDir)
	require.NoError(t, err)

	// Verify only the matching file was processed
	require.Equal(t, []string{"match.txt"}, appliedOn, "only match.txt should be acted on")
}
