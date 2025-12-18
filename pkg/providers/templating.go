package providers

import (
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

func renderTemplates(inputDir, outputDir string, data *templateData) error {
	// Ensure target exists.
	if err := os.MkdirAll(outputDir, 0777); err != nil {
		return fmt.Errorf("create outputDir failed: %w", err)
	}
	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(inputDir, path)
		dest := filepath.Join(outputDir, rel)

		if info.IsDir() {
			return os.MkdirAll(dest, info.Mode())
		}
		// Regular file: render with template delimiters.
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %q failed: %w", path, readErr)
		}
		tmpl, parseErr := template.New(info.Name()).
			Delims("$((", "))$").
			Parse(string(content))
		if parseErr != nil {
			return fmt.Errorf("parse %q as template failed: %w", path, parseErr)
		}
		out, createErr := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
		if createErr != nil {
			return fmt.Errorf("create %q failed: %w", dest, createErr)
		}
		if execErr := errors.Join(tmpl.Execute(out, data), out.Close()); execErr != nil {
			return fmt.Errorf("write rendered %q failed: %w", dest, execErr)
		}
		return nil
	})
}
