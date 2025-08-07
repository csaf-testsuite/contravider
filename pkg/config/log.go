// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

package config

import (
	"io"
	"log/slog"
	"os"
)

// Config applies the logging configuration to the default slog logger.
func (lg *Log) Config() error {
	var w io.Writer
	if lg.File == "" {
		w = os.Stderr
	} else {
		f, err := os.OpenFile(lg.File, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		w = f
	}

	// Create a multi-writer to output logs to both the file and the console.
	multiWriter := io.MultiWriter(w, os.Stdout)

	opts := slog.HandlerOptions{
		AddSource: lg.Source,
		Level:     lg.Level,
	}
	var handler slog.Handler
	if lg.JSON {
		handler = slog.NewJSONHandler(multiWriter, &opts)
	} else {
		handler = slog.NewTextHandler(multiWriter, &opts)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return nil
}
