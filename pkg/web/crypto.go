// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering:
// * 2025 Intevation GmbH <https://intevation.de>
// * 2025 Fraunhofer Institute for Applied an Integrated Security (AISEC) <https://aisec.fraunhofer.de>

// Package web contains the web controller logic.
package web

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// prepareKeyRing unlocks and returns a reusable KeyRing for signing.
func prepareKeyRing(armoredPrivateKeyPath string, passphrase string) (*crypto.KeyRing, error) {
	// read armored private key as bytes from file
	armoredPrivateKeyByte, err := os.ReadFile(armoredPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	privateKeyObj, err := crypto.NewKeyFromArmored(string(armoredPrivateKeyByte))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	unlockedKeyObj, err := privateKeyObj.Unlock([]byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to unlock private key: %w", err)
	}

	signingKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	return signingKeyRing, nil
}

// signFileWithKeyRing signs a file using an unlocked KeyRing.
func signFileWithKeyRing(filePath string, signingKeyRing *crypto.KeyRing) error {
	// Read content of file to sign
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	message := crypto.NewPlainMessage(fileData)
	pgpSignature, err := signingKeyRing.SignDetached(message)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	signPath := filePath + ".asc"
	armor, err := pgpSignature.GetArmored()
	if err != nil {
		return fmt.Errorf("failed to armor signature: %w", err)
	}
	if err := os.WriteFile(signPath, []byte(armor), 0644); err != nil {
		return fmt.Errorf("failed to write signature to file: %w", err)
	}
	return nil
}

// writeHashtoFile writes a hash to a given file.
func writeHashtoFile(fname, name string, hash []byte) error {
	f, err := os.Create(fname)
	if err != nil {
		return fmt.Errorf("failed to write hash to file: %w", err)
	}
	fmt.Fprintf(f, "%x %s\n", hash, name)
	return f.Close()
}

// writeFileHashes computes hashes for an existing file and writes them.
func writeFileHashes(filePath string, writeSha256 bool, writeSha512 bool) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filePath, err)
	}

	defer f.Close()

	// Prepare hashers
	var writers []io.Writer
	s256 := sha256.New()
	s512 := sha512.New()

	if writeSha256 {
		writers = append(writers, s256)
	}
	if writeSha512 {
		writers = append(writers, s512)
	}

	if len(writers) == 0 {
		// both hashes exist already -> write nothing
		return nil
	}

	// Copy file into the selected hashers.
	hasher := io.MultiWriter(writers...)
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("failed to copy file to hashers: %w", err)
	}

	name := filepath.Base(filePath)

	// Write hashes
	if writeSha256 {
		if err := writeHashtoFile(filePath+".sha256", name, s256.Sum(nil)); err != nil {
			return fmt.Errorf("failed to write sha256: %w", err)
		}
	}
	if writeSha512 {
		if err := writeHashtoFile(filePath+".sha512", name, s512.Sum(nil)); err != nil {
			return fmt.Errorf("failed to write sha512: %w", err)
		}
	}
	return nil
}

// signAndHash checks whether a file needs to be signed or hashes and then signs or hashes it
func signAndHash(file string, signingKeyRing *crypto.KeyRing) error {
	// the files to be checked and created
	fileSignature := file + ".asc"
	fileHash256 := file + ".sha256"
	fileHash512 := file + ".sha512"

	// write Signature if it doesn't exist
	if checkFileNotExists(fileSignature) {
		if err := signFileWithKeyRing(file, signingKeyRing); err != nil {
			return fmt.Errorf("failed to sign file: %w", err)
		}
	}

	// write Hashes
	if err := writeFileHashes(file, checkFileNotExists(fileHash256), checkFileNotExists(fileHash512)); err != nil {
		return fmt.Errorf("failed to write Hashes: %w", err)
	}
	return nil
}

// checkFileExists returns whether a file does not exist
func checkFileNotExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return errors.Is(error, os.ErrNotExist)
}

// signAndHashWalk walks from a starting directory and signs and hashes all json files
// except for those given in a list of exceptions
func signAndHashWalk(inputDir string, exceptions []string, privateKeyPath string, privateKeyPassword string) error {
	signKey, err := prepareKeyRing(privateKeyPath, privateKeyPassword)
	if err != nil {
		return fmt.Errorf("failed to unlock privatekey: %w", err)
	}
	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			for _, exception := range exceptions {
				if info.Name() == exception {
					return nil
				}
			}
			return signAndHash(path, signKey)
		}
		return nil
	})
}
