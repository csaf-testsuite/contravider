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
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// prepareKeyRing unlocks and returns a reusable KeyRing for signing.
func prepareKeyRing(armoredPrivateKeyPath string, passphrase string) (*crypto.Key, error) {
	// read armored private key as bytes from file
	armoredPrivateKeyByte, err := os.ReadFile(armoredPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	privateKey, err := crypto.NewKeyFromArmored(string(armoredPrivateKeyByte))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	if passphrase != "" {
		privateKey, err = privateKey.Unlock([]byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("failed to unlock private key: %w", err)
		}
	}
	return privateKey, nil
}

// signFileWithKey signs a file using an unlocked key.
// func signFileWithKey(filePath string, signingKey *crypto.Key) error {
func signFileWithKey(filePath string, signer crypto.PGPSign) error {
	// Read content of file to sign
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	armored, err := signer.Sign(fileData, crypto.Armor)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	signPath := filePath + ".asc"
	if err := os.WriteFile(signPath, []byte(armored), 0644); err != nil {
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

	if !writeSha256 && !writeSha512 {
		// both hashes exist already -> write nothing
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer f.Close()

	// Prepare hashers
	var hashers []io.Writer
	s256 := sha256.New()
	s512 := sha512.New()

	if writeSha256 {
		hashers = append(hashers, s256)
	}
	if writeSha512 {
		hashers = append(hashers, s512)
	}

	// Copy file into the selected hashers.
	if _, err := io.Copy(io.MultiWriter(hashers...), f); err != nil {
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

// encloseSignFile creates an action that signs a file with a keyring parameter.
func encloseSignFile(signingKey *crypto.Key) (Action, error) {
	pgp := crypto.PGP()
	signer, err := pgp.Sign().SigningKey(signingKey).Detached().New()
	if err != nil {
		return nil, fmt.Errorf("building signer failed: %w", err)
	}
	return func(file string, _ os.FileInfo) error {
		// the files to be checked and created
		fileSignature := file + ".asc"
		// write Signature if it doesn't exist
		if checkFileNotExists(fileSignature) {
			if err := signFileWithKey(file, signer); err != nil {
				return fmt.Errorf("failed to sign file: %w", err)
			}
		}
		return nil
	}, nil
}

// hashFile checks whether a file needs to be hashed and then hashes it.
func hashFile(file string, _ os.FileInfo) error {
	// the files to be checked and created
	fileHash256 := file + ".sha256"
	fileHash512 := file + ".sha512"

	shouldCreate256 := checkFileNotExists(fileHash256)
	shouldCreate512 := checkFileNotExists(fileHash512)

	// write Hashes
	if err := writeFileHashes(file, shouldCreate256, shouldCreate512); err != nil {
		return fmt.Errorf("failed to write Hashes: %w", err)
	}
	return nil
}

// checkFileExists returns whether a file does not exist.
func checkFileNotExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return errors.Is(err, os.ErrNotExist)
}

// writePublicKey writes the public key into the target directory.
func writePublicKey(key *crypto.Key, targetDir string) error {
	asc, err := key.GetArmoredPublicKey()
	if err != nil {
		return fmt.Errorf("cannot get public key: %w", err)
	}
	hexid := key.GetHexKeyID()
	path := path.Join(targetDir, hexid+".asc")
	if err := os.WriteFile(path, []byte(asc), 0666); err != nil {
		return fmt.Errorf("cannot write public key to %q: %w", path, err)
	}
	return nil
}
