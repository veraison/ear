// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// SetKeyAttestation sets the value of `akpub` in the
// "ear_veraison_key_attestation" claim.
// The following key types are currently supported: *rsa.PublicKey,
// *ecdsa.PublicKey, ed25519.PublicKey (not a pointer).
// Unsupported key types result in an error.
func SetKeyAttestation(appraisal *Appraisal, pub any) error {
	switch v := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return fmt.Errorf("unsupported type for public key: %T", v)
	}

	k, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	akpub := base64.RawURLEncoding.EncodeToString(k)

	if appraisal.Extensions == nil {
		appraisal.Extensions = NewExtensions()
	}

	appraisal.Extensions.StringSet(
		"ear_veraison_key_attestation",
		map[string]any{
			"akpub": akpub,
		},
	)

	return nil
}

// GetKeyAttestation returns the decoded public key carried in the
// "ear_veraison_key_attestation" claim.
// The returned key type is one supported by x509.ParsePKIXPublicKey.
func GetKeyAttestation(appraisal *Appraisal) (any, error) {
	if appraisal.Extensions == nil {
		return nil, errors.New("appraisal does not contain extensions")
	}

	extVal, err := appraisal.Extensions.GetStringMap("ear_veraison_key_attestation")
	if err != nil {
		return nil, err
	}

	v, ok := extVal["akpub"]
	if !ok {
		return nil, errors.New(`"akpub" claim not found in "ear_veraison_key_attestation"`)
	}

	akpub, ok := v.(string)
	if !ok {
		return nil, errors.New(`"ear_veraison_key_attestation" malformed: "akpub" must be string`)
	}

	k, err := base64.RawURLEncoding.DecodeString(akpub)
	if err != nil {
		return nil, fmt.Errorf(`"ear_veraison_key_attestation" malformed: decoding "akpub": %w`, err)
	}

	pub, err := x509.ParsePKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf(`parsing "akpub" failed: %w`, err)
	}

	return pub, nil
}
