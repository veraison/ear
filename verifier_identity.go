// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"

	"github.com/veraison/eat"
)

// VerifierIdentity is the verifier software identification as defined by AR4SI:
//
//	https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-03#section-2.2.2
type VerifierIdentity struct {
	// Developer uniquely identifies the organizational unit responsible
	// for this build.
	Developer string `cbor:"0,keyasint" json:"developer"`
	// Build uniquely identifies the software build running the verifier.
	Build string `cbor:"1,keyasint" json:"build"`
}

// NewVerifierIdentity returns a pointer to a new NewVerifierIdentity
// with the provided build and developer values.
func NewVerifierIdentity(build, developer string) *VerifierIdentity {
	return &VerifierIdentity{
		Developer: developer,
		Build:     build,
	}
}

// VerifierIdentityFromAny returns a pointer to a VerifierIdentity obtained
// from the provided input. If the input is already a VerifierIdentity, pointer
// to the same identity is returned, otherwise the input must be a map with
// "build" and "developer" keys, and a new VerifierIdentity will be constructed
// from it.
func VerifierIdentityFromAny(value any) (*VerifierIdentity, error) {
	switch t := value.(type) {
	case VerifierIdentity:
		return &t, nil
	case *VerifierIdentity:
		return t, nil
	}

	var verifierID VerifierIdentity

	claims, err := eat.IntOrStringMapFromAny(value)
	if err != nil {
		return nil, err
	}

	for key, value := range claims {
		switch key {
		case eat.IntOrStringFromString("developer"):
			developer, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("developer: expected string, got %T", value)
			}

			verifierID.Developer = developer
		case eat.IntOrStringFromString("build"):
			build, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("build: expected string, got %T", value)
			}

			verifierID.Build = build
		default:
			return nil, fmt.Errorf("unexpected VerifierIdentity field: %s", key.String())
		}
	}

	return &verifierID, nil
}
