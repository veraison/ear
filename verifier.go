// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
)

// VerifierIdentity is the verifier software identification as defined by AR4SI:
//
//	https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-03#section-2.2.2
type VerifierIdentity struct {
	// Build uniquely identifies the software build running the verifier.
	Build *string `cbor:"0,keyasint,omitempty" json:"build"`
	// Developer uniquely identifies the organizational unit responsible
	// for this build.
	Developer *string `cbor:"1,keyasint,omitempty" json:"developer"`
}

func ToVerifierIdentity(v interface{}) (*VerifierIdentity, error) {
	var verifierID VerifierIdentity

	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, errors.New("not a JSON object")
	}

	err := populateStructFromMap(&verifierID, m, "json",
		map[string]parser{}, stringPtrParser, false)

	return &verifierID, err
}
