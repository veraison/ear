// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SetGetKeyAttestation_ok(t *testing.T) {
	extMap := map[string]any{
		"akpub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhY8T3U6Vb8B3FP2wLDH7ueLQMb_fSWpbiKCuYnO9xwUSg",
	}

	der, err := base64.RawURLEncoding.DecodeString(extMap["akpub"].(string))
	require.NoError(t, err)

	tv, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)

	appraisal := NewAppraisal()

	err = SetKeyAttestation(appraisal, tv)
	assert.NoError(t, err)

	pub, err := GetKeyAttestation(appraisal)
	assert.NoError(t, err)
	assert.Equal(t, tv, pub)
}

func Test_SetKeyAttestation_fail_unsupported_key_type(t *testing.T) {
	err := SetKeyAttestation(NewAppraisal(), "MFkwWwYHKo")
	assert.EqualError(t, err, "unsupported type for public key: string")
}

func Test_GetKeyAttestation_fail_no_claim(t *testing.T) {
	_, err := GetKeyAttestation(NewAppraisal())
	assert.EqualError(t, err, `extension "ear_veraison_key_attestation" not found`)

	_, err = GetKeyAttestation(&Appraisal{})
	assert.EqualError(t, err, "appraisal does not contain extensions")
}

func Test_GetKeyAttestation_fail_akpub_missing(t *testing.T) {
	appraisal := NewAppraisal()
	appraisal.Extensions.StringSet("ear_veraison_key_attestation", map[string]any{})

	_, err := GetKeyAttestation(appraisal)
	assert.EqualError(t, err, `"akpub" claim not found in "ear_veraison_key_attestation"`)
}

func Test_GetKeyAttestation_fail_akpub_truncated(t *testing.T) {
	appraisal := NewAppraisal()
	appraisal.Extensions.StringSet(
		"ear_veraison_key_attestation",
		map[string]any{
			"akpub": "MFkwEwYHKo",
		},
	)

	_, err := GetKeyAttestation(appraisal)
	assert.EqualError(t, err, `parsing "akpub" failed: asn1: syntax error: data truncated`)
}

func TestAppraisalExtensions_GetKeyAttestation_fail_akpub_not_a_string(t *testing.T) {
	appraisal := NewAppraisal()
	appraisal.Extensions.StringSet(
		"ear_veraison_key_attestation",
		map[string]any{
			"akpub": 141245,
		},
	)

	_, err := GetKeyAttestation(appraisal)
	assert.EqualError(t, err, `"ear_veraison_key_attestation" malformed: "akpub" must be string`)
}

func TestAppraisalExtensions_GetKeyAttestation_fail_akpub_no_b64url(t *testing.T) {
	appraisal := NewAppraisal()
	appraisal.Extensions.StringSet(
		"ear_veraison_key_attestation",
		map[string]any{
			"akpub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==",
		},
	)

	_, err := GetKeyAttestation(appraisal)
	assert.EqualError(t, err, `"ear_veraison_key_attestation" malformed: decoding "akpub": illegal base64 data at input byte 84`)
}
