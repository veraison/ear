// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

func TestAppraisal_ok(t *testing.T) {
	// A1         # map(1)
	//    19 03E8 # unsigned(1000)
	//    02      # unsigned(2)
	tv := []byte{0xA1, 0x19, 0x03, 0xE8, 0x02}

	var appraisal Appraisal
	err := cbor.Unmarshal(tv, &appraisal)
	assert.NoError(t, err)

	expectedStatus := TrustTier(2)
	assert.Equal(t, &expectedStatus, appraisal.Status)
}

func TestAppraisalExtensions_SetGetKeyAttestation_ok(t *testing.T) {
	expected := AppraisalExtensions{
		VeraisonKeyAttestation: &map[string]interface{}{
			"akpub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhY8T3U6Vb8B3FP2wLDH7ueLQMb_fSWpbiKCuYnO9xwUSg",
		},
	}

	x, y := new(big.Int), new(big.Int)
	x.SetString("50631180696798613978298281067436158137915100161810154046459014669202204445206", 10)
	y.SetString("27279160910143077479535430864293552757342796444793851632003786495367057249354", 10)

	tv := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	actual := AppraisalExtensions{}

	err := actual.SetKeyAttestation(tv)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)

	pub, err := actual.GetKeyAttestation()
	assert.NoError(t, err)
	assert.Equal(t, tv, pub)
}

func TestAppraisalExtensions_SetKeyAttestation_fail_unsupported_key_type(t *testing.T) {
	tv := "MFkwWwYHKo"

	actual := AppraisalExtensions{}
	err := actual.SetKeyAttestation(tv)
	assert.EqualError(t, err, "unsupported type for public key: string")
}

func TestAppraisalExtensions_GetKeyAttestation_fail_no_claim(t *testing.T) {
	tv := AppraisalExtensions{}

	_, err := tv.GetKeyAttestation()
	assert.EqualError(t, err, `"ear.veraison.key-attestation" claim not found`)
}

func TestAppraisalExtensions_GetKeyAttestation_fail_akpub_missing(t *testing.T) {
	tv := AppraisalExtensions{
		VeraisonKeyAttestation: &map[string]interface{}{},
	}

	_, err := tv.GetKeyAttestation()
	assert.EqualError(t, err, `"akpub" claim not found in "ear.veraison.key-attestation"`)
}

func TestAppraisalExtensions_GetKeyAttestation_fail_akpub_truncated(t *testing.T) {
	tv := AppraisalExtensions{
		VeraisonKeyAttestation: &map[string]interface{}{
			"akpub": "MFkwEwYHKo",
		},
	}

	_, err := tv.GetKeyAttestation()
	assert.EqualError(t, err, `parsing "akpub" failed: asn1: syntax error: data truncated`)
}

func TestAppraisalExtensions_GetKeyAttestation_fail_akpub_not_a_string(t *testing.T) {
	tv := AppraisalExtensions{
		VeraisonKeyAttestation: &map[string]interface{}{
			"akpub": 141245,
		},
	}

	_, err := tv.GetKeyAttestation()
	assert.EqualError(t, err, `"ear.veraison.key-attestation" malformed: "akpub" must be string`)
}

func TestAppraisalExtensions_GetKeyAttestation_fail_akpub_no_b64url(t *testing.T) {
	tv := AppraisalExtensions{
		VeraisonKeyAttestation: &map[string]interface{}{
			"akpub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==",
		},
	}
	_, err := tv.GetKeyAttestation()
	assert.EqualError(t, err, `"ear.veraison.key-attestation" malformed: decoding "akpub": illegal base64 data at input byte 84`)
}
