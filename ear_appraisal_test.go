// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppraisalExtensions_SetGetKeyAttestation_ok(t *testing.T) {
	expected := AppraisalExtensions{
		VeraisonKeyAttestation: &map[string]interface{}{
			"akpub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li_hp_m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q",
		},
	}

	kp, err := ecdsa.GenerateKey(elliptic.P256(), new(zeroSource))
	require.NoError(t, err)
	tv := kp.Public()

	actual := AppraisalExtensions{}

	err = actual.SetKeyAttestation(tv)
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

func TestAppraisalExtensions_SetGetRealmIdentity_ok(t *testing.T) {
	tv := "cd1f0e55-26f9-460d-b9d8-f7fde171787c"

	expected := AppraisalExtensions{
		VeraisonRealmIdentity: &map[string]interface{}{
			"realmID": tv,
		},
	}

	actual := AppraisalExtensions{}

	err := actual.SetRealmIdentity(tv)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)

	pub, err := actual.GetRealmIdentity()
	assert.NoError(t, err)
	assert.Equal(t, tv, pub)
}

func TestAppraisalExtensions_SetRealmIdentity_nok(t *testing.T) {
	tv := "plaintext"
	actual := AppraisalExtensions{}

	err := actual.SetRealmIdentity(tv)
	assert.EqualError(t, err, `"ear.veraison.realm-identity" invalid uuid: invalid UUID length: 9`)
}

func TestAppraisalExtensions_GetRealmIdentity_realmID_missing(t *testing.T) {

	tv := AppraisalExtensions{}
	_, err := tv.GetRealmIdentity()
	assert.EqualError(t, err, `"ear.veraison.realm-identity" claim not found`)

	tv = AppraisalExtensions{
		VeraisonRealmIdentity: &map[string]interface{}{},
	}

	_, err = tv.GetRealmIdentity()
	assert.EqualError(t, err, `"realmID" not found in "veraison.realm-identity"`)
}
