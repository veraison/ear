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
	"github.com/veraison/eat"
	"github.com/veraison/swid"
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

func TestAppraisalExtensions_TEEPClaims_ok(t *testing.T) {
	// A1                                      # map(1)
	//    19 FDE8                              # unsigned(65000)
	//    A6                                   # map(6)
	//       0A                                # unsigned(10)
	//       48                                # bytes(8)
	//          948F8860D13A463E               # "\x94\x8F\x88`\xD1:F>"
	//       19 0100                           # unsigned(256)
	//       50                                # bytes(16)
	//          0198F50A4FF6C05861C8860D13A638EA # "\u0001\x98\xF5\nO\xF6\xC0XaȆ\r\u0013\xA68\xEA"
	//       19 0102                           # unsigned(258)
	//       43                                # bytes(3)
	//          064242                         # "\u0006BB"
	//       19 0103                           # unsigned(259)
	//       50                                # bytes(16)
	//          EE80F5A66C1FB9742999A8FDAB930893 # "\xEE\x80\xF5\xA6l\u001F\xB9t)\x99\xA8\xFD\xAB\x93\b\x93"
	//       19 0104                           # unsigned(260)
	//       82                                # array(2)
	//          65                             # text(5)
	//             312E322E35                  # "1.2.5"
	//          19 4000                        # unsigned(16384)
	//       19 0109                           # unsigned(265)
	//       74                                # text(20)
	//          75726E3A696574663A7266633A72666358585858 # "urn:ietf:rfc:rfcXXXX"

	expected := []byte{
		0xA1, 0x19, 0xFD, 0xE8, 0xA6, 0x0A, 0x48, 0x94,
		0x8F, 0x88, 0x60, 0xD1, 0x3A, 0x46, 0x3E, 0x19,
		0x01, 0x00, 0x50, 0x01, 0x98, 0xF5, 0x0A, 0x4F,
		0xF6, 0xC0, 0x58, 0x61, 0xC8, 0x86, 0x0D, 0x13,
		0xA6, 0x38, 0xEA, 0x19, 0x01, 0x02, 0x43, 0x06,
		0x42, 0x42, 0x19, 0x01, 0x03, 0x50, 0xEE, 0x80,
		0xF5, 0xA6, 0x6C, 0x1F, 0xB9, 0x74, 0x29, 0x99,
		0xA8, 0xFD, 0xAB, 0x93, 0x08, 0x93, 0x19, 0x01,
		0x04, 0x82, 0x65, 0x31, 0x2E, 0x32, 0x2E, 0x35,
		0x19, 0x40, 0x00, 0x19, 0x01, 0x09, 0x74, 0x75,
		0x72, 0x6E, 0x3A, 0x69, 0x65, 0x74, 0x66, 0x3A,
		0x72, 0x66, 0x63, 0x3A, 0x72, 0x66, 0x63, 0x58,
		0x58, 0x58, 0x58,
	}

	testNonce := eat.Nonce{}
	assert.Nil(t, testNonce.UnmarshalCBOR([]byte{0x48, 0x94, 0x8F, 0x88, 0x60, 0xD1, 0x3A, 0x46, 0x3E}))
	testProfile := eat.Profile{}
	testProfile.Set("urn:ietf:rfc:rfcXXXX")
	var testVersionScheme swid.VersionScheme
	testVersionScheme.SetCode(swid.VersionSchemeSemVer)

	tv := AppraisalExtensions{
		EatClaimsSet: &eat.Eat{
			Nonce: &testNonce,
			UEID:  &eat.UEID{0x01, 0x98, 0xF5, 0x0A, 0x4F, 0xF6, 0xC0, 0x58, 0x61, 0xC8, 0x86, 0x0D, 0x13, 0xA6, 0x38, 0xEA},
			OemID: &[]byte{0x06, 0x42, 0x42},
			HardwareModel: &[]byte{
				0xEE, 0x80, 0xF5, 0xA6, 0x6C, 0x1F, 0xB9, 0x74,
				0x29, 0x99, 0xA8, 0xFD, 0xAB, 0x93, 0x08, 0x93,
			},
			HardwareVersion: &eat.Version{
				Version: "1.2.5",
				Scheme:  &testVersionScheme,
			},
			Profile: &testProfile,
		},
	}

	data, err := cbor.Marshal(tv)
	assert.NoError(t, err)
	assert.Equal(t, expected, data)
}
