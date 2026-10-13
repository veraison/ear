// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
	"github.com/veraison/eat"
)

var (
	testECDSAPublicKey = `{
"kty": "EC",
"crv": "P-256",
"x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
"y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
}`

	testECDSAPrivateKey = `{
"kty": "EC",
"crv": "P-256",
"x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
"y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
"d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
}`

	testVidBuild     = "rrtrap-v1.0.0"
	testVidDeveloper = "Acme Inc."

	testStatus     = TrustTierAffirming
	testIAT        = int64(1666091373)
	testPolicyID   = "policy://test/01234"
	testVerifierID = VerifierIdentity{
		Build:     testVidBuild,
		Developer: testVidDeveloper,
	}
	testProfile   = EatProfile
	testPolicyIDs = []string{testPolicyID}

	testAttestationResult = AttestationResult{
		IssuedAt:   testIAT,
		VerifierID: &testVerifierID,
		Profile:    testProfile,
		Submods: NewSubmods().AddAppraisal("test", &Appraisal{
			Status:             testStatus,
			AppraisalPolicyIDs: testPolicyIDs,
			VerifierClaims: map[eat.IntOrString]any{
				eat.IntOrStringFromString("foo"): "bar",
				eat.IntOrStringFromString("bar"): "baz",
			},
			AttesterClaims: map[eat.IntOrString]any{
				eat.IntOrStringFromString("k1"): "v1",
				eat.IntOrStringFromString("k2"): "v2",
			},
			Extensions: NewExtensions(),
		}),
		Extensions: NewExtensions(),
	}
)

func TestAttestationResult_round_trip(t *testing.T) {
	testCases := []struct {
		title        string
		result       AttestationResult
		expectedJSON string
	}{
		{
			title: "ok minimal",
			result: AttestationResult{
				Profile:    EatProfile,
				IssuedAt:   1666091373,
				VerifierID: NewVerifierIdentity("test-build", "test-developer"),
				Submods: NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status:     TrustTierAffirming,
						Extensions: NewExtensions(),
					},
				),
				Extensions: NewExtensions(),
			},
			expectedJSON: `{"ear_verifier_id":{"build":"test-build","developer":"test-developer"},"eat_profile":"tag:ietf.org,2026:rats/ear#04","iat":1666091373,"submods":{"test-appraisal":{"ear_status":"affirming"}}}`,
		},
		{
			title: "ok complete",
			result: AttestationResult{
				Profile:    EatProfile,
				IssuedAt:   1666091373,
				Expiry:     Ptr(int64(9999999999)),
				VerifierID: NewVerifierIdentity("test-build", "test-developer"),
				Status:     &TrustTierAffirming,
				RawEvidence: func() *cmw.CMW {
					ret, _ := cmw.NewMonad(
						"application/x-test",
						[]byte{0xde, 0xad, 0xbe, 0xef},
					)
					return ret
				}(),
				Submods: NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status:     TrustTierAffirming,
						Extensions: NewExtensions(),
					},
				),
				Nonce: eat.MustNewNonceFromBytes([]byte{
					0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				}),
				DeviceTopology: NewDeviceTopology().
					Add("test-appraisal", []string{"foo", "bar"}),
				Extensions: NewExtensions(),
			},
			expectedJSON: `{"ear_device_topology":{"test-appraisal":["foo","bar"]},"ear_raw_evidence":["application/x-test","3q2-7w"],"ear_status":"affirming","ear_verifier_id":{"build":"test-build","developer":"test-developer"},"eat_nonce":"3q2-796tvu8","eat_profile":"tag:ietf.org,2026:rats/ear#04","exp":9999999999,"iat":1666091373,"submods":{"test-appraisal":{"ear_status":"affirming"}}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			encodedJSON, err := tc.result.MarshalJSON()
			assert.NoError(t, err)
			assert.JSONEq(t, tc.expectedJSON, string(encodedJSON))

			var decoded AttestationResult
			err = decoded.UnmarshalJSON(encodedJSON)
			assert.NoError(t, err)

			// CMWs do not round trip. On unmarshal, an unexported
			// "format" field is set to the format the CMW was
			// unmarshaled from; when a new CMW is created, it is
			// set to "unknown". CMW does not provided a way to set
			// the field. To get around that, we validate the
			// values manually and then set RawEvidence to nil so
			// we can use assert.EqualValues() to check the rest.
			if tc.result.RawEvidence != nil {
				expectedType, _ := tc.result.RawEvidence.GetMonadType()
				actualType, _ := decoded.RawEvidence.GetMonadType()
				assert.Equal(t, expectedType, actualType)

				expectedValue, _ := tc.result.RawEvidence.GetMonadValue()
				actualValue, _ := decoded.RawEvidence.GetMonadValue()
				assert.Equal(t, expectedValue, actualValue)

				tc.result.RawEvidence = nil
				decoded.RawEvidence = nil
			}

			assert.EqualValues(t, tc.result, decoded)
		})
	}
}

func TestAttestationResult_MarshalJSON_negative(t *testing.T) {
	testCases := []struct {
		title  string
		result AttestationResult
		err    string
	}{
		{
			title:  "empty",
			result: AttestationResult{},
			err:    `missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'`,
		},
		{
			title: "empty submods",
			result: AttestationResult{
				Submods: Submods{},
			},
			err: `missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'`,
		},
		{
			title: "missing mandatory",
			result: AttestationResult{
				Profile: EatProfile,
				Submods: Submods{
					"test": &Submod{&Appraisal{
						Status: TrustTierAffirming,
					}},
				},
			},
			err: `missing mandatory 'iat', 'ear_verifier_id'`,
		},
		{
			title: "unsupported profile",
			result: AttestationResult{
				Profile: eat.MustNewProfile("1.2.3.4.5"),
				Submods: Submods{
					"test": &Submod{&Appraisal{
						Status: TrustTierAffirming,
					}},
				},
			},
			err: `missing mandatory 'iat', 'ear_verifier_id'; invalid value(s) for eat_profile (1.2.3.4.5)`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			_, err := tc.result.MarshalJSON()
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestUnmarshalJSON_fail(t *testing.T) {
	testCases := []struct {
		title string
		ar    string
		err   string
	}{
		{
			title: "unexpected EOF",
			ar:    `{`,
			err:   `unexpected end of JSON input`,
		},
		{
			title: "array",
			ar:    `[]`,
			err:   `json: cannot unmarshal array into Go value of type ear.resultUnmarshalHelper`,
		},
		{
			title: "empty",
			ar:    `{}`,
			err:   `missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			var ar AttestationResult

			err := ar.UnmarshalJSON([]byte(tc.ar))
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestVerify_pass(t *testing.T) {
	testCases := []struct {
		title    string
		token    string
		expected AttestationResult
	}{
		{
			title: "ok",
			token: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg`, // #nosec G101
			expected: AttestationResult{
				IssuedAt:   testIAT,
				VerifierID: &testVerifierID,
				Profile:    testProfile,
				Submods: NewSubmods().AddAppraisal("test", &Appraisal{
					Status:             testStatus,
					AppraisalPolicyIDs: testPolicyIDs,
					VerifierClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("foo"): "bar",
						eat.IntOrStringFromString("bar"): "baz",
					},
					AttesterClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("k1"): "v1",
						eat.IntOrStringFromString("k2"): "v2",
					},
					Extensions: NewExtensions().
						StringSet(
							"ear_veraison_key_attestation",
							map[string]any{
								"akpub": "YWtwdWIK",
							},
						),
				}),
				Extensions: NewExtensions(),
			},
		},
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			ar, err := AttestationResultFromVerifiedJWT([]byte(tc.token), &JWTKeyEntry{jwa.ES256(), k})
			assert.NoError(t, err)
			assert.Equal(t, &tc.expected, ar)
		})
	}
}

func TestVerify_fail(t *testing.T) {
	testCases := []struct {
		title string
		token string
		err   string
	}{
		{
			title: "non-matching alg (HS256)",
			token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.Dv3PqGA2W8anXne0YZs8cvIhQhNF1Su1RS83RPzDVg4OhJFNN1oSF-loDpjfIwPdzCWt0eA6JYxSMqpGiemq-Q`, // #nosec G101
			err:   `protected header "alg" "HS256" does not match verification algorithm "ES256"`,
		},
		{
			title: "alg none",
			token: `eyJhbGciOiJub25lIn0.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.`, // #nosec G101
			err:   `protected header "alg" "none" does not match verification algorithm "ES256"`,
		},
		{
			title: "bad JWT formatting",
			token: `.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.Dv3PqGA2W8anXne0YZs8cvIhQhNF1Su1RS83RPzDVg4OhJFNN1oSF-loDpjfIwPdzCWt0eA6JYxSMqpGiemq-Q`, // #nosec G101
			err:   `failed to parse token: unknown payload type (payload is not JWT?)`,
		},
		{
			title: "empty attestation results",
			token: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.9Tvx3hVBNfkmVXTndrVfv9ZeNJgX59w0JpR2vyjUn8lGxL8VT7OggUeYSYFnxrouSi2TusNh61z8rLdOqxGA-A`, // #nosec G101
			err:   `missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'`,
		},
		{
			title: "JWT with trailing rubbish",
			token: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmdpdGh1Yi5jb20sMjAyMzp2ZXJhaXNvbi9lYXIiLCJpYXQiOjEuNjY2MDkxMzczZSswOSwianRpIjoiMTY1Zjg0YzY3YzE0ZTEwZDFlNGI0MzM0MDgzY2IyYTIxZDI2YmYxN2FhNjBkNWU5ZGE5ZDhmNzE3NmFjNWI2MyIsIm5iZiI6MTY3NjQ3MjcwOSwic3VibW9kcyI6eyJ0ZXN0Ijp7ImVhci5hcHByYWlzYWwtcG9saWN5LWlkIjoicG9saWN5Oi8vdGVzdC8wMTIzNCIsImVhci5zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXIudmVyYWlzb24uYW5ub3RhdGVkLWV2aWRlbmNlIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhci52ZXJhaXNvbi5wb2xpY3ktY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fX19.LunlKAnUiVHZxIUr7jNnrwFlRtd7t6f6W1rzIFgcWFLdtJELKIVGkPVV5PriHh8T0uLLIEJafwvi6hmIr27aDw.trailing-rubbish`, // #nosec G101
			err:   `failed to parse token: unknown payload type (payload is not JWT?)`,
		},
		{
			title: "JWT with invalid profile",
			token: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoiaW52YWxpZC1wcm9maWxlIiwiaWF0IjoxNjY2MDkxMzczLCJzdWJtb2RzIjp7InRlc3QiOnsiZWFyX2FwcHJhaXNhbF9wb2xpY3lfaWRzIjpbInBvbGljeTovL3Rlc3QvMDEyMzQiXSwiZWFyX2F0dGVzdGVyX2NsYWltcyI6eyJrMSI6InYxIiwiazIiOiJ2MiJ9LCJlYXJfc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWFyX3ZlcmFpc29uX2tleV9hdHRlc3RhdGlvbiI6eyJha3B1YiI6IllXdHdkV0lLIn0sImVhcl92ZXJpZmllcl9jbGFpbXMiOnsiYmFyIjoiYmF6IiwiZm9vIjoiYmFyIn19fX0.HXq08DW-vCLE3bRRxCeO3U19RQ0xIx82OBK1_gNW4SOCeOPIBG7Jew1qsXxsiYswxSiH0TAprwsmJqUcb3aRNQ`, // #nosec G101
			err:   `profile string must be an absolute URL or an ASN.1 OID`,
		},
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			_, err := AttestationResultFromVerifiedJWT([]byte(tc.token), &JWTKeyEntry{jwa.ES256(), k})
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestSignJWT(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	ar := AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   1666091373,
		Expiry:     Ptr(int64(9999999999)),
		VerifierID: NewVerifierIdentity("test-build", "test-developer"),
		Status:     &TrustTierAffirming,
		RawEvidence: func() *cmw.CMW {
			ret, _ := cmw.NewMonad(
				"application/x-test",
				[]byte{0xde, 0xad, 0xbe, 0xef},
			)
			return ret
		}(),
		Submods: NewSubmods().AddAppraisal(
			"test-appraisal",
			&Appraisal{
				Profile: eat.MustNewProfile("http://test-profile"),
				Status:  TrustTierAffirming,
				TrustVector: &TrustVector{
					InstanceIdentity: TrustworthyInstanceClaim,
				},
				AppraisalPolicyIDs: []string{"test-policy"},
				Nonce: eat.MustNewNonceFromBytes([]byte{
					0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				}),
				AttesterClaims: map[eat.IntOrString]any{
					eat.IntOrStringFromString("ac-1"): "foo",
				},
				VerifierClaims: map[eat.IntOrString]any{
					eat.IntOrStringFromInt(1): "foo",
				},
				Extensions: NewExtensions().StringSet(
					"foo",
					map[string]any{
						"bar": true,
					},
				),
			},
		),
		Nonce: eat.MustNewNonceFromBytes([]byte{
			0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		}),
		DeviceTopology: NewDeviceTopology().
			Add("test-appraisal", []string{"foo", "bar"}),
		Extensions: NewExtensions().IntSet(1, true),
	}

	signed, err := ar.SignJWT(jwa.ES256(), sigK)
	assert.NoError(t, err)

	_, err = AttestationResultFromVerifiedJWT(signed, &JWTKeyEntry{jwa.ES256(), sigK})
	assert.NoError(t, err)
}

func TestSignJWT_fail(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	// an empty AR is not a valid AR4SI payload
	var ar AttestationResult

	_, err = ar.SignJWT(jwa.ES256(), sigK)
	assert.EqualError(t, err, `missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'`)

	ar = AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   1666091373,
		VerifierID: NewVerifierIdentity("test-build", "test-developer"),
		Submods: NewSubmods().AddAppraisal(
			"test-appraisal",
			&Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions(),
			},
		),
		Extensions: NewExtensions().
			// conflicts with IssuedAt
			StringSet("iat", "foo"),
	}

	_, err = ar.SignJWT(jwa.ES256(), sigK)
	assert.EqualError(t, err, "extensions conflict with standard claims")
}

func TestRoundTrip_pass(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	token, err := testAttestationResult.SignJWT(jwa.ES256(), sigK)
	assert.NoError(t, err)

	fmt.Println(string(token))

	vfyK, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	actual, err := AttestationResultFromVerifiedJWT(token, &JWTKeyEntry{jwa.ES256(), vfyK})
	assert.NoError(t, err)

	assert.Equal(t, &testAttestationResult, actual)
}

func TestRoundTrip_tampering(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	token, err := testAttestationResult.SignJWT(jwa.ES256(), sigK)
	assert.NoError(t, err)

	vfyK, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	// Tamper with the signature.
	// Note that since ES256 is randomized, this could result in different kinds
	// of verification errors. Therefore we have to use ErrorContains rather
	// than EqualError.
	if token[len(token)-1] == 'A' {
		token[len(token)-1] = 'd'
	} else {
		token[len(token)-1] = 'A'
	}

	_, err = AttestationResultFromVerifiedJWT(token, &JWTKeyEntry{jwa.ES256(), vfyK})
	assert.ErrorContains(t, err, "failed to verify signature")
}

func TestUpdateStatusFromTrustVector(t *testing.T) {
	ar := NewAttestationResultWithAppraisal("test", "test", "test")

	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierNone, ar.Submods["test"].Appraisal().Status)

	ar.Submods["test"].Appraisal().TrustVector.Configuration = ApprovedConfigClaim
	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierAffirming, ar.Submods["test"].Appraisal().Status)

	ar.Submods["test"].Appraisal().Status = TrustTierWarning
	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierWarning, ar.Submods["test"].Appraisal().Status)

	ar.Submods["test"].Appraisal().TrustVector.Configuration = UnsupportableConfigClaim
	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierContraindicated, ar.Submods["test"].Appraisal().Status)
	assert.Equal(t, TrustTierContraindicated, *ar.Status)

	ar = NewAttestationResult("test", "test")
	ar.Submods.AddAttestationResult("test", &AttestationResult{
		Status:     &TrustTierWarning,
		Profile:    EatProfile,
		IssuedAt:   1666091373,
		VerifierID: NewVerifierIdentity("test-build", "test-developer"),
		Submods: NewSubmods().AddAppraisal(
			"test-appraisal",
			&Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions(),
			},
		),
		Extensions: NewExtensions(),
	})
	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierWarning, *ar.Status)

	jwtBytes := []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg") // #nosec G101
	ar = NewAttestationResult("test", "test")
	ar.Submods.AddJWT("test", jwtBytes)

	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierIncomplete, *ar.Status)

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	ar.Status = nil
	ar.UpdateStatusFromSubmods(&JWTKeyEntry{jwa.ES256(), k})
	assert.Equal(t, TrustTierAffirming, *ar.Status)
}

func TestNewAttestationResult(t *testing.T) {
	ar := NewAttestationResult("testBuild", "testDev")

	assert.Equal(t, "testBuild", ar.VerifierID.Build)
	assert.Equal(t, "testDev", ar.VerifierID.Developer)
}

func TestNewAttestationResultWithAppraisal(t *testing.T) {
	ar := NewAttestationResultWithAppraisal("test", "testBuild", "testDev")

	_, err := ar.MarshalJSON()
	assert.NoError(t, err)
}

func TestAttestationResultFromUnverifiedJWT(t *testing.T) {
	token := `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg` // #nosec G101

	_, err := AttestationResultFromUnverifiedJWT([]byte(token))
	assert.NoError(t, err)

	_, err = AttestationResultFromUnverifiedJWT([]byte("@@@"))
	assert.ErrorContains(t, err, "failed to parse token")
}

func TestAttestationResultFromNestedToken(t *testing.T) {
	testCases := []struct {
		title    string
		token    eat.NestedToken
		expected AttestationResult
		err      string
	}{
		{
			title: "ok",
			token: eat.NestedToken{
				Type: eat.NestedTokenJWT,
				Data: []byte(`"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg"`), // #nosec G101
			},
			expected: AttestationResult{
				Profile:    EatProfile,
				IssuedAt:   1666091373,
				VerifierID: NewVerifierIdentity("rrtrap-v1.0.0", "Acme Inc."),
				Submods: NewSubmods().AddAppraisal("test", &Appraisal{
					Status:             TrustTierAffirming,
					AppraisalPolicyIDs: []string{"policy://test/01234"},
					AttesterClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("k1"): "v1",
						eat.IntOrStringFromString("k2"): "v2",
					},
					VerifierClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("foo"): "bar",
						eat.IntOrStringFromString("bar"): "baz",
					},
					Extensions: NewExtensions().StringSet(
						"ear_veraison_key_attestation",
						map[string]any{
							"akpub": "YWtwdWIK",
						},
					),
				}),
				Extensions: NewExtensions(),
			},
		},
		{
			title: "err bad JWT",
			token: eat.NestedToken{
				Type: eat.NestedTokenJWT,
				Data: []byte(`"aaaaaaaa.bbbbbbbbbbbbbbbb.cccccccc"`),
			},
			err: "failed to parse token",
		},
		{
			title: "err unsupported type",
			token: eat.NestedToken{
				Type: eat.NestedTokenDigest,
				Data: []byte(`[-16,"3q2-7w"]`),
			},
			err: "cannot create AttestationResult from DIGEST",
		},
		{
			title: "err CBOR",
			token: eat.NestedToken{
				Type: eat.NestedTokenCBOR,
				Data: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			err: "CBOR encoding not supported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := AttestationResultFromNestedToken(&tc.token)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, &tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestAttestationResultFromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected AttestationResult
		err      string
	}{
		{
			title:    "ok AttestationResult",
			input:    testAttestationResult,
			expected: testAttestationResult,
		},
		{
			title:    "ok AttestationResult pointer",
			input:    &testAttestationResult,
			expected: testAttestationResult,
		},
		{
			title: "ok NestedToken",
			input: eat.NestedToken{
				Type: eat.NestedTokenJWT,
				Data: []byte(`"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg"`), // #nosec G101
			},
			expected: AttestationResult{
				Profile:    EatProfile,
				IssuedAt:   1666091373,
				VerifierID: NewVerifierIdentity("rrtrap-v1.0.0", "Acme Inc."),
				Submods: NewSubmods().AddAppraisal("test", &Appraisal{
					Status:             TrustTierAffirming,
					AppraisalPolicyIDs: []string{"policy://test/01234"},
					AttesterClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("k1"): "v1",
						eat.IntOrStringFromString("k2"): "v2",
					},
					VerifierClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("foo"): "bar",
						eat.IntOrStringFromString("bar"): "baz",
					},
					Extensions: NewExtensions().StringSet(
						"ear_veraison_key_attestation",
						map[string]any{
							"akpub": "YWtwdWIK",
						},
					),
				}),
				Extensions: NewExtensions(),
			},
		},
		{
			title: "ok NestedToken pointer",
			input: &eat.NestedToken{
				Type: eat.NestedTokenJWT,
				Data: []byte(`"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg"`), // #nosec G101
			},
			expected: AttestationResult{
				Profile:    EatProfile,
				IssuedAt:   1666091373,
				VerifierID: NewVerifierIdentity("rrtrap-v1.0.0", "Acme Inc."),
				Submods: NewSubmods().AddAppraisal("test", &Appraisal{
					Status:             TrustTierAffirming,
					AppraisalPolicyIDs: []string{"policy://test/01234"},
					AttesterClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("k1"): "v1",
						eat.IntOrStringFromString("k2"): "v2",
					},
					VerifierClaims: map[eat.IntOrString]any{
						eat.IntOrStringFromString("foo"): "bar",
						eat.IntOrStringFromString("bar"): "baz",
					},
					Extensions: NewExtensions().StringSet(
						"ear_veraison_key_attestation",
						map[string]any{
							"akpub": "YWtwdWIK",
						},
					),
				}),
				Extensions: NewExtensions(),
			},
		},
		{
			title: "ok map[string]any",
			input: map[string]any{
				"eat_profile":     "tag:ietf.org,2026:rats/ear#04",
				"iat":             1666091373,
				"exp":             Ptr(int64(9999999999)),
				"ear_verifier_id": NewVerifierIdentity("test-build", "test-developer"),
				"ear_status":      &TrustTierAffirming,
				"ear_raw_evidence": func() *cmw.CMW {
					ret, _ := cmw.NewMonad(
						"application/x-test",
						[]byte{0xde, 0xad, 0xbe, 0xef},
					)
					return ret
				}(),
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status:     TrustTierAffirming,
						Extensions: NewExtensions(),
					},
				),
				"eat_nonce": eat.MustNewNonceFromBytes([]byte{
					0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				}),
				"ear_device_topology": NewDeviceTopology().
					Add("test-appraisal", []string{"foo", "bar"}),
				"foo": "bar",
			},
			expected: AttestationResult{
				Profile:    EatProfile,
				IssuedAt:   1666091373,
				Expiry:     Ptr(int64(9999999999)),
				VerifierID: NewVerifierIdentity("test-build", "test-developer"),
				Status:     &TrustTierAffirming,
				RawEvidence: func() *cmw.CMW {
					ret, _ := cmw.NewMonad(
						"application/x-test",
						[]byte{0xde, 0xad, 0xbe, 0xef},
					)
					return ret
				}(),
				Submods: NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status:     TrustTierAffirming,
						Extensions: NewExtensions(),
					},
				),
				Nonce: eat.MustNewNonceFromBytes([]byte{
					0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				}),
				DeviceTopology: NewDeviceTopology().
					Add("test-appraisal", []string{"foo", "bar"}),
				Extensions: NewExtensions().StringSet("foo", "bar"),
			},
		},
		{
			title: "err bad type",
			input: 1,
			err:   "cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err missing mandatory",
			input: map[string]any{},
			err:   "missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'",
		},
		{
			title: "err bad iat",
			input: map[string]any{
				"iat": "foo",
			},
			err: `iat: strconv.Atoi: parsing "foo": invalid syntax`,
		},
		{
			title: "err bad profile",
			input: map[string]any{
				"eat_profile":     1,
				"iat":             1666091373,
				"ear_verifier_id": NewVerifierIdentity("test-build", "test-developer"),
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: "eat_profile: expected a string, got int",
		},
		{
			title: "err bad verifier ID",
			input: map[string]any{
				"eat_profile":     "tag:ietf.org,2026:rats/ear#04",
				"iat":             1666091373,
				"ear_verifier_id": 1,
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: "ear_verifier_id: cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err bad submods",
			input: map[string]any{
				"eat_profile":     "tag:ietf.org,2026:rats/ear#04",
				"iat":             1666091373,
				"ear_verifier_id": NewVerifierIdentity("test-build", "test-developer"),
				"submods":         1,
			},
			err: "submods: unexpected Submods type int",
		},
		{
			title: "err bad status",
			input: map[string]any{
				"eat_profile":     "tag:ietf.org,2026:rats/ear#04",
				"ear_status":      -1,
				"iat":             1666091373,
				"ear_verifier_id": NewVerifierIdentity("test-build", "test-developer"),
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: "ear_status: not a valid TrustTier value: -1",
		},
		{
			title: "err bad exp",
			input: map[string]any{
				"eat_profile":     "tag:ietf.org,2026:rats/ear#04",
				"iat":             1666091373,
				"exp":             "foo",
				"ear_verifier_id": NewVerifierIdentity("test-build", "test-developer"),
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: `exp: strconv.Atoi: parsing "foo": invalid syntax`,
		},
		{
			title: "err bad raw evidence",
			input: map[string]any{
				"eat_profile":      "tag:ietf.org,2026:rats/ear#04",
				"iat":              1666091373,
				"ear_verifier_id":  NewVerifierIdentity("test-build", "test-developer"),
				"ear_raw_evidence": 1,
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: "ear_raw_evidence: decoding CMW record: want JSON object or JSON array start symbols, got: 0x31",
		},
		{
			title: "err bad nonce",
			input: map[string]any{
				"eat_profile":     "tag:ietf.org,2026:rats/ear#04",
				"iat":             1666091373,
				"ear_verifier_id": NewVerifierIdentity("test-build", "test-developer"),
				"eat_nonce":       1,
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: "eat_nonce: cannot convert 1 (int) to Nonce",
		},
		{
			title: "err bad device topology",
			input: map[string]any{
				"eat_profile":         "tag:ietf.org,2026:rats/ear#04",
				"iat":                 1666091373,
				"ear_verifier_id":     NewVerifierIdentity("test-build", "test-developer"),
				"ear_device_topology": 1,
				"submods": NewSubmods().AddAppraisal(
					"test-appraisal",
					&Appraisal{
						Status: TrustTierAffirming,
					},
				),
			},
			err: "ear_device_topology: invalid type int for DeviceTopology",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := AttestationResultFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, &tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestAttestationResult_bad_topology(t *testing.T) {
	ar := AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   1666091373,
		VerifierID: NewVerifierIdentity("test-build", "test-developer"),
		DeviceTopology: NewDeviceTopology().
			Add("test-appraisal", []string{"foo"}).
			Add("nihil", []string{"foo"}),
		Submods: NewSubmods().AddAppraisal(
			"test-appraisal",
			&Appraisal{
				Status: TrustTierAffirming,
			},
		),
	}

	err := ar.Validate()
	assert.ErrorContains(t, err, "ear_device_topology entries not in submods: nihil")
}
