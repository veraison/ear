// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/ecdsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
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

	testECDSAPublicKeyOther = `{
"kty": "EC",
"crv": "P-256",
"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
"kid": "1"
}`
	testCWT = []byte{
		0xd8, 0x3d, //                                     tag(61) [CWT]
		0xd2,       //                                     . tag(18) [cose-sign1]
		0x84,       //                                     . . array(4) [COSE_Sign1]
		0x43,       //                                     . . . [0]bstr(3) [protected-header]
		0xa1,       //                                     . . . . map(1) [header_map]
		0x01,       //                                     . . . . . key: 1 [alg]
		0x26,       //                                     . . . . . value: -7 [ES256]
		0xa0,       //                                     . . . [1]map(0) [unprotected-header]
		0x58, 0x85, //                                     . . . [2]bstr(133) [payload]
		0xa4,                         //                   . . . . map(4) [AttestationResult]
		0x06,                         //                   . . . . . key: 6 [iat]
		0x1a, 0x63, 0x4e, 0x89, 0x6d, //                   . . . . . value: 1666091373
		0x19, 0x01, 0x09, //                            // . . . . . key: 265 [eat_profile]
		0x78, 0x1d, //                                  // . . . . . value: tstr(29)
		0x74, 0x61, 0x67, 0x3a, 0x69, 0x65, 0x74, 0x66, // . . . . . . "tag:ietf"
		0x2e, 0x6f, 0x72, 0x67, 0x2c, 0x32, 0x30, 0x32, // . . . . . . ".org,202"
		0x36, 0x3a, 0x72, 0x61, 0x74, 0x73, 0x2f, 0x65, // . . . . . . "6:rats/e"
		0x61, 0x72, 0x23, 0x30, 0x34, //                   . . . . . . "ar#04"
		0x19, 0x01, 0x0a, //                               . . . . . key: 266 [submods]
		0xa1,                   //                         . . . . . value: map(1) [Submods]
		0x64,                   //                         . . . . . . key: tstr(4)
		0x74, 0x65, 0x73, 0x74, //                         . . . . . . . "test"
		0xa2,             //                               . . . . . . value: map(2) [Appraisal]
		0x19, 0x03, 0xe8, //                               . . . . . . . key: 1000 [ear_status]
		0x02,             //                               . . . . . . . value: 2 [affirming]
		0x19, 0x03, 0xeb, //                               . . . . . . . key: 1003 [ear_appraisal_policy]
		0x81,       //                                     . . . . . . . value: array(1)
		0x78, 0x2a, //                                     . . . . . . . . [0]tstr(42)
		0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, // . . . . . . . . . "https://"
		0x76, 0x65, 0x72, 0x61, 0x69, 0x73, 0x6f, 0x6e, // . . . . . . . . . "veraison"
		0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // . . . . . . . . . ".example"
		0x2f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2f, // . . . . . . . . . "/policy/"
		0x31, 0x2f, 0x36, 0x30, 0x61, 0x30, 0x30, 0x36, // . . . . . . . . . "1/60a006"
		0x38, 0x64, //                                     . . . . . . . . . "8d"
		0x19, 0x03, 0xec, //                               . . . . . key: 1004 [ear_verifier_id]
		0xa2,                                           // . . . . . value: map(2) [VerifierIdentity]
		0x00,                                           // . . . . . . key: 0 [developer]
		0x69,                                           // . . . . . . value: tstr(9)
		0x41, 0x63, 0x6d, 0x65, 0x20, 0x49, 0x6e, 0x63, // . . . . . . . "Acme Inc"
		0x2e,                                           // . . . . . . . "."
		0x01,                                           // . . . . . . key: 1 [build]
		0x6d,                                           // . . . . . . value: tstr(13)
		0x72, 0x72, 0x74, 0x72, 0x61, 0x70, 0x2d, 0x76, // . . . . . . . "rrtrap-v"
		0x31, 0x2e, 0x30, 0x2e, 0x30, //                // . . . . . . . "1.0.0"
		0x58, 0x40, //                                     . . . [3]bstr(64) [signature]
		0x86, 0x65, 0x9a, 0xe4, 0x50, 0x4f, 0xf9, 0xc6,
		0x2e, 0xfd, 0x54, 0x31, 0x44, 0x5b, 0x65, 0x1e,
		0x71, 0x21, 0x08, 0xc5, 0x15, 0x76, 0xf4, 0xef,
		0x06, 0xa5, 0x1b, 0xf3, 0xfe, 0x17, 0x69, 0x30,
		0xe2, 0xfb, 0x26, 0x17, 0x50, 0xe6, 0x3b, 0xe1,
		0x39, 0x9a, 0x55, 0x87, 0x51, 0x46, 0x2f, 0x98,
		0x8d, 0xc0, 0x02, 0x47, 0xe4, 0x34, 0xd0, 0xcd,
		0xca, 0x95, 0x23, 0x4f, 0xcf, 0x99, 0xf2, 0x95,
	}

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
		expectedCBOR []byte
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
			expectedCBOR: []byte{
				0xa4,                         //                   map(4)
				0x06,                         //                   . key: 6 [iat]
				0x1a, 0x63, 0x4e, 0x89, 0x6d, //                   . value: 1666091373
				0x19, 0x01, 0x09, //                            // . key: 265 [eat_profile]
				0x78, 0x1d, //                                  // . value: tstr(29)
				0x74, 0x61, 0x67, 0x3a, 0x69, 0x65, 0x74, 0x66, // . . "tag:ietf"
				0x2e, 0x6f, 0x72, 0x67, 0x2c, 0x32, 0x30, 0x32, // . . ".org,202"
				0x36, 0x3a, 0x72, 0x61, 0x74, 0x73, 0x2f, 0x65, // . . "6:rats/e"
				0x61, 0x72, 0x23, 0x30, 0x34, //                   . . "ar#04"
				0x19, 0x01, 0x0a, //                               . key: 266 [submods]
				0xa1,                                           // . value: map(1) [Submods]
				0x6e,                                           // . . key: tstr(15)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x70, 0x70, // . . . "test-app"
				0x72, 0x61, 0x69, 0x73, 0x61, 0x6c, //             . . . "raisal"
				0xa1,             //                               . . value: map(1) [Appraisal]
				0x19, 0x03, 0xe8, //                               . . . key: 1000 [ear_status]
				0x02,             //                               . . . value: 2 [affirming]
				0x19, 0x03, 0xec, //                               . . key: 1004 [ear_verifier_id]
				0xa2,                                           // . . value: map(2) [VerifierIdentity]
				0x00,                                           // . . key: 0 [developer]
				0x6e,                                           // . . value: tstr(14)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x65, 0x76, // . . . "test-dev"
				0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, //             . . . "eloper"
				0x01,                                           // . . key: 1 [build]
				0x6a,                                           // . . value: tstr(10)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x62, 0x75, 0x69, // . . . "test-bui"
				0x6c, 0x64, //                                     . . . "ld"
			},
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
			expectedCBOR: []byte{
				0xa8,                                           // map(4)
				0x04,                                           // . key: 4 [exp]
				0x1b,                                           // . value: uint(8)
				0x00, 0x00, 0x00, 0x02, 0x54, 0x0b, 0xe3, 0xff, // . . 9999999999
				0x06,                         //                   . key: 6 [iat]
				0x1a, 0x63, 0x4e, 0x89, 0x6d, //                   . value: 1666091373
				0x0a, //                                           . key: 10 [nonce]
				0x48, //                                           . value: bstr(8)
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				0x19, 0x01, 0x09, //                            // . key: 265 [eat_profile]
				0x78, 0x1d, //                                  // . value: tstr(29)
				0x74, 0x61, 0x67, 0x3a, 0x69, 0x65, 0x74, 0x66, // . . "tag:ietf"
				0x2e, 0x6f, 0x72, 0x67, 0x2c, 0x32, 0x30, 0x32, // . . ".org,202"
				0x36, 0x3a, 0x72, 0x61, 0x74, 0x73, 0x2f, 0x65, // . . "6:rats/e"
				0x61, 0x72, 0x23, 0x30, 0x34, //                   . . "ar#04"
				0x19, 0x01, 0x0a, //                               . key: 266 [submods]
				0xa1,                                           // . value: map(1) [Submods]
				0x6e,                                           // . . key: tstr(15)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x70, 0x70, // . . . "test-app"
				0x72, 0x61, 0x69, 0x73, 0x61, 0x6c, //             . . . "raisal"
				0xa1,             //                               . . value: map(1) [Appraisal]
				0x19, 0x03, 0xe8, //                               . . . key: 1000 [ear_status]
				0x02,             //                               . . . value: 2 [affirming]
				0x19, 0x03, 0xe8, //                               . . key: 1000 [ear_status]
				0x02,             //                               . . value: 2 [affirming]
				0x19, 0x03, 0xec, //                               . . key: 1004 [ear_verifier_id]
				0xa2,                                           // . . value: map(2) [VerifierIdentity]
				0x00,                                           // . . key: 0 [developer]
				0x6e,                                           // . . value: tstr(14)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x65, 0x76, // . . . "test-dev"
				0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, //             . . . "eloper"
				0x01,                                           // . . key: 1 [build]
				0x6a,                                           // . . value: tstr(10)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x62, 0x75, 0x69, // . . . "test-bui"
				0x6c, 0x64, //                                     . . . "ld"
				0x19, 0x03, 0xef, //                               . . key: 1007 [ear_device_topology]
				0xa1,                                           // . . value: map(1) [DeviceTopology]
				0x6e,                                           // . . . key: tstr(14)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x70, 0x70, // . . . . "test-app"
				0x72, 0x61, 0x69, 0x73, 0x61, 0x6c, //             . . . . "raisal"
				0x82,             //                               . . . value: array(2)
				0x63,             //                               . . . . [0]tstr(3)
				0x66, 0x6f, 0x6f, //                               . . . . . "foo"
				0x63,             //                               . . . . [1]tstr(3)
				0x62, 0x61, 0x72, //                               . . . . . "bar"
			},
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

			encodedCBOR, err := tc.result.MarshalCBOR()
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCBOR, encodedCBOR)

			err = decoded.UnmarshalCBOR(encodedCBOR)
			assert.NoError(t, err)

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
	ar.UpdateStatusFromSubmods(JWTKeyEntry{jwa.ES256(), k})
	assert.Equal(t, TrustTierAffirming, *ar.Status)

	ar = NewAttestationResult("test", "test")
	ar.Submods.AddCWT("test", testCWT)

	ar.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierIncomplete, *ar.Status)

	pubKey, err := jwk.Export[*ecdsa.PublicKey](k)
	require.NoError(t, err)

	ar.Status = nil
	ar.UpdateStatusFromSubmods(CWTKeyEntry{cose.AlgorithmES256, pubKey})
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
			title: "ok CBOR",
			token: eat.NestedToken{
				Type: eat.NestedTokenCBOR,
				Data: testCWT,
			},
			expected: AttestationResult{
				IssuedAt:   testIAT,
				VerifierID: &testVerifierID,
				Profile:    testProfile,
				Submods: NewSubmods().AddAppraisal("test", &Appraisal{
					Status: testStatus,
					AppraisalPolicyIDs: []string{
						"https://veraison.example/policy/1/60a0068d",
					},
					Extensions: NewExtensions(),
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

func TestAttestationResult_CWT(t *testing.T) {
	key, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	alg, signer, err := SignerFromJWK(key)
	require.NoError(t, err)

	jwkPubKey, err := key.PublicKey()
	require.NoError(t, err)

	pubKey, err := jwk.Export[*ecdsa.PublicKey](jwkPubKey)
	require.NoError(t, err)

	result := AttestationResult{
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
	}

	signedCWT, err := result.SignCWT(alg, signer, nil)
	assert.NoError(t, err)

	decoded, err := AttestationResultFromVerifiedCWT(signedCWT, &CWTKeyEntry{alg, pubKey})
	assert.NoError(t, err)
	assert.Equal(t, &result, decoded)

	decoded, err = AttestationResultFromUnverifiedCWT(signedCWT)
	assert.NoError(t, err)
	assert.Equal(t, &result, decoded)

	_, err = (&AttestationResult{}).SignCWT(alg, signer, nil)
	assert.ErrorContains(t, err, "missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'")

	cwtBytes := []byte{
		0xd8, 0x3d, // tag(61) [CWT]
		0xd2, //       . tag(18) [cose-sign1]
		0x84, //       . . array(4) [COSE_Sign1]
		0x43, //       . . . [0]bstr(3) [protected-header]
		0xa1, //       . . . . map(1) [header_map]
		0x01, //       . . . . . key: 1 [alg]
		0x26, //       . . . . . value: -7 [ES256]
		0xa0, //       . . . [1]map(0) [unprotected-header]
		0x48, //       . . . [2]bstr(8) [payload]
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0x58, 0x40, // . . . [3]bstr(64) [signature]
		0x2d, 0xb5, 0x63, 0xa7, 0x44, 0xa6, 0x15, 0x4f,
		0xd9, 0x8a, 0x3d, 0x73, 0x90, 0xc4, 0x85, 0x95,
		0x0a, 0x35, 0x64, 0x2e, 0xcd, 0xa6, 0xd0, 0xbe,
		0x76, 0xe3, 0x96, 0x71, 0x75, 0x07, 0x7d, 0xea,
		0x4e, 0x6d, 0x0b, 0x28, 0x28, 0x1c, 0x8c, 0xbd,
		0x6e, 0xb7, 0xef, 0xdf, 0xc0, 0x5b, 0xe1, 0x97,
		0x19, 0xf4, 0x65, 0xa7, 0xa2, 0x3d, 0x5f, 0x31,
		0x6c, 0x81, 0xc6, 0xc8, 0x73, 0x76, 0x01, 0x1d,
	}

	_, err = AttestationResultFromVerifiedCWT(cwtBytes, &CWTKeyEntry{alg, pubKey})
	assert.ErrorContains(t, err, "invalid additional information 30 for type tag")

	_, err = AttestationResultFromUnverifiedCWT(cwtBytes)
	assert.ErrorContains(t, err, "invalid additional information 30 for type tag")
}
