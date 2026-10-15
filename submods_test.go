// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/eat"
)

func TestSubmodFromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected Submod
		err      string
	}{
		{
			title: "ok Submod",
			input: Submod{&Appraisal{
				Status: TrustTierAffirming,
			}},
			expected: Submod{&Appraisal{
				Status: TrustTierAffirming,
			}},
		},
		{
			title: "ok Submod pointer",
			input: Submod{&Appraisal{
				Status: TrustTierAffirming,
			}},
			expected: Submod{&Appraisal{
				Status: TrustTierAffirming,
			}},
		},
		{
			title: "ok appraisal",
			input: Appraisal{
				Status: TrustTierAffirming,
			},
			expected: Submod{&Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions(),
			}},
		},
		{
			title: "err wrong type",
			input: 1,
			err:   `decoding JSON: invalid JSON type (expected object or array): "1"`,
		},
		{
			title: "err encoding JSON",
			input: make(chan int),
			err:   "encoding JSON: json: unsupported type: chan int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			submod, err := SubmodFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, &tc.expected, submod)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestSubmod_accessors(t *testing.T) {
	appraisal := Appraisal{
		Status: TrustTierAffirming,
	}

	submod := Submod{&appraisal}

	assert.Equal(t, &appraisal, submod.Value())
	assert.Equal(t, &appraisal, submod.Appraisal())
	assert.Nil(t, submod.AttestationResult())
	assert.Nil(t, submod.NestedToken())

	result := AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   1666091373,
		VerifierID: NewVerifierIdentity("test-build", "test-developer"),
		Submods: NewSubmods().AddAppraisal(
			"test-appraisal",
			&Appraisal{
				Status: TrustTierAffirming,
			},
		),
	}

	submod = Submod{&result}

	assert.Equal(t, &result, submod.Value())
	assert.Equal(t, &result, submod.AttestationResult())
	assert.Nil(t, submod.Appraisal())
	assert.Nil(t, submod.NestedToken())

	token := eat.NestedToken{
		Type: eat.NestedTokenJWT,
		Data: []byte(`"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg"`), // #nosec G101
	}

	submod = Submod{&token}

	assert.Equal(t, &token, submod.Value())
	assert.Equal(t, &token, submod.NestedToken())
	assert.Nil(t, submod.Appraisal())
	assert.Nil(t, submod.AttestationResult())
}

func TestSubmod_round_trip(t *testing.T) {
	testCases := []struct {
		title        string
		submod       Submod
		expectedJSON string
		expectedCBOR []byte
	}{
		{
			title: "ok Appraisal",
			submod: Submod{
				&Appraisal{
					Status:     TrustTierAffirming,
					Extensions: NewExtensions(),
				},
			},
			expectedJSON: `{"ear_status":"affirming"}`,
			expectedCBOR: []byte{
				0xa1,             // map(1)
				0x19, 0x03, 0xe8, // . key: 1000 [eat_status]
				0x02, //           // . value: 2 [affirming]
			},
		},
		{
			title: "ok AttestationResult",
			submod: Submod{
				&AttestationResult{
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
			},
			expectedJSON: `{"ear_verifier_id":{"developer":"test-developer","build":"test-build"},"eat_profile":"tag:ietf.org,2026:rats/ear#04","iat":1666091373,"submods":{"test-appraisal":{"ear_status":"affirming"}}}`,
			expectedCBOR: []byte{
				0xa4,                         //                   map(4)
				0x06,                         //                   . key: 6 [iat]
				0x1a, 0x63, 0x4e, 0x89, 0x6d, //                   . value: 1666091373
				0x19, 0x01, 0x09, //                               . key: 265 [eat_profile]
				0x78, 0x1d, //                                     . value: tstr(29)
				0x74, 0x61, 0x67, 0x3a, 0x69, 0x65, 0x74, 0x66, // . . "tag:ietf"
				0x2e, 0x6f, 0x72, 0x67, 0x2c, 0x32, 0x30, 0x32, // . . ".org,202"
				0x36, 0x3a, 0x72, 0x61, 0x74, 0x73, 0x2f, 0x65, // . . "6:rats/e"
				0x61, 0x72, 0x23, 0x30, 0x34, //                   . . "ar#04"
				0x19, 0x01, 0x0a, //                               . key: 266 [submods]
				0xa1,                                           // . value: map(1) [Submods]
				0x6e,                                           // . key: tstr(14)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x70, 0x70, // . . "test-app"
				0x72, 0x61, 0x69, 0x73, 0x61, 0x6c, //             . . "raisal"
				0xa1,             //                               . value: map(1) [Appraisal]
				0x19, 0x03, 0xe8, //                               . . key: 1000 [ear_status]
				0x02,             //                               . . value: 2 [affirming]
				0x19, 0x03, 0xec, //                               . key: 1004 [ear_verifier_id]
				0xa2,                                           // . value: map(2) [VerifierIdentity]
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
			title: "ok eat.NestedToken",
			submod: Submod{
				&eat.NestedToken{
					Type: eat.NestedTokenJWT,
					Data: []byte(`"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg"`), // #nosec G101
				},
			},
			expectedJSON: `["JWT","eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg"]`,
			expectedCBOR: []byte{
				0x79, 0x02, 0x70, // tstr(624)
				0x22, 0x65, 0x79, 0x4a, 0x68, 0x62, 0x47, 0x63,
				0x69, 0x4f, 0x69, 0x4a, 0x46, 0x55, 0x7a, 0x49,
				0x31, 0x4e, 0x69, 0x49, 0x73, 0x49, 0x6e, 0x52,
				0x35, 0x63, 0x43, 0x49, 0x36, 0x49, 0x6b, 0x70,
				0x58, 0x56, 0x43, 0x4a, 0x39, 0x2e, 0x65, 0x79,
				0x4a, 0x6c, 0x59, 0x58, 0x4a, 0x66, 0x64, 0x6d,
				0x56, 0x79, 0x61, 0x57, 0x5a, 0x70, 0x5a, 0x58,
				0x4a, 0x66, 0x61, 0x57, 0x51, 0x69, 0x4f, 0x6e,
				0x73, 0x69, 0x59, 0x6e, 0x56, 0x70, 0x62, 0x47,
				0x51, 0x69, 0x4f, 0x69, 0x4a, 0x79, 0x63, 0x6e,
				0x52, 0x79, 0x59, 0x58, 0x41, 0x74, 0x64, 0x6a,
				0x45, 0x75, 0x4d, 0x43, 0x34, 0x77, 0x49, 0x69,
				0x77, 0x69, 0x5a, 0x47, 0x56, 0x32, 0x5a, 0x57,
				0x78, 0x76, 0x63, 0x47, 0x56, 0x79, 0x49, 0x6a,
				0x6f, 0x69, 0x51, 0x57, 0x4e, 0x74, 0x5a, 0x53,
				0x42, 0x4a, 0x62, 0x6d, 0x4d, 0x75, 0x49, 0x6e,
				0x30, 0x73, 0x49, 0x6d, 0x56, 0x68, 0x64, 0x46,
				0x39, 0x77, 0x63, 0x6d, 0x39, 0x6d, 0x61, 0x57,
				0x78, 0x6c, 0x49, 0x6a, 0x6f, 0x69, 0x64, 0x47,
				0x46, 0x6e, 0x4f, 0x6d, 0x6c, 0x6c, 0x64, 0x47,
				0x59, 0x75, 0x62, 0x33, 0x4a, 0x6e, 0x4c, 0x44,
				0x49, 0x77, 0x4d, 0x6a, 0x59, 0x36, 0x63, 0x6d,
				0x46, 0x30, 0x63, 0x79, 0x39, 0x6c, 0x59, 0x58,
				0x49, 0x6a, 0x4d, 0x44, 0x51, 0x69, 0x4c, 0x43,
				0x4a, 0x70, 0x59, 0x58, 0x51, 0x69, 0x4f, 0x6a,
				0x45, 0x32, 0x4e, 0x6a, 0x59, 0x77, 0x4f, 0x54,
				0x45, 0x7a, 0x4e, 0x7a, 0x4d, 0x73, 0x49, 0x6e,
				0x4e, 0x31, 0x59, 0x6d, 0x31, 0x76, 0x5a, 0x48,
				0x4d, 0x69, 0x4f, 0x6e, 0x73, 0x69, 0x64, 0x47,
				0x56, 0x7a, 0x64, 0x43, 0x49, 0x36, 0x65, 0x79,
				0x4a, 0x6c, 0x59, 0x58, 0x4a, 0x66, 0x59, 0x58,
				0x42, 0x77, 0x63, 0x6d, 0x46, 0x70, 0x63, 0x32,
				0x46, 0x73, 0x58, 0x33, 0x42, 0x76, 0x62, 0x47,
				0x6c, 0x6a, 0x65, 0x56, 0x39, 0x70, 0x5a, 0x48,
				0x4d, 0x69, 0x4f, 0x6c, 0x73, 0x69, 0x63, 0x47,
				0x39, 0x73, 0x61, 0x57, 0x4e, 0x35, 0x4f, 0x69,
				0x38, 0x76, 0x64, 0x47, 0x56, 0x7a, 0x64, 0x43,
				0x38, 0x77, 0x4d, 0x54, 0x49, 0x7a, 0x4e, 0x43,
				0x4a, 0x64, 0x4c, 0x43, 0x4a, 0x6c, 0x59, 0x58,
				0x4a, 0x66, 0x59, 0x58, 0x52, 0x30, 0x5a, 0x58,
				0x4e, 0x30, 0x5a, 0x58, 0x4a, 0x66, 0x59, 0x32,
				0x78, 0x68, 0x61, 0x57, 0x31, 0x7a, 0x49, 0x6a,
				0x70, 0x37, 0x49, 0x6d, 0x73, 0x78, 0x49, 0x6a,
				0x6f, 0x69, 0x64, 0x6a, 0x45, 0x69, 0x4c, 0x43,
				0x4a, 0x72, 0x4d, 0x69, 0x49, 0x36, 0x49, 0x6e,
				0x59, 0x79, 0x49, 0x6e, 0x30, 0x73, 0x49, 0x6d,
				0x56, 0x68, 0x63, 0x6c, 0x39, 0x7a, 0x64, 0x47,
				0x46, 0x30, 0x64, 0x58, 0x4d, 0x69, 0x4f, 0x69,
				0x4a, 0x68, 0x5a, 0x6d, 0x5a, 0x70, 0x63, 0x6d,
				0x31, 0x70, 0x62, 0x6d, 0x63, 0x69, 0x4c, 0x43,
				0x4a, 0x6c, 0x59, 0x58, 0x4a, 0x66, 0x64, 0x6d,
				0x56, 0x79, 0x59, 0x57, 0x6c, 0x7a, 0x62, 0x32,
				0x35, 0x66, 0x61, 0x32, 0x56, 0x35, 0x58, 0x32,
				0x46, 0x30, 0x64, 0x47, 0x56, 0x7a, 0x64, 0x47,
				0x46, 0x30, 0x61, 0x57, 0x39, 0x75, 0x49, 0x6a,
				0x70, 0x37, 0x49, 0x6d, 0x46, 0x72, 0x63, 0x48,
				0x56, 0x69, 0x49, 0x6a, 0x6f, 0x69, 0x57, 0x56,
				0x64, 0x30, 0x64, 0x32, 0x52, 0x58, 0x53, 0x55,
				0x73, 0x69, 0x66, 0x53, 0x77, 0x69, 0x5a, 0x57,
				0x46, 0x79, 0x58, 0x33, 0x5a, 0x6c, 0x63, 0x6d,
				0x6c, 0x6d, 0x61, 0x57, 0x56, 0x79, 0x58, 0x32,
				0x4e, 0x73, 0x59, 0x57, 0x6c, 0x74, 0x63, 0x79,
				0x49, 0x36, 0x65, 0x79, 0x4a, 0x69, 0x59, 0x58,
				0x49, 0x69, 0x4f, 0x69, 0x4a, 0x69, 0x59, 0x58,
				0x6f, 0x69, 0x4c, 0x43, 0x4a, 0x6d, 0x62, 0x32,
				0x38, 0x69, 0x4f, 0x69, 0x4a, 0x69, 0x59, 0x58,
				0x49, 0x69, 0x66, 0x58, 0x31, 0x39, 0x66, 0x51,
				0x2e, 0x61, 0x4c, 0x79, 0x4f, 0x2d, 0x4a, 0x52,
				0x78, 0x71, 0x79, 0x76, 0x45, 0x46, 0x49, 0x5a,
				0x79, 0x76, 0x71, 0x68, 0x56, 0x65, 0x62, 0x64,
				0x4c, 0x61, 0x72, 0x39, 0x4b, 0x53, 0x41, 0x65,
				0x53, 0x68, 0x42, 0x2d, 0x44, 0x62, 0x5a, 0x5a,
				0x31, 0x79, 0x71, 0x66, 0x64, 0x47, 0x7a, 0x6b,
				0x36, 0x2d, 0x35, 0x6e, 0x75, 0x31, 0x74, 0x55,
				0x30, 0x44, 0x67, 0x78, 0x5f, 0x4d, 0x6a, 0x6f,
				0x79, 0x6f, 0x31, 0x33, 0x68, 0x67, 0x4e, 0x70,
				0x57, 0x31, 0x39, 0x69, 0x48, 0x76, 0x76, 0x6a,
				0x31, 0x70, 0x42, 0x43, 0x67, 0x74, 0x67, 0x22,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			encodedJSON, err := tc.submod.MarshalJSON()
			assert.NoError(t, err)
			assert.JSONEq(t, tc.expectedJSON, string(encodedJSON))

			var decoded Submod
			err = decoded.UnmarshalJSON(encodedJSON)
			assert.NoError(t, err)
			assert.Equal(t, tc.submod, decoded)

			encodedCBOR, err := tc.submod.MarshalCBOR()
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCBOR, encodedCBOR)

			err = decoded.UnmarshalCBOR(encodedCBOR)
			assert.NoError(t, err)
			assert.Equal(t, tc.submod, decoded)
		})
	}
}

func TestSubmod_UnmarshalJSON_negative(t *testing.T) {
	testCases := []struct {
		title string
		input string
		err   string
	}{
		{
			title: "err empty",
			input: "",
			err:   "truncated input",
		},
		{
			title: "err wrong type",
			input: "1",
			err:   `invalid JSON type (expected object or array): "1"`,
		},
		{
			title: "err bad eat.NestedToken",
			input: "[]",
			err:   "nested token: selector type: unexpected end of JSON input",
		},
		{
			title: "err bad Appraisal",
			input: "{}",
			err:   `appraisal: missing mandatory "ear_status" claim`,
		},
		{
			title: "err bad AttestationResult",
			input: `{"iat": 112}`,
			err:   `attestation result: missing mandatory 'eat_profile', 'ear_verifier_id', 'submods'`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			var decoded Submod
			err := decoded.UnmarshalJSON([]byte(tc.input))
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestSubmod_UnmarshalCBOR_negative(t *testing.T) {
	testCases := []struct {
		title string
		input []byte
		err   string
	}{
		{
			title: "err empty",
			input: []byte{},
			err:   "truncated input",
		},
		{
			title: "err bad CBOR",
			input: []byte{0xde, 0xad, 0xbe, 0xef},
			err:   "unexpected CBOR major type 6 (expected 3, 4, or 5)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			var decoded Submod
			err := decoded.UnmarshalCBOR(tc.input)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestSubmodsFromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected Submods
		err      string
	}{
		{
			title: "ok Submods",
			input: Submods{
				"test": &Submod{&Appraisal{}},
			},
			expected: Submods{
				"test": &Submod{&Appraisal{}},
			},
		},
		{
			title: "ok Submods pointer",
			input: &Submods{
				"test": &Submod{&Appraisal{}},
			},
			expected: Submods{
				"test": &Submod{&Appraisal{}},
			},
		},
		{
			title: "ok map[string]*Submod",
			input: map[string]*Submod{
				"test": &Submod{&Appraisal{}},
			},
			expected: Submods{
				"test": &Submod{&Appraisal{}},
			},
		},
		{
			title: "ok map[string]any",
			input: map[string]any{
				"test": map[string]any{
					"ear_status": "none",
				},
			},
			expected: Submods{
				"test": &Submod{&Appraisal{
					Extensions: NewExtensions(),
				}},
			},
		},
		{
			title: "err nil pointer",
			input: (*Submods)(nil),
			err:   "nil pointer",
		},
		{
			title: "err wrong type",
			input: 1,
			err:   "unexpected Submods type int",
		},
		{
			title: "err map[string]any missing mandatory",
			input: map[string]any{
				"test": map[string]any{},
			},
			err: `appraisal: missing mandatory "ear_status" claim`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			submods, err := SubmodsFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, submods)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestSubmods_set_get(t *testing.T) {
	appraisal := Appraisal{}
	result := AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   1666091373,
		VerifierID: NewVerifierIdentity("test-build", "test-developer"),
		Submods: NewSubmods().AddAppraisal(
			"test-appraisal",
			&Appraisal{
				Status: TrustTierAffirming,
			},
		),
	}
	jwtBytes := []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXJfdmVyaWZpZXJfaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmlldGYub3JnLDIwMjY6cmF0cy9lYXIjMDQiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXJfYXBwcmFpc2FsX3BvbGljeV9pZHMiOlsicG9saWN5Oi8vdGVzdC8wMTIzNCJdLCJlYXJfYXR0ZXN0ZXJfY2xhaW1zIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhcl9zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXJfdmVyYWlzb25fa2V5X2F0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyX3ZlcmlmaWVyX2NsYWltcyI6eyJiYXIiOiJiYXoiLCJmb28iOiJiYXIifX19fQ.aLyO-JRxqyvEFIZyvqhVebdLar9KSAeShB-DbZZ1yqfdGzk6-5nu1tU0Dgx_Mjoyo13hgNpW19iHvvj1pBCgtg") // #nosec G101

	submods := NewSubmods()
	assert.True(t, submods.IsEmpty())

	submods.AddAppraisal("test-appraisal", &appraisal).
		AddAttestationResult("test-result", &result).
		AddJWT("test-nested", jwtBytes)

	assert.False(t, submods.IsEmpty())

	obtainedAppraisal, err := submods.GetAppraisal("test-appraisal")
	assert.NoError(t, err)
	assert.Equal(t, &appraisal, obtainedAppraisal)

	obtainedResult, err := submods.GetAttestationResult("test-result")
	assert.NoError(t, err)
	assert.Equal(t, &result, obtainedResult)

	expectedToken := eat.NestedToken{
		Type: eat.NestedTokenJWT,
		Data: []byte(fmt.Sprintf("%q", string(jwtBytes))),
	}
	obtainedToken, err := submods.GetNestedToken("test-nested")
	assert.NoError(t, err)
	assert.Equal(t, &expectedToken, obtainedToken)

	_, err = submods.GetAppraisal("foo")
	assert.ErrorContains(t, err, `no submod named "foo"`)

	_, err = submods.GetAppraisal("test-result")
	assert.ErrorContains(t, err, "not an appraisal")

	_, err = submods.GetAttestationResult("test-nested")
	assert.ErrorContains(t, err, "not an attestation result")

	_, err = submods.GetNestedToken("test-appraisal")
	assert.ErrorContains(t, err, "not a nested token")
}

func TestSubmods_Validate(t *testing.T) {
	testCases := []struct {
		title   string
		submods Submods
		err     string
	}{
		{
			title: "ok",
			submods: Submods{
				"test": &Submod{&Appraisal{}},
			},
		},
		{
			title:   "err empty",
			submods: Submods{},
			err:     "no submods defined",
		},
		{
			title: "err bad appraisal",
			submods: Submods{
				"test": &Submod{&Appraisal{
					Status: TrustTierAffirming,
					TrustVector: &TrustVector{
						Executables: UnrecognizedRuntimeClaim,
					},
				}},
			},
			err: "test: status 2 has higher trustworthiness than executables trust vector element(32)",
		},
		{
			title: "err bad attestation result",
			submods: Submods{
				"test": &Submod{&AttestationResult{}},
			},
			err: "test: missing mandatory 'eat_profile', 'iat', 'ear_verifier_id', 'submods'",
		},
		{
			title: "err bad nested token",
			submods: Submods{
				"test": &Submod{&eat.NestedToken{
					Type: eat.NestedTokenDigest,
					Data: []byte(`[-16,"3q2-7w"]`),
				}},
			},
			err: "test: cannot create AttestationResult from DIGEST",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			err := tc.submods.Validate()

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
