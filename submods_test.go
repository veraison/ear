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
