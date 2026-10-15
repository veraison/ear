// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
)

func TestNewAppraisal(t *testing.T) {
	appraisal := NewAppraisal()

	assert.Equal(t, TrustTierNone, appraisal.Status)

	for _, claim := range appraisal.TrustVector.Map() {
		assert.Equal(t, NoClaim, claim)
	}
}

func TestAppraisal_UpdateStatusFromTrustVector_new(t *testing.T) {
	appraisal := NewAppraisal()

	appraisal.UpdateStatusFromTrustVector()

	assert.Equal(t, TrustTierNone, appraisal.Status)
}

func TestAppraisal_UpdateStatusFromTrustVector_basic(t *testing.T) {
	appraisal := NewAppraisal()
	trustVector := TrustVector{
		InstanceIdentity: -2,
		Configuration:    54,
	}
	appraisal.TrustVector = &trustVector

	appraisal.UpdateStatusFromTrustVector()

	assert.Equal(t, TrustTierWarning, appraisal.Status)
}

func TestAppraisal_UpdateStatusFromTrustVector_respects_negative(t *testing.T) {
	appraisal := NewAppraisal()
	trustVector := TrustVector{
		InstanceIdentity: -2,
		Configuration:    5,
		FileSystem:       54,
		Hardware:         -97,
	}
	appraisal.TrustVector = &trustVector

	appraisal.UpdateStatusFromTrustVector()

	assert.Equal(t, TrustTierContraindicated, appraisal.Status)
}

func TestAppraisal_Validate_new(t *testing.T) {
	appraisal := NewAppraisal()
	assert.Nil(t, appraisal.Validate())
}

func TestAppraisal_Validate_basic(t *testing.T) {
	appraisal := NewAppraisal()
	trustVector := TrustVector{
		InstanceIdentity: -2,
		Configuration:    5,
		Hardware:         32,
	}
	appraisal.TrustVector = &trustVector
	assert.Nil(t, appraisal.Validate())

	appraisal.Status = TrustTierAffirming
	assert.Error(t, appraisal.Validate(), "status 2 has higher trustworthiness than Hardware trust vector element(32)")

	appraisal.Status = TrustTierWarning
	assert.Nil(t, appraisal.Validate())
}

func TestAppraisal_Validate_respects_negative(t *testing.T) {
	appraisal := NewAppraisal()
	trustVector := TrustVector{
		InstanceIdentity: -2,
		Configuration:    0,
		Hardware:         -54,
	}
	appraisal.TrustVector = &trustVector
	assert.Nil(t, appraisal.Validate())

	appraisal.Status = TrustTierAffirming
	assert.Error(t, appraisal.Validate(), "status 2 has higher trustworthiness than Hardware trust vector element(32)")

	appraisal.Status = TrustTierWarning
	assert.Nil(t, appraisal.Validate())

	appraisal.Status = TrustTierContraindicated
	assert.Nil(t, appraisal.Validate())
}

func TestAppraisal_round_trip(t *testing.T) {
	testCases := []struct {
		title        string
		appraisal    Appraisal
		expectedJSON string
		expectedCBOR []byte
	}{
		{
			title: "ok minimal",
			appraisal: Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions(),
			},
			expectedJSON: `{"ear_status": "affirming"}`,
			expectedCBOR: []byte{
				0xa1,             // map(1)
				0x19, 0x03, 0xe8, // . key: 1000 [ear_status]
				0x02, //             . value: 2 [affirming]
			},
		},
		{
			title: "ok with extensions",
			appraisal: Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions().StringSet("foo", true),
			},
			expectedJSON: `{"ear_status": "affirming", "foo": true}`,
			expectedCBOR: []byte{
				0xa2,             // map(2)
				0x19, 0x03, 0xe8, // . key: 1000 [ear_status]
				0x02,             // . value: 2 [affirming]
				0x63,             // . key: tstr(3)
				0x66, 0x6f, 0x6f, // . . "foo"
				0xf5, //             . value: true
			},
		},
		{
			title: "ok full",
			appraisal: Appraisal{
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
			expectedJSON: `{"ear_appraisal_policy_ids":["test-policy"],"ear_attester_claims":{"ac-1":"foo"},"ear_status":"affirming","ear_trustworthiness_vector":{"instance-identity":2},"ear_verifier_claims":{"1":"foo"},"eat_nonce":"3q2-796tvu8","eat_profile":"http://test-profile","foo":{"bar":true}}`,
			expectedCBOR: []byte{
				0xa8, //                                           map(8)
				0x0a, //                                           . key: 10 [eat_nonce]
				0x48, //                                           . value: bstr(8)
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				0x19, 0x01, 0x09, //                               . key: 265 [eat_profile]
				0x73,                                           // . value: tstr(19)
				0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x74, // . . "http://t"
				0x65, 0x73, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x66, // . . "est-prof"
				0x69, 0x6c, 0x65, //                               . . "ile"
				0x19, 0x03, 0xe8, //                               . key: 1000 [ear_status]
				0x02,             //                               . value: 2 [affirming]
				0x19, 0x03, 0xe9, //                               . key: 1001 [ear_trustworthiness_vector]
				0xa1,             //                               . value: map(1) [TrustVector]
				0x00,             //                               . . key: 0 [instance-identity]
				0x02,             //                               . . value: 2 [recognized_instance]
				0x19, 0x03, 0xeb, //                               . key: 1003 [ear_appraisal_policy_ids]
				0x81,                                           // . value: array(1)
				0x6b,                                           // . . [0]tstr(11)
				0x74, 0x65, 0x73, 0x74, 0x2d, 0x70, 0x6f, 0x6c, // . . . "test-pol"
				0x69, 0x63, 0x79, //                               . . . "icy"
				0x19, 0x03, 0xed, //                               . key: 1005 [ear_attester_claims]
				0xa1,                   //                         . value: map(1)
				0x64,                   //                         . . key: tstr(4)
				0x61, 0x63, 0x2d, 0x31, //                         . . . "ac-1"
				0x63,             //                               . . value: tstr(3)
				0x66, 0x6f, 0x6f, //                               . . . "foo"
				0x19, 0x03, 0xee, //                               . key: 1006 [ear_verifier_claims]
				0xa1,             //                               . value: map(1)
				0x01,             //                               . . key: 1
				0x63,             //                               . . value: tstr(3)
				0x66, 0x6f, 0x6f, //                               . . . "foo"
				0x63,             //                               . key: tstr(3) [extension]
				0x66, 0x6f, 0x6f, //                               . . "foo"
				0xa1,             //                               . value: map(1)
				0x63,             //                               . . key: tstr(3)
				0x62, 0x61, 0x72, //                               . . . "bar"
				0xf5, //                                           . . value: true
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			encodedJSON, err := json.Marshal(&tc.appraisal)
			assert.NoError(t, err)
			assert.JSONEq(t, tc.expectedJSON, string(encodedJSON))

			var decoded Appraisal
			err = json.Unmarshal(encodedJSON, &decoded)
			assert.NoError(t, err)
			assert.EqualValues(t, tc.appraisal, decoded)

			encodedCBOR, err := tc.appraisal.MarshalCBOR()
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCBOR, encodedCBOR)

			err = decoded.UnmarshalCBOR(encodedCBOR)
			assert.NoError(t, err)

			if tc.title == "ok full" {
				// the map inside extension value gets
				// unmarshaled as map[any]any in CBOR (but as
				// map[string]any in JSON). So we need to
				// manually adjust that here.
				extMap, err := decoded.Extensions.GetMap("foo")
				require.NoError(t, err)

				adjusted := make(map[string]any)
				for key, value := range extMap {
					adjusted[key.(string)] = value
				}

				decoded.Extensions.StringSet("foo", adjusted)
			}

			assert.EqualValues(t, tc.appraisal, decoded)
		})
	}
}

func TestAppraisalFromAny(t *testing.T) {
	testAppraisal := Appraisal{
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
	}

	testCases := []struct {
		title    string
		input    any
		expected Appraisal
		err      string
	}{
		{
			title:    "ok Appraisal",
			input:    testAppraisal,
			expected: testAppraisal,
		},
		{
			title:    "ok Appraisal pointer",
			input:    &testAppraisal,
			expected: testAppraisal,
		},
		{
			title: "ok map[string]any",
			input: map[string]any{
				"eat_profile": "http://test-profile",
				"ear_status":  TrustTierAffirming,
				"ear_trustworthiness_vector": &TrustVector{
					InstanceIdentity: TrustworthyInstanceClaim,
				},
				"ear_appraisal_policy_ids": []any{"test-policy"},
				"eat_nonce": eat.MustNewNonceFromBytes([]byte{
					0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				}),
				"ear_attester_claims": map[eat.IntOrString]any{
					eat.IntOrStringFromString("ac-1"): "foo",
				},
				"ear_verifier_claims": map[eat.IntOrString]any{
					eat.IntOrStringFromInt(1): "foo",
				},
				"foo": map[string]any{
					"bar": true,
				},
			},
			expected: testAppraisal,
		},
		{
			title: "err bad type",
			input: 1,
			err:   "cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err bad profile type",
			input: map[string]any{
				"eat_profile": 1,
				"ear_status":  TrustTierAffirming,
			},
			err: "eat_profile: expected a string, got int",
		},
		{
			title: "err bad profile string",
			input: map[string]any{
				"eat_profile": "@@@",
				"ear_status":  TrustTierAffirming,
			},
			err: "eat_profile: profile string must be an absolute URL or an ASN.1 OID",
		},
		{
			title: "err bad status",
			input: map[string]any{
				"ear_status": "foo",
			},
			err: `ear_status: not a valid TrustTier name: "foo"`,
		},
		{
			title: "err bad trust vector",
			input: map[string]any{
				"ear_status":                 TrustTierAffirming,
				"ear_trustworthiness_vector": 1,
			},
			err: "ear_trustworthiness_vector: cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err bad policy ids",
			input: map[string]any{
				"ear_status":               TrustTierAffirming,
				"ear_appraisal_policy_ids": 1,
			},
			err: "ear_appraisal_policy_ids: expected an []any, got int",
		},
		{
			title: "err bad nonce",
			input: map[string]any{
				"ear_status": TrustTierAffirming,
				"eat_nonce":  1,
			},
			err: "eat_nonce: cannot convert 1 (int) to Nonce",
		},
		{
			title: "err bad attester claims",
			input: map[string]any{
				"ear_status":          TrustTierAffirming,
				"ear_attester_claims": 1,
			},
			err: "ear_attester_claims: cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err bad verifier claims",
			input: map[string]any{
				"ear_status":          TrustTierAffirming,
				"ear_verifier_claims": 1,
			},
			err: "ear_verifier_claims: cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err invalid",
			input: map[string]any{
				"ear_status": TrustTierAffirming,
				"ear_trustworthiness_vector": &TrustVector{
					InstanceIdentity: UntrustworthyInstanceClaim,
				},
			},
			err: "status 2 has higher trustworthiness than instance-identity trust vector element(96)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := AppraisalFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, &tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
