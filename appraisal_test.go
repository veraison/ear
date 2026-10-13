// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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
	}{
		{
			title: "ok minimal",
			appraisal: Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions(),
			},
			expectedJSON: `{"ear_status": "affirming"}`,
		},
		{
			title: "ok with extensions",
			appraisal: Appraisal{
				Status:     TrustTierAffirming,
				Extensions: NewExtensions().StringSet("foo", true),
			},
			expectedJSON: `{"ear_status": "affirming", "foo": true}`,
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
