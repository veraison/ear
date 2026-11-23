// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
)

func testSupplyChainAppraisal() *Appraisal {
	return &Appraisal{
		Status: TrustTierAffirming,
		EndorserClaims: SupplyChainClaims{
			"Arm": {eat.IntOrStringFromString("psa-certification-reference"): "1234567890123-12345"},
		},
		ReferenceValueProviderClaims: SupplyChainClaims{
			"Arm":    {eat.IntOrStringFromString("measurement-value"): "AQID"},
			"NVIDIA": {eat.IntOrStringFromInt(-75000): "fw-1.2"},
		},
		Extensions: NewExtensions(),
	}
}

func TestSupplyChainClaims_round_trip(t *testing.T) {
	appraisal := testSupplyChainAppraisal()

	data, err := json.Marshal(appraisal)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"ear_status": "affirming",
		"ear_endorser_claims": {
			"Arm": { "psa-certification-reference": "1234567890123-12345" }
		},
		"ear_reference_value_provider_claims": {
			"Arm": { "measurement-value": "AQID" },
			"NVIDIA": { "-75000": "fw-1.2" }
		}
	}`, string(data))

	var fromJSON Appraisal
	require.NoError(t, json.Unmarshal(data, &fromJSON))
	assert.Equal(t, appraisal, &fromJSON)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(data, &claims))
	fromAny, err := AppraisalFromAny(claims)
	require.NoError(t, err)
	assert.Equal(t, appraisal, fromAny)

	data, err = appraisal.MarshalCBOR()
	require.NoError(t, err)

	var fromCBOR Appraisal
	require.NoError(t, fromCBOR.UnmarshalCBOR(data))
	assert.Equal(t, appraisal, &fromCBOR)

	var cborClaims map[any]any
	require.NoError(t, dm.Unmarshal(data, &cborClaims))
	fromAny, err = AppraisalFromAny(cborClaims)
	require.NoError(t, err)
	assert.Equal(t, appraisal, fromAny)
}

func TestSupplyChainClaimsFromAny(t *testing.T) {
	expected := SupplyChainClaims{"123": {eat.IntOrStringFromString("k"): "v"}}

	ret, err := SupplyChainClaimsFromAny(map[string]any{"123": map[string]any{"k": "v"}})
	require.NoError(t, err)
	assert.Equal(t, expected, ret)

	ret, err = SupplyChainClaimsFromAny(map[string]map[eat.IntOrString]any(expected))
	require.NoError(t, err)
	assert.Equal(t, expected, ret)

	_, err = SupplyChainClaimsFromAny(map[any]any{1: map[string]any{"k": "v"}})
	assert.EqualError(t, err, "entity 1: expected a string identifier, got int")

	_, err = SupplyChainClaimsFromAny(map[string]any{"Arm": 1})
	assert.ErrorContains(t, err, `entity "Arm": `)

	_, err = SupplyChainClaimsFromAny(map[string]any{"Arm": map[string]any{}})
	assert.EqualError(t, err, `entity "Arm": no claims`)

	_, err = SupplyChainClaimsFromAny(map[string]any{})
	assert.EqualError(t, err, "no entities")

	_, err = SupplyChainClaimsFromAny([]any{})
	assert.EqualError(t, err, "expected a map, got []interface {}")
}

func TestSupplyChainClaims_Appraisal_Validate(t *testing.T) {
	appraisal := testSupplyChainAppraisal()
	appraisal.EndorserClaims = SupplyChainClaims{}
	assert.EqualError(t, appraisal.Validate(), "ear_endorser_claims: no entities")

	appraisal = testSupplyChainAppraisal()
	appraisal.ReferenceValueProviderClaims["Arm"] = nil
	assert.EqualError(t, appraisal.Validate(), `ear_reference_value_provider_claims: entity "Arm": no claims`)

	_, err := AppraisalFromAny(map[string]any{
		"ear_status":          "affirming",
		"ear_endorser_claims": 1,
	})
	assert.EqualError(t, err, "ear_endorser_claims: expected a map, got int")

	_, err = AppraisalFromAny(map[string]any{
		"ear_status":                          "affirming",
		"ear_reference_value_provider_claims": 1,
	})
	assert.EqualError(t, err, "ear_reference_value_provider_claims: expected a map, got int")
}
