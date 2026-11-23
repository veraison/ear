// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentsBound_values(t *testing.T) {
	for _, tc := range []struct {
		value ComponentsBound
		name  string
		i     int
		tier  TrustTier
	}{
		{ComponentsBoundBound, "bound", 2, TrustTierAffirming},
		{ComponentsBoundNotBound, "not-bound", 96, TrustTierContraindicated},
		{ComponentsBoundCouldNotDetermine, "could-not-determine", 1, TrustTierIncomplete},
		{ComponentsBound{}, "could-not-determine", 1, TrustTierIncomplete},
	} {
		assert.Equal(t, tc.name, tc.value.String())
		assert.Equal(t, tc.i, tc.value.Int())
		assert.Equal(t, tc.tier, tc.value.Tier())
	}

	assert.True(t, ComponentsBoundNotBound.WorseThan(ComponentsBoundBound))
	assert.False(t, ComponentsBoundBound.WorseThan(ComponentsBoundNotBound))
}

func TestComponentsBound_JSON(t *testing.T) {
	data, err := json.Marshal(ComponentsBoundNotBound)
	require.NoError(t, err)
	assert.Equal(t, `"not-bound"`, string(data))

	var cb ComponentsBound
	require.NoError(t, json.Unmarshal([]byte(`"bound"`), &cb))
	assert.Equal(t, ComponentsBoundBound, cb)

	// unrecognised values are treated as could-not-determine
	require.NoError(t, json.Unmarshal([]byte(`"maybe"`), &cb))
	assert.Equal(t, ComponentsBoundCouldNotDetermine, cb)

	assert.ErrorContains(t, json.Unmarshal([]byte(`2`), &cb), "unable to decode components bound")
}

func TestComponentsBound_CBOR(t *testing.T) {
	data, err := em.Marshal(ComponentsBoundNotBound)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x18, 0x60}, data)

	data, err = em.Marshal(ComponentsBound{})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01}, data)

	var cb ComponentsBound
	require.NoError(t, dm.Unmarshal([]byte{0x02}, &cb))
	assert.Equal(t, ComponentsBoundBound, cb)

	// unrecognised values are treated as could-not-determine
	for _, input := range [][]byte{{0x18, 0x20}, {0x19, 0x01, 0x00}, {0x20}} {
		require.NoError(t, dm.Unmarshal(input, &cb))
		assert.Equal(t, ComponentsBoundCouldNotDetermine, cb)
	}

	assert.Error(t, dm.Unmarshal([]byte{0x64, 0x62, 0x6f, 0x75, 0x6e}, &cb))
}

func TestComponentsBoundFromAny(t *testing.T) {
	for _, tc := range []struct {
		input    any
		expected ComponentsBound
	}{
		{"bound", ComponentsBoundBound},
		{"not-bound", ComponentsBoundNotBound},
		{"could-not-determine", ComponentsBoundCouldNotDetermine},
		{"other", ComponentsBoundCouldNotDetermine},
		{2, ComponentsBoundBound},
		{uint64(96), ComponentsBoundNotBound},
		{float64(1), ComponentsBoundCouldNotDetermine},
		{int64(1000), ComponentsBoundCouldNotDetermine},
		{ComponentsBoundNotBound, ComponentsBoundNotBound},
		{&ComponentsBoundBound, ComponentsBoundBound},
	} {
		cb, err := ComponentsBoundFromAny(tc.input)
		require.NoError(t, err, tc.input)
		assert.Equal(t, tc.expected, *cb, tc.input)
	}

	_, err := ComponentsBoundFromAny((*ComponentsBound)(nil))
	assert.EqualError(t, err, "nil pointer")

	_, err = ComponentsBoundFromAny(1.5)
	assert.EqualError(t, err, "not an integer: 1.5")

	_, err = ComponentsBoundFromAny([]any{})
	assert.Error(t, err)
}

func testComponentsBoundResult(bound *ComponentsBound) *AttestationResult {
	return &AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   testIAT,
		VerifierID: &testVerifierID,
		Submods: NewSubmods().
			AddAppraisal("cpu", &Appraisal{Status: TrustTierAffirming, Extensions: NewExtensions()}).
			AddAppraisal("gpu", &Appraisal{Status: TrustTierAffirming, Extensions: NewExtensions()}),
		ComponentsBound: bound,
		Extensions:      NewExtensions(),
	}
}

func TestAttestationResult_ComponentsBound(t *testing.T) {
	result := testComponentsBoundResult(&ComponentsBoundBound)
	result.Status = &TrustTierAffirming

	data, err := result.MarshalJSON()
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(data, &claims))
	assert.Equal(t, "bound", claims["ear_components_bound"])

	fromAny, err := AttestationResultFromAny(claims)
	require.NoError(t, err)
	assert.Equal(t, result, fromAny)

	claims["ear_components_bound"] = []any{}
	_, err = AttestationResultFromAny(claims)
	assert.ErrorContains(t, err, "ear_components_bound: ")

	data, err = result.MarshalCBOR()
	require.NoError(t, err)

	var fromCBOR AttestationResult
	require.NoError(t, fromCBOR.UnmarshalCBOR(data))
	assert.Equal(t, result, &fromCBOR)

	result.ComponentsBound = &ComponentsBoundNotBound
	assert.EqualError(
		t, result.Validate(),
		"invalid value(s) for ear_status (affirming has higher trustworthiness than ear_components_bound not-bound)",
	)
}

func TestAttestationResult_UpdateStatusFromSubmods_ComponentsBound(t *testing.T) {
	result := testComponentsBoundResult(&ComponentsBoundBound)
	result.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierAffirming, *result.Status)
	assert.Equal(t, ComponentsBoundBound, *result.ComponentsBound)

	result = testComponentsBoundResult(&ComponentsBoundNotBound)
	result.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierContraindicated, *result.Status)

	// nested values are combined by taking the one of lowest trust
	nested := testComponentsBoundResult(&ComponentsBoundCouldNotDetermine)
	result = testComponentsBoundResult(&ComponentsBoundBound)
	result.Submods.AddAttestationResult("nested", nested)
	result.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierIncomplete, *nested.Status)
	assert.Equal(t, TrustTierIncomplete, *result.Status)
	assert.Equal(t, ComponentsBoundCouldNotDetermine, *result.ComponentsBound)

	// the nested value is used when the lead verifier has none of its own
	nested = testComponentsBoundResult(&ComponentsBoundBound)
	result = testComponentsBoundResult(nil)
	result.Submods.AddAttestationResult("nested", nested)
	result.UpdateStatusFromSubmods()
	assert.Equal(t, TrustTierAffirming, *result.Status)
	assert.Equal(t, ComponentsBoundBound, *result.ComponentsBound)

	// a nested submod without the claim does not contribute
	nested = testComponentsBoundResult(nil)
	result = testComponentsBoundResult(nil)
	result.Submods.AddAttestationResult("nested", nested)
	result.UpdateStatusFromSubmods()
	assert.Nil(t, result.ComponentsBound)
}
