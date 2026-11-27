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

func testDetailsAppraisal() *Appraisal {
	return &Appraisal{
		Status:        TrustTierContraindicated,
		StatusDetails: []string{"The 'executables' category is contraindicated."},
		TrustVector: &TrustVector{
			InstanceIdentity: 2,
			Executables:      96,
			Hardware:         2,
		},
		TrustVectorDetails: &TrustVectorDetails{
			Executables: []string{"unauthorized code found in runtime memory"},
		},
		Extensions: NewExtensions(),
	}
}

func TestDetails_round_trip(t *testing.T) {
	appraisal := testDetailsAppraisal()

	data, err := json.Marshal(appraisal)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"ear_status": "contraindicated",
		"ear_status_details": [ "The 'executables' category is contraindicated." ],
		"ear_trustworthiness_vector": {
			"instance-identity": 2,
			"executables": 96,
			"hardware": 2
		},
		"ear_trustworthiness_vector_details": {
			"executables": [ "unauthorized code found in runtime memory" ]
		}
	}`, string(data))

	var fromJSON Appraisal
	require.NoError(t, json.Unmarshal(data, &fromJSON))
	assert.Equal(t, appraisal, &fromJSON)

	data, err = appraisal.MarshalCBOR()
	require.NoError(t, err)

	var claims map[int]any
	require.NoError(t, dm.Unmarshal(data, &claims))
	assert.Equal(t, []any{"The 'executables' category is contraindicated."}, claims[1010])
	assert.Equal(t, map[any]any{uint64(2): []any{"unauthorized code found in runtime memory"}}, claims[1011])

	var fromCBOR Appraisal
	require.NoError(t, fromCBOR.UnmarshalCBOR(data))
	assert.Equal(t, appraisal, &fromCBOR)
}

func TestDetails_AttestationResult(t *testing.T) {
	result := AttestationResult{
		Profile:       EatProfile,
		Status:        &TrustTierContraindicated,
		StatusDetails: []string{"PSA is contraindicated"},
		IssuedAt:      testIAT,
		VerifierID:    &testVerifierID,
		Submods:       NewSubmods().AddAppraisal("PSA", testDetailsAppraisal()),
		Extensions:    NewExtensions(),
	}

	data, err := result.MarshalJSON()
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(data, &claims))

	decoded, err := AttestationResultFromAny(claims)
	require.NoError(t, err)
	assert.Equal(t, result.StatusDetails, decoded.StatusDetails)
	assert.Equal(t, testDetailsAppraisal(), decoded.Submods["PSA"].Appraisal())

	result.StatusDetails = []string{}
	_, err = result.MarshalJSON()
	assert.ErrorContains(t, err, "invalid value(s) for ear_status_details (empty list of reasons)")

	claims["ear_status_details"] = "not a list"
	_, err = AttestationResultFromAny(claims)
	assert.EqualError(t, err, "ear_status_details: expected a list of strings, got string")
}

func TestDetails_Appraisal_Validate(t *testing.T) {
	appraisal := testDetailsAppraisal()
	appraisal.StatusDetails = []string{}
	assert.EqualError(t, appraisal.Validate(), "ear_status_details: empty list of reasons")

	appraisal = testDetailsAppraisal()
	appraisal.TrustVectorDetails = &TrustVectorDetails{}
	assert.EqualError(t, appraisal.Validate(), "ear_trustworthiness_vector_details: no categories")

	appraisal = testDetailsAppraisal()
	appraisal.TrustVectorDetails.Executables = []string{}
	assert.EqualError(t, appraisal.Validate(), "ear_trustworthiness_vector_details: executables: empty list of reasons")

	appraisal = testDetailsAppraisal()
	appraisal.TrustVectorDetails.Hardware = []string{}
	assert.EqualError(t, appraisal.Validate(), "ear_trustworthiness_vector_details: hardware: empty list of reasons")

	appraisal = testDetailsAppraisal()
	appraisal.TrustVectorDetails.Configuration = []string{"bad config"}
	appraisal.TrustVectorDetails.SourcedData = []string{"bad data"}
	assert.EqualError(
		t, appraisal.Validate(),
		"ear_trustworthiness_vector_details: categories not in trust vector: configuration, sourced-data",
	)

	appraisal.TrustVector = nil
	assert.ErrorContains(t, appraisal.Validate(), "categories not in trust vector: configuration, executables, sourced-data")
}

func TestTrustVectorDetailsFromAny(t *testing.T) {
	expected := &TrustVectorDetails{
		InstanceIdentity: []string{"a"},
		Configuration:    []string{"b"},
		Executables:      []string{"c"},
		FileSystem:       []string{"d"},
		Hardware:         []string{"e"},
		RuntimeOpaque:    []string{"f"},
		StorageOpaque:    []string{"g"},
		SourcedData:      []string{"h", "i"},
	}

	details, err := TrustVectorDetailsFromAny(map[string]any{
		"instance-identity": []any{"a"},
		"configuration":     []any{"b"},
		"executables":       []any{"c"},
		"file-system":       []any{"d"},
		"hardware":          []any{"e"},
		"runtime-opaque":    []any{"f"},
		"storage-opaque":    []any{"g"},
		"sourced-data":      []string{"h", "i"},
	})
	require.NoError(t, err)
	assert.Equal(t, expected, details)

	details, err = TrustVectorDetailsFromAny(map[any]any{
		0: []any{"a"}, 1: []any{"b"}, 2: []any{"c"}, 3: []any{"d"},
		4: []any{"e"}, 5: []any{"f"}, 6: []any{"g"}, 7: []any{"h", "i"},
	})
	require.NoError(t, err)
	assert.Equal(t, expected, details)

	details, err = TrustVectorDetailsFromAny(expected)
	require.NoError(t, err)
	assert.Equal(t, expected, details)

	details, err = TrustVectorDetailsFromAny(*expected)
	require.NoError(t, err)
	assert.Equal(t, expected, details)

	_, err = TrustVectorDetailsFromAny((*TrustVectorDetails)(nil))
	assert.EqualError(t, err, "nil pointer")

	_, err = TrustVectorDetailsFromAny(map[string]any{"foo": []any{"a"}})
	assert.EqualError(t, err, `unknown category "foo"`)

	_, err = TrustVectorDetailsFromAny(map[string]any{"hardware": []any{1}})
	assert.EqualError(t, err, "hardware: [0]: expected a string, got int")

	_, err = TrustVectorDetailsFromAny(map[string]any{"hardware": []any{}})
	assert.EqualError(t, err, "hardware: empty list of reasons")

	_, err = TrustVectorDetailsFromAny(1)
	assert.Error(t, err)
}

func TestAppraisalFromAny_details(t *testing.T) {
	appraisal, err := AppraisalFromAny(map[eat.IntOrString]any{
		eat.IntOrStringFromInt(1000): 96,
		eat.IntOrStringFromInt(1010): []any{"The 'executables' category is contraindicated."},
		eat.IntOrStringFromInt(1001): map[string]any{
			"instance-identity": 2,
			"executables":       96,
			"hardware":          2,
		},
		eat.IntOrStringFromInt(1011): map[any]any{
			2: []any{"unauthorized code found in runtime memory"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, testDetailsAppraisal(), appraisal)

	_, err = AppraisalFromAny(map[string]any{
		"ear_status":         "affirming",
		"ear_status_details": []any{},
	})
	assert.EqualError(t, err, "ear_status_details: empty list of reasons")

	_, err = AppraisalFromAny(map[string]any{
		"ear_status":                         "affirming",
		"ear_trustworthiness_vector_details": 1,
	})
	assert.ErrorContains(t, err, "ear_trustworthiness_vector_details: ")
}
