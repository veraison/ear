// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrustTier_round_trip(t *testing.T) {
	testCases := []struct {
		title        string
		tier         TrustTier
		expectedJSON string
		expectedCBOR []byte
	}{
		{
			title:        "ok none",
			tier:         TrustTierNone,
			expectedJSON: `"none"`,
			expectedCBOR: []byte{0x00},
		},
		{
			title:        "ok affirming",
			tier:         TrustTierAffirming,
			expectedJSON: `"affirming"`,
			expectedCBOR: []byte{0x02},
		},
		{
			title:        "ok warning",
			tier:         TrustTierWarning,
			expectedJSON: `"warning"`,
			expectedCBOR: []byte{0x18, 0x20},
		},
		{
			title:        "ok contraindicated",
			tier:         TrustTierContraindicated,
			expectedJSON: `"contraindicated"`,
			expectedCBOR: []byte{0x18, 0x60},
		},
		{
			title:        "ok incomplete",
			tier:         TrustTierIncomplete,
			expectedJSON: `"incomplete"`,
			expectedCBOR: []byte{0x18, 0x7f},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			encodedJSON, err := json.Marshal(tc.tier)
			assert.NoError(t, err)
			assert.JSONEq(t, tc.expectedJSON, string(encodedJSON))

			var tier TrustTier
			err = json.Unmarshal(encodedJSON, &tier)
			assert.NoError(t, err)
			assert.Equal(t, tc.tier, tier)

			encodedCBOR, err := tc.tier.MarshalCBOR()
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCBOR, encodedCBOR)

			err = tier.UnmarshalCBOR(encodedCBOR)
			assert.NoError(t, err)
			assert.Equal(t, tc.tier, tier)
		})
	}
}

func TestTrustTier_UnmarshalJSON_negative(t *testing.T) {
	var tier TrustTier
	err := tier.UnmarshalJSON([]byte(`"foo"`))
	assert.ErrorContains(t, err, `unknown trust tier "foo"`)

	err = tier.UnmarshalJSON([]byte(`@@@`))
	assert.ErrorContains(t, err, `unable to decode trust tier "@@@"`)
}

func TestTrustTierFromInt(t *testing.T) {
	tier, err := TrustTierFromInt(2)
	assert.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, tier)

	_, err = TrustTierFromInt(999)
	assert.ErrorContains(t, err, "not a valid TrustTier value: 999")
}

func TestTrustTierFromString(t *testing.T) {
	tier, err := TrustTierFromString("affirming")
	assert.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, tier)

	tier, err = TrustTierFromString("2")
	assert.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, tier)

	_, err = TrustTierFromString("foo")
	assert.ErrorContains(t, err, `not a valid TrustTier name: "foo"`)
}

func TestTrustTierFromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected TrustTier
		err      string
	}{
		{
			title:    "ok TrustTier",
			input:    TrustTierAffirming,
			expected: TrustTierAffirming,
		},
		{
			title:    "ok pointer",
			input:    &TrustTierAffirming,
			expected: TrustTierAffirming,
		},
		{
			title:    "ok TrustClaim",
			input:    TrustClaim(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok string",
			input:    "affirming",
			expected: TrustTierAffirming,
		},
		{
			title:    "ok int",
			input:    2,
			expected: TrustTierAffirming,
		},
		{
			title:    "ok int8",
			input:    int8(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok int16",
			input:    int16(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok int32",
			input:    int32(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok int64",
			input:    int64(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok uint",
			input:    2,
			expected: TrustTierAffirming,
		},
		{
			title:    "ok uint8",
			input:    uint8(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok uint16",
			input:    uint16(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok uint32",
			input:    uint32(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok uint64",
			input:    uint64(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok uint",
			input:    uint(2),
			expected: TrustTierAffirming,
		},
		{
			title:    "ok float",
			input:    2.0,
			expected: TrustTierAffirming,
		},
		{
			title:    "ok json.Number",
			input:    json.Number("2"),
			expected: TrustTierAffirming,
		},
		{
			title: "err bad type",
			input: true,
			err:   "cannot convert true (bool) to TrustTier",
		},
		{
			title: "err uint out of range",
			input: uint(math.MaxInt64) + 1,
			err:   "not a valid TrustTier value: 9223372036854775808",
		},
		{
			title: "err uint64 out of range",
			input: uint64(math.MaxInt64) + 1,
			err:   "not a valid TrustTier value: 9223372036854775808",
		},
		{
			title: "err invalid json.Number",
			input: json.Number("foo"),
			err:   "not a valid TrustTier value: foo",
		},
		{
			title: "err bad json.Number",
			input: json.Number("7"),
			err:   "not a valid TrustTier value: 7",
		},
		{
			title: "err nil",
			input: (*TrustTier)(nil),
			err:   "nil pointer",
		},
		{
			title: "err bad float64",
			input: 3.4,
			err:   "not a valid TrustTier value: 3.4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := TrustTierFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestTrustTier_Int8(t *testing.T) {
	assert.Equal(t, int8(0), TrustTierNone.Int8())
	assert.Equal(t, int8(2), TrustTierAffirming.Int8())
	assert.Equal(t, int8(32), TrustTierWarning.Int8())
	assert.Equal(t, int8(96), TrustTierContraindicated.Int8())
	assert.Equal(t, int8(127), TrustTierIncomplete.Int8())
}

func TestTrustTier_ColorString(t *testing.T) {
	assert.Equal(t, "\\033[47mnone\\033[0m", TrustTierNone.ColorString())
	assert.Equal(t, "\\033[42maffirming\\033[0m", TrustTierAffirming.ColorString())
	assert.Equal(t, "\\033[43mwarning\\033[0m", TrustTierWarning.ColorString())
	assert.Equal(t, "\\033[41mcontraindicated\\033[0m", TrustTierContraindicated.ColorString())
	assert.Equal(t, "\\033[1;33;41mincomplete\\033[0m", TrustTierIncomplete.ColorString())
}
