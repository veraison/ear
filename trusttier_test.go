package ear

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustTier_MarshalJSON_pass(t *testing.T) {
	tvs := []struct {
		status   TrustTier
		expected string
	}{
		{
			status:   TrustTierNone,
			expected: `"none"`,
		},
		{
			status:   TrustTierAffirming,
			expected: `"affirming"`,
		},
		{
			status:   TrustTierWarning,
			expected: `"warning"`,
		},
		{
			status:   TrustTierContraindicated,
			expected: `"contraindicated"`,
		},
	}

	for _, tv := range tvs {
		actual, err := tv.status.MarshalJSON()
		assert.NoError(t, err)
		assert.JSONEq(t, tv.expected, string(actual))
	}
}

func TestTrustTier_MarshalJSON_fail(t *testing.T) {
	tvs := []struct {
		status   TrustTier
		expected string
	}{
		{
			status:   TrustTier(123),
			expected: `unknown trust tier '123'`,
		},
	}

	for i, tv := range tvs {
		_, err := tv.status.MarshalJSON()
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestTrustTier_UnmarshalJSON_pass(t *testing.T) {
	tvs := []struct {
		status   string
		expected TrustTier
	}{
		{
			status:   `"none"`,
			expected: TrustTierNone,
		},
		{
			status:   `"affirming"`,
			expected: TrustTierAffirming,
		},
		{
			status:   `"warning"`,
			expected: TrustTierWarning,
		},
		{
			status:   `"contraindicated"`,
			expected: TrustTierContraindicated,
		},
	}

	for i, tv := range tvs {
		var actual TrustTier

		err := actual.UnmarshalJSON([]byte(tv.status))
		assert.NoError(t, err)
		assert.Equal(t, tv.expected, actual, "failed test vector at index %d", i)
	}
}

func TestTrustTier_UnmarshalJSON_fail(t *testing.T) {
	tvs := []struct {
		status   string
		expected string
	}{
		{
			status:   `"unknown string"`,
			expected: `unknown trust tier 'unknown string'`,
		},
		{
			status:   `"1000000"`,
			expected: `unknown trust tier '1000000'`,
		},
		{
			status:   `[]`,
			expected: `unable to decode trust tier '[]': json: cannot unmarshal array into Go value of type string`,
		},
		{
			status:   `"none`,
			expected: `unable to decode trust tier '"none': unexpected end of JSON input`,
		},
	}

	for i, tv := range tvs {
		var actual TrustTier

		err := actual.UnmarshalJSON([]byte(tv.status))
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestTrustTier_ToTrustTier(t *testing.T) {
	var tt *TrustTier
	var err error

	tt, err = TrustTierFromAny(2)
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)

	tt, err = TrustTierFromAny(2.5)
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)

	_, err = TrustTierFromAny(3.1)
	assert.ErrorContains(t, err, "not a valid TrustTier value: 3.100000 (3)")

	_, err = TrustTierFromAny(math.MaxFloat32)
	assert.ErrorContains(t, err, "not a valid TrustTier value: 34028234")

	tt, err = TrustTierFromAny(int8(32))
	require.NoError(t, err)
	assert.Equal(t, TrustTierWarning, *tt)

	_, err = TrustTierFromAny(uint64(math.MaxUint64))
	assert.ErrorContains(t, err,
		fmt.Sprintf("not a valid TrustTier value: %d", uint64(math.MaxUint64)))

	tt, err = TrustTierFromAny("affirming")
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)

	tt, err = TrustTierFromAny("96")
	require.NoError(t, err)
	assert.Equal(t, TrustTierContraindicated, *tt)

	tt, err = TrustTierFromAny([]byte{0x33, 0x32}) // "32"
	require.NoError(t, err)
	assert.Equal(t, TrustTierWarning, *tt)

	_, err = TrustTierFromAny("totally safe")
	assert.ErrorContains(t, err, `not a valid TrustTier name: "totally safe"`)

	tt, err = TrustTierFromAny(UnrecognizedHardwareClaim)
	require.NoError(t, err)
	assert.Equal(t, TrustTierContraindicated, *tt)

	tt, err = TrustTierFromAny(TrustTierContraindicated)
	require.NoError(t, err)
	assert.Equal(t, TrustTierContraindicated, *tt)

	taff := TrustTierAffirming
	tt, err = TrustTierFromAny(&taff)
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)
}
