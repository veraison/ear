// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ranges = map[string][]int8{
		"none": {
			-1, 0, 1,
		},
		"affirming": {
			// negative
			-32, -31, -30, -29, -28, -27, -26, -25, -24, -23, -22, -21, -20,
			-19, -18, -17, -16, -15, -14, -13, -12, -11, -10, -9, -8, -7, -6,
			-5, -4, -3, -2,
			// positive
			2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		},
		"warning": {
			// negative
			-96, -95, -94, -93, -92, -91, -90, -89, -88, -87, -86, -85, -84,
			-83, -82, -81, -80, -79, -78, -77, -76, -75, -74, -73, -72, -71,
			-70, -69, -68, -67, -66, -65, -64, -63, -62, -61, -60, -59, -58,
			-57, -56, -55, -54, -53, -52, -51, -50, -49, -48, -47, -46, -45,
			-44, -43, -42, -41, -40, -39, -38, -37, -36, -35, -34, -33,
			// positive
			32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
			49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
			66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
			83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
		},
		"contraindicated": {
			// negative
			-128, -127, -126, -125, -124, -123, -122, -121, -120, -119, -118,
			-117, -116, -115, -114, -113, -112, -111, -110, -109, -108, -107,
			-106, -105, -104, -103, -102, -101, -100, -99, -98, -97,
			// positive
			96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
			110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
			123, 124, 125, 126, 127,
		},
	}
)

func TestTrustClaim_TrustTier_entire_range(t *testing.T) {
	for s, a := range ranges {
		for _, i := range a {
			assert.Equal(t, s, TrustClaim(i).GetTier().String(), "enum: %d", i)
		}
	}
}

func TestToTrustClaim(t *testing.T) {
	v, err := ToTrustClaim(32)
	require.NoError(t, err)
	assert.Equal(t, UnsafeRuntimeClaim, *v)

	_, err = ToTrustClaim(512)
	assert.ErrorContains(t, err, "out of range for TrustClaim: 512")

	v, err = ToTrustClaim("2")
	require.NoError(t, err)
	assert.Equal(t, TrustClaim(2), *v)

	v, err = ToTrustClaim("unsafe_hw")
	require.NoError(t, err)
	assert.Equal(t, TrustClaim(32), *v)

	v, err = ToTrustClaim("ApprovedFS")
	require.NoError(t, err)
	assert.Equal(t, ApprovedFilesClaim, *v)

	v, err = ToTrustClaim("CRYPTO-FAILED")
	require.NoError(t, err)
	assert.Equal(t, CryptoValidationFailedClaim, *v)

	v, err = ToTrustClaim("Trusted Sources")
	require.NoError(t, err)
	assert.Equal(t, TrustedSourcesClaim, *v)

	v, err = ToTrustClaim(TrustedSourcesClaim)
	require.NoError(t, err)
	assert.Equal(t, TrustedSourcesClaim, *v)

	tc := VerifierMalfunctionClaim
	v, err = ToTrustClaim(&tc)
	require.NoError(t, err)
	assert.Equal(t, VerifierMalfunctionClaim, *v)

	n := json.Number("-1")
	v, err = ToTrustClaim(n)
	require.NoError(t, err)
	assert.Equal(t, VerifierMalfunctionClaim, *v)

	_, err = ToTrustClaim("512")
	assert.ErrorContains(t, err, "out of range for TrustClaim: 512")

	_, err = getTrustClaimFromString("Bogus Claim")
	assert.ErrorContains(t, err, `not a valid TrustClaim value: "Bogus Claim"`)
}

func TestTrustClaim_GetTier(t *testing.T) {
	assert.Equal(t, TrustTierNone, VerifierMalfunctionClaim.GetTier())
	assert.Equal(t, TrustTierAffirming, ApprovedBootClaim.GetTier())
	assert.Equal(t, TrustTierWarning, UnsafeConfigClaim.GetTier())
	assert.Equal(t, TrustTierContraindicated, UnsupportableConfigClaim.GetTier())
}
