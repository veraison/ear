// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"
	"math"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testECDSAPublicKey = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
		"y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
	}`

	testECDSAPrivateKey = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
		"y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
		"d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
	}`

	testStatus             = TrustTierAffirming
	testIAT                = int64(1666091373)
	testPolicyID           = "https://veraison.example/policy/1/60a0068d"
	testProfile            = EatProfile
	testUnsupportedProfile = "1.2.3.4.5"

	testAttestationResultsWithVeraisonExtns = AttestationResult{
		Status:            &testStatus,
		IssuedAt:          &testIAT,
		AppraisalPolicyID: &testPolicyID,
		Profile:           &testProfile,
		Extensions: Extensions{
			VeraisonVerifierAddedClaims: &map[string]interface{}{
				"foo": "bar",
				"bar": "baz",
			},
			VeraisonProcessedEvidence: &map[string]interface{}{
				"k1": "v1",
				"k2": "v2",
			},
		},
	}
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

	tt, err = ToTrustTier(2)
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)

	tt, err = ToTrustTier(2.5)
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)

	_, err = ToTrustTier(3.1)
	assert.ErrorContains(t, err, "not a valid TrustTier value: 3.100000 (3)")

	_, err = ToTrustTier(math.MaxFloat32)
	assert.ErrorContains(t, err, "not a valid TrustTier value: 34028234")

	tt, err = ToTrustTier(int8(32))
	require.NoError(t, err)
	assert.Equal(t, TrustTierWarning, *tt)

	_, err = ToTrustTier(uint64(math.MaxUint64))
	assert.ErrorContains(t, err,
		fmt.Sprintf("not a valid TrustTier value: %d", uint64(math.MaxUint64)))

	tt, err = ToTrustTier("affirming")
	require.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *tt)

	tt, err = ToTrustTier("96")
	require.NoError(t, err)
	assert.Equal(t, TrustTierContraindicated, *tt)

	tt, err = ToTrustTier([]byte{0x33, 0x32}) // "32"
	require.NoError(t, err)
	assert.Equal(t, TrustTierWarning, *tt)

	_, err = ToTrustTier("totally safe")
	assert.ErrorContains(t, err, `not a valid TrustTier name: "totally safe"`)

	tt, err = ToTrustTier(UnrecognizedHardwareClaim)
	require.NoError(t, err)
	assert.Equal(t, TrustTierContraindicated, *tt)
}

func TestToJSON_fail(t *testing.T) {
	tvs := []struct {
		ar       AttestationResult
		expected string
	}{
		{
			ar:       AttestationResult{},
			expected: `missing mandatory 'eat_profile', 'status', 'iat'`,
		},
		{
			ar: AttestationResult{
				Status: &testStatus,
			},
			expected: `missing mandatory 'eat_profile', 'iat'`,
		},
		{
			ar: AttestationResult{
				IssuedAt: &testIAT,
			},
			expected: `missing mandatory 'eat_profile', 'status'`,
		},
		{
			ar: AttestationResult{
				Profile: &testProfile,
			},
			expected: `missing mandatory 'status', 'iat'`,
		},
		{
			ar: AttestationResult{
				Status:  &testStatus,
				Profile: &testUnsupportedProfile,
			},
			expected: `missing mandatory 'iat'; invalid value(s) for eat_profile (1.2.3.4.5)`,
		}}

	for i, tv := range tvs {
		_, err := tv.ar.MarshalJSON()
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestUnmarshalJSON_fail(t *testing.T) {
	tvs := []struct {
		ar       string
		expected string
	}{
		{
			ar:       `{`,
			expected: `unexpected end of JSON input`,
		},
		{
			ar:       `[]`,
			expected: `json: cannot unmarshal array into Go value of type map[string]interface {}`,
		},
		{
			ar:       `{}`,
			expected: `missing mandatory 'ear.status', 'eat_profile', 'iat'`,
		},
	}

	for i, tv := range tvs {
		var ar AttestationResult

		err := ar.UnmarshalJSON([]byte(tv.ar))
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestVerify_pass(t *testing.T) {
	tvs := []string{
		// ok
		`eyJhbGciOiJFUzI1NiJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIyOnZlcmFpc29uL2VhciIsImlhdCI6MTY2NjA5MTM3MywiZWFyLmFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJlYXIudmVyYWlzb24ucHJvY2Vzc2VkLWV2aWRlbmNlIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhci52ZXJhaXNvbi52ZXJpZmllci1hZGRlZC1jbGFpbXMiOnsiYmFyIjoiYmF6IiwiZm9vIjoiYmFyIn19.P0yB2s_DmCQ7DSX2pOnyKbNMVCfTrqkxohWrDxwBdKqOMrrXoCYJmWlpgwtHV-AA56NXMRObeZk9zT_0TlPgpQ`,
		// trailing stuff means the format is no longer valid.
		`eyJhbGciOiJFUzI1NiJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIyOnZlcmFpc29uL2VhciIsImlhdCI6MTY2NjA5MTM3MywiZWFyLmFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJlYXIudmVyYWlzb24ucHJvY2Vzc2VkLWV2aWRlbmNlIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhci52ZXJhaXNvbi52ZXJpZmllci1hZGRlZC1jbGFpbXMiOnsiYmFyIjoiYmF6IiwiZm9vIjoiYmFyIn19.P0yB2s_DmCQ7DSX2pOnyKbNMVCfTrqkxohWrDxwBdKqOMrrXoCYJmWlpgwtHV-AA56NXMRObeZk9zT_0TlPgpQ.trailing-rubbish`,
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	var ar AttestationResult

	err = ar.Verify([]byte(tvs[0]), jwa.ES256, k)
	assert.NoError(t, err)
	assert.Equal(t, testAttestationResultsWithVeraisonExtns, ar)

	var ar2 AttestationResult
	err = ar2.Verify([]byte(tvs[1]), jwa.ES256, k)
	assert.ErrorContains(t, err, "failed to parse token: invalid character 'e' looking for beginning of value")
}

func TestVerify_fail(t *testing.T) {
	tvs := []struct {
		token    string
		expected string
	}{
		{
			// non-matching alg (HS256)
			token:    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.Dv3PqGA2W8anXne0YZs8cvIhQhNF1Su1RS83RPzDVg4OhJFNN1oSF-loDpjfIwPdzCWt0eA6JYxSMqpGiemq-Q`,
			expected: `failed verifying JWT message: could not verify message using any of the signatures or keys`,
		},
		{
			// alg "none"
			token:    `eyJhbGciOiJub25lIn0.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.`,
			expected: `failed verifying JWT message: could not verify message using any of the signatures or keys`,
		},
		{
			// bad JWT formatting
			token:    `.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.Dv3PqGA2W8anXne0YZs8cvIhQhNF1Su1RS83RPzDVg4OhJFNN1oSF-loDpjfIwPdzCWt0eA6JYxSMqpGiemq-Q`,
			expected: `failed verifying JWT message: failed to parse jws: failed to parse JOSE headers: EOF`,
		},
		{
			// empty attestation results
			token:    `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.9Tvx3hVBNfkmVXTndrVfv9ZeNJgX59w0JpR2vyjUn8lGxL8VT7OggUeYSYFnxrouSi2TusNh61z8rLdOqxGA-A`,
			expected: `missing mandatory 'ear.status', 'eat_profile'`,
		},
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	for i, tv := range tvs {
		var ar AttestationResult

		err := ar.Verify([]byte(tv.token), jwa.ES256, k)
		assert.ErrorContains(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestSign_fail(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	// an empty AR is not a valid AR4SI payload
	var ar AttestationResult

	_, err = ar.Sign(jwa.ES256, sigK)
	assert.EqualError(t, err, `missing mandatory 'eat_profile', 'status', 'iat'`)
}

func TestRoundTrip_pass(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	token, err := testAttestationResultsWithVeraisonExtns.Sign(jwa.ES256, sigK)
	assert.NoError(t, err)

	fmt.Println(string(token))

	vfyK, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	var actual AttestationResult

	err = actual.Verify(token, jwa.ES256, vfyK)
	assert.NoError(t, err)

	assert.Equal(t, testAttestationResultsWithVeraisonExtns, actual)
}

func TestRoundTrip_tampering(t *testing.T) {
	sigK, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	token, err := testAttestationResultsWithVeraisonExtns.Sign(jwa.ES256, sigK)
	assert.NoError(t, err)

	vfyK, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	var actual AttestationResult

	// Tamper with the signature.
	// Note that since ES256 is randomized, this could result in different kinds
	// of verification errors. Therefore we have to use ErrorContains rather
	// than EqualError.
	token[len(token)-1] ^= 1

	err = actual.Verify(token, jwa.ES256, vfyK)
	assert.ErrorContains(t, err, "failed verifying JWT message")
}

func TestUpdateStatusFromTrustVector(t *testing.T) {
	ar := NewAttestationResult()

	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierNone, *ar.Status)

	ar.TrustVector.Configuration = ApprovedConfigClaim
	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierAffirming, *ar.Status)

	*ar.Status = TrustTierWarning
	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierWarning, *ar.Status)

	ar.TrustVector.Configuration = UnsupportableConfigClaim
	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierContraindicated, *ar.Status)
}

func TestAsMap(t *testing.T) {
	policyID := "foo"

	ar := NewAttestationResult()
	status := NewTrustTier(TrustTierAffirming)
	ar.Status = status
	ar.TrustVector.Executables = ApprovedRuntimeClaim
	ar.AppraisalPolicyID = &policyID

	expected := map[string]interface{}{
		"ear.status": *status,
		"ear.trustworthiness-vector": map[string]TrustClaim{
			"instance-identity": NoClaim,
			"configuration":     NoClaim,
			"executables":       ApprovedRuntimeClaim,
			"file-system":       NoClaim,
			"hardware":          NoClaim,
			"runtime-opaque":    NoClaim,
			"storage-opaque":    NoClaim,
			"sourced-data":      NoClaim,
		},
		"ear.appraisal-policy-id": "foo",
		"eat_profile":             EatProfile,
	}

	m := ar.AsMap()
	for _, field := range []string{
		"ear.status",
		"ear.trustworthiness-vector",
		"eat_profile",
		"ear.appraisal-policy-id",
	} {
		assert.Equal(t, expected[field], m[field])
	}
}

func Test_populateFromMap(t *testing.T) {
	var ar AttestationResult
	m := map[string]interface{}{
		"ear.status": 2,
		"ear.trustworthiness-vector": map[string]interface{}{
			"instance-identity": 0,
			"configuration":     0,
			"executables":       2,
			"file-system":       0,
			"hardware":          0,
			"runtime-opaque":    0,
			"storage-opaque":    0,
			"sourced-data":      0,
		},
		"ear.raw-evidence":        "SSBkaWRuJ3QgZG8gaXQ",
		"ear.appraisal-policy-id": "foo",
		"iat":                     1234,
		"eat_profile":             EatProfile,
	}

	err := ar.populateFromMap(m)
	assert.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *ar.Status)
	assert.Equal(t, EatProfile, *ar.Profile)
}

func TestTrustTier_ColorString(t *testing.T) {
	assert.Equal(t, "\\033[47mnone\\033[0m", TrustTierNone.ColorString())
	assert.Equal(t, "\\033[42maffirming\\033[0m", TrustTierAffirming.ColorString())
	assert.Equal(t, "\\033[43mwarning\\033[0m", TrustTierWarning.ColorString())
	assert.Equal(t, "\\033[41mcontraindicated\\033[0m", TrustTierContraindicated.ColorString())
}
