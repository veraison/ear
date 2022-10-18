// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
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
		_, err := tv.ar.ToJSON()
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestFromJSON_fail(t *testing.T) {
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
			expected: `json: cannot unmarshal array into Go value of type ar4si.AttestationResult`,
		},
		{
			ar:       `{}`,
			expected: `missing mandatory 'eat_profile', 'status', 'iat'`,
		},
	}

	for i, tv := range tvs {
		var ar AttestationResult

		err := ar.FromJSON([]byte(tv.ar))
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestVerify_pass(t *testing.T) {
	tvs := []string{
		// ok
		`eyJhbGciOiJFUzI1NiJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbS92ZXJhaXNvbi9hcjRzaSwyMDIyLTEwLTE3IiwiaWF0IjoxNjY2MDkxMzczLCJlYXIuYXBwcmFpc2FsLXBvbGljeS1pZCI6Imh0dHBzOi8vdmVyYWlzb24uZXhhbXBsZS9wb2xpY3kvMS82MGEwMDY4ZCIsInZlcmFpc29uLnByb2Nlc3NlZC1ldmlkZW5jZSI6eyJrMSI6InYxIiwiazIiOiJ2MiJ9LCJ2ZXJhaXNvbi52ZXJpZmllci1hZGRlZC1jbGFpbXMiOnsiYmFyIjoiYmF6IiwiZm9vIjoiYmFyIn19.vo2KoisD9Bf18z7oymoS0Ty2ekurZiGti62-jn10jSMNfvGZQBjr9mFe1AroHzpjLBSzYfvXk6xlKf0domS3yQ`,
		// ok with trailing stuff (ignored)
		`eyJhbGciOiJFUzI1NiJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbS92ZXJhaXNvbi9hcjRzaSwyMDIyLTEwLTE3IiwiaWF0IjoxNjY2MDkxMzczLCJlYXIuYXBwcmFpc2FsLXBvbGljeS1pZCI6Imh0dHBzOi8vdmVyYWlzb24uZXhhbXBsZS9wb2xpY3kvMS82MGEwMDY4ZCIsInZlcmFpc29uLnByb2Nlc3NlZC1ldmlkZW5jZSI6eyJrMSI6InYxIiwiazIiOiJ2MiJ9LCJ2ZXJhaXNvbi52ZXJpZmllci1hZGRlZC1jbGFpbXMiOnsiYmFyIjoiYmF6IiwiZm9vIjoiYmFyIn19.vo2KoisD9Bf18z7oymoS0Ty2ekurZiGti62-jn10jSMNfvGZQBjr9mFe1AroHzpjLBSzYfvXk6xlKf0domS3yQ.trailing-rubbish-is-ignored`,
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	for _, tv := range tvs {
		var ar AttestationResult

		err := ar.Verify([]byte(tv), jwa.ES256, k)
		assert.NoError(t, err)
		assert.Equal(t, testAttestationResultsWithVeraisonExtns, ar)
	}
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
			expected: `failed parsing JWT payload: missing mandatory 'eat_profile', 'status', 'iat'`,
		},
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	for i, tv := range tvs {
		var ar AttestationResult

		err := ar.Verify([]byte(tv.token), jwa.ES256, k)
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
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
