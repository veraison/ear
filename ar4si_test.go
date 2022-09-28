// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
	"testing"
	"time"

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

	testStatus    = TrustTierAffirming
	testTimestamp = time.Date(2022, 9, 26, 17, 29, 0, 0, time.UTC)
	testPolicyID  = "https://veraison.example/policy/1/60a0068d"

	testAttestationResultsWithVeraisonExtns = AttestationResult{
		Status:            &testStatus,
		Timestamp:         &testTimestamp,
		AppraisalPolicyID: &testPolicyID,
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
			expected: `missing mandatory field(s): 'status', 'timestamp'`,
		},
		{
			ar: AttestationResult{
				Status: &testStatus,
			},
			expected: `missing mandatory field(s): 'timestamp'`,
		},
		{
			ar: AttestationResult{
				Timestamp: &testTimestamp,
			},
			expected: `missing mandatory field(s): 'status'`,
		},
	}

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
			expected: `missing mandatory field(s): 'status', 'timestamp'`,
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
		`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.Dv3PqGA2W8anXne0YZs8cvIhQhNF1Su1RS83RPzDVg4OhJFNN1oSF-loDpjfIwPdzCWt0eA6JYxSMqpGiemq-Q`,
		// ok with trailing stuff (ignored)
		`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhZmZpcm1pbmciLCJ0aW1lc3RhbXAiOiIyMDIyLTA5LTI2VDE3OjI5OjAwWiIsImFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQiLCJ2ZXJhaXNvbi5wcm9jZXNzZWQtZXZpZGVuY2UiOnsiazEiOiJ2MSIsImsyIjoidjIifSwidmVyYWlzb24udmVyaWZpZXItYWRkZWQtY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fQ.Dv3PqGA2W8anXne0YZs8cvIhQhNF1Su1RS83RPzDVg4OhJFNN1oSF-loDpjfIwPdzCWt0eA6JYxSMqpGiemq-Q.trailing-rubbish-is-ignored`,
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
			expected: `failed parsing JWT payload: missing mandatory field(s): 'status', 'timestamp'`,
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
	assert.EqualError(t, err, `missing mandatory field(s): 'status', 'timestamp'`)
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
	// of specific verification errors and this is the reason why below we
	// use ErrorContains rather than EqualError.
	token[len(token)-1] ^= 1

	err = actual.Verify(token, jwa.ES256, vfyK)
	assert.ErrorContains(t, err, "failed verifying JWT message")
}
