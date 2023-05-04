// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"
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

	testVidBuild     = "rrtrap-v1.0.0"
	testVidDeveloper = "Acme Inc."

	testStatus     = TrustTierAffirming
	testIAT        = int64(1666091373)
	testPolicyID   = "policy://test/01234"
	testVerifierID = VerifierIdentity{
		Build:     &testVidBuild,
		Developer: &testVidDeveloper,
	}
	testProfile            = EatProfile
	testUnsupportedProfile = "1.2.3.4.5"
	testNonce              = "0123456789abcdef"
	testBadNonce           = "1337"
	testEvidenceID         = "405e0c3127e455ebc22361210b43ca9499ca80d3f6b1dc79b89fa35290cee3d9"
	testEvidence           = []byte("evidence")
	testTeeName            = "aws-nitro"

	testAttestationResultsWithVeraisonExtns = AttestationResult{
		IssuedAt:   &testIAT,
		VerifierID: &testVerifierID,
		Profile:    &testProfile,
		Submods: map[string]*Appraisal{
			"test": {
				Status:            &testStatus,
				AppraisalPolicyID: &testPolicyID,
				AppraisalExtensions: AppraisalExtensions{
					VeraisonPolicyClaims: &map[string]interface{}{
						"foo": "bar",
						"bar": "baz",
					},
					VeraisonAnnotatedEvidence: &map[string]interface{}{
						"k1": "v1",
						"k2": "v2",
					},
					VeraisonKeyAttestation: &map[string]interface{}{
						"akpub": "YWtwdWIK",
					},
				},
			},
		},
	}
)

func TestToJSON_fail(t *testing.T) {
	testTrustTier := TrustTierAffirming

	tvs := []struct {
		ar       AttestationResult
		expected string
	}{
		{
			ar:       AttestationResult{},
			expected: `missing mandatory 'eat_profile', 'iat', 'verifier-id', 'submods' (at least one appraisal must be present)`,
		},
		{
			ar: AttestationResult{
				Submods: map[string]*Appraisal{},
			},
			expected: `missing mandatory 'eat_profile', 'iat', 'verifier-id', 'submods' (at least one appraisal must be present)`,
		},
		{
			ar: AttestationResult{
				IssuedAt: &testIAT,
				Submods: map[string]*Appraisal{
					"test": {},
				},
			},
			expected: `missing mandatory 'eat_profile', 'verifier-id'; invalid value(s) for submods[test]: missing mandatory 'ear.status'`,
		},
		{
			ar: AttestationResult{
				Profile: &testProfile,
				Submods: map[string]*Appraisal{
					"test": {Status: &testTrustTier},
				},
			},
			expected: `missing mandatory 'iat', 'verifier-id'`,
		},
		{
			ar: AttestationResult{
				Profile: &testUnsupportedProfile,
				Submods: map[string]*Appraisal{
					"test": {Status: &testTrustTier},
				},
			},
			expected: `missing mandatory 'iat', 'verifier-id'; invalid value(s) for eat_profile (1.2.3.4.5)`,
		},
		{
			ar: AttestationResult{
				IssuedAt:   &testIAT,
				Profile:    &testProfile,
				VerifierID: &testVerifierID,
				Nonce:      &testBadNonce,
				Submods: map[string]*Appraisal{
					"test": {Status: &testTrustTier},
				},
			},
			expected: `invalid value(s) for eat_nonce (4 bytes)`,
		},
	}

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
			expected: `missing mandatory 'eat_profile', 'ear.verifier-id', 'iat', 'submods'`,
		},
	}

	for i, tv := range tvs {
		var ar AttestationResult

		err := ar.UnmarshalJSON([]byte(tv.ar))
		assert.EqualError(t, err, tv.expected, "failed test vector at index %d", i)
	}
}

func TestVerify_pass(t *testing.T) {
	tvs := []struct {
		token    string
		expected AttestationResult
	}{
		{
			token:    `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmdpdGh1Yi5jb20sMjAyMzp2ZXJhaXNvbi9lYXIiLCJpYXQiOjE2NjYwOTEzNzMsInN1Ym1vZHMiOnsidGVzdCI6eyJlYXIuYXBwcmFpc2FsLXBvbGljeS1pZCI6InBvbGljeTovL3Rlc3QvMDEyMzQiLCJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWFyLnZlcmFpc29uLmFubm90YXRlZC1ldmlkZW5jZSI6eyJrMSI6InYxIiwiazIiOiJ2MiJ9LCJlYXIudmVyYWlzb24ua2V5LWF0dGVzdGF0aW9uIjp7ImFrcHViIjoiWVd0d2RXSUsifSwiZWFyLnZlcmFpc29uLnBvbGljeS1jbGFpbXMiOnsiYmFyIjoiYmF6IiwiZm9vIjoiYmFyIn19fX0.gTuJrH5Ctf6sAXlaFu1NvHAtI4H0iSqsp2ZtxPPhSfZJBkyeWmZi62lTBw644JDRI0DY9X7Wk7CBWWE6dmBVAA`,
			expected: testAttestationResultsWithVeraisonExtns,
		},
	}

	k, err := jwk.ParseKey([]byte(testECDSAPublicKey))
	require.NoError(t, err)

	for i, tv := range tvs {
		var ar AttestationResult

		err := ar.Verify([]byte(tv.token), jwa.ES256, k)
		assert.NoError(t, err, "failed test vector at index %d", i)
		assert.Equal(t, tv.expected, ar)
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
			expected: `missing mandatory 'eat_profile', 'ear.verifier-id', 'submods'`,
		},
		{
			// empty attestation results
			token:    `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmdpdGh1Yi5jb20sMjAyMzp2ZXJhaXNvbi9lYXIiLCJpYXQiOjEuNjY2MDkxMzczZSswOSwianRpIjoiMTY1Zjg0YzY3YzE0ZTEwZDFlNGI0MzM0MDgzY2IyYTIxZDI2YmYxN2FhNjBkNWU5ZGE5ZDhmNzE3NmFjNWI2MyIsIm5iZiI6MTY3NjQ3MjcwOSwic3VibW9kcyI6eyJ0ZXN0Ijp7ImVhci5hcHByYWlzYWwtcG9saWN5LWlkIjoicG9saWN5Oi8vdGVzdC8wMTIzNCIsImVhci5zdGF0dXMiOiJhZmZpcm1pbmciLCJlYXIudmVyYWlzb24uYW5ub3RhdGVkLWV2aWRlbmNlIjp7ImsxIjoidjEiLCJrMiI6InYyIn0sImVhci52ZXJhaXNvbi5wb2xpY3ktY2xhaW1zIjp7ImJhciI6ImJheiIsImZvbyI6ImJhciJ9fX19.LunlKAnUiVHZxIUr7jNnrwFlRtd7t6f6W1rzIFgcWFLdtJELKIVGkPVV5PriHh8T0uLLIEJafwvi6hmIr27aDw.trailing-rubbish`,
			expected: `failed to parse token: invalid character 'e' looking for beginning of value`,
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
	assert.EqualError(t, err, `missing mandatory 'eat_profile', 'iat', 'verifier-id', 'submods' (at least one appraisal must be present)`)
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
	ar := NewAttestationResult("test", "test", "test")

	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierNone, *ar.Submods["test"].Status)

	ar.Submods["test"].TrustVector.Configuration = ApprovedConfigClaim
	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierAffirming, *ar.Submods["test"].Status)

	*ar.Submods["test"].Status = TrustTierWarning
	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierWarning, *ar.Submods["test"].Status)

	ar.Submods["test"].TrustVector.Configuration = UnsupportableConfigClaim
	ar.UpdateStatusFromTrustVector()
	assert.Equal(t, TrustTierContraindicated, *ar.Submods["test"].Status)
}

func TestAsMap(t *testing.T) {
	policyID := "foo"

	ar := NewAttestationResult("someScheme", "test", "test")
	status := NewTrustTier(TrustTierAffirming)
	ar.Submods["someScheme"].Status = status
	ar.Submods["someScheme"].TrustVector.Executables = ApprovedRuntimeClaim
	ar.Submods["someScheme"].AppraisalPolicyID = &policyID
	ar.Nonce = &testNonce

	expected := map[string]interface{}{
		"submods": map[string]interface{}{
			"someScheme": map[string]interface{}{
				"ear.status": *status,
				"ear.trustworthiness-vector": map[string]interface{}{
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
			},
		},
		"eat_profile": EatProfile,
		"eat_nonce":   testNonce,
	}

	m := ar.AsMap()
	for _, field := range []string{
		"submods",
		"eat_profile",
		"ear.appraisal-policy-id",
	} {
		assert.Equal(t, expected[field], m[field])
	}
}

func Test_populateFromMap(t *testing.T) {
	var ar AttestationResult
	m := map[string]interface{}{
		"submods": map[string]interface{}{
			"test": map[string]interface{}{
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
				"ear.appraisal-policy-id": "foo",
			},
		},
		"ear.raw-evidence": "SSBkaWRuJ3QgZG8gaXQ",
		"iat":              1234,
		"eat_profile":      EatProfile,
		"ear.verifier-id": map[string]interface{}{
			"build":     "rrtrap-v1.0.0",
			"developer": "Acme Inc.",
		},
	}

	err := ar.populateFromMap(m)
	assert.NoError(t, err)
	assert.Equal(t, TrustTierAffirming, *ar.Submods["test"].Status)
	assert.Equal(t, EatProfile, *ar.Profile)
}

func TestTrustTier_ColorString(t *testing.T) {
	assert.Equal(t, "\\033[47mnone\\033[0m", TrustTierNone.ColorString())
	assert.Equal(t, "\\033[42maffirming\\033[0m", TrustTierAffirming.ColorString())
	assert.Equal(t, "\\033[43mwarning\\033[0m", TrustTierWarning.ColorString())
	assert.Equal(t, "\\033[41mcontraindicated\\033[0m", TrustTierContraindicated.ColorString())
}

func TestNewAttestationResult(t *testing.T) {
	ar := NewAttestationResult("test", "testBuild", "testDev")

	_, err := ar.MarshalJSON()
	assert.NoError(t, err)

	assert.Equal(t, "testBuild", *ar.VerifierID.Build)
	assert.Equal(t, "testDev", *ar.VerifierID.Developer)
}
