// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
)

// digest value used in the draft-ietf-rats-ear-06 examples
var testDigestValue, _ = hex.DecodeString(
	"4c89eb4a5cec6b3f637cbeda6e0bc9daba28d8ff77268cecb77c77394fda7cd8",
)

func TestDigest_JSON(t *testing.T) {
	var d Digest
	require.NoError(t, json.Unmarshal(
		[]byte(`["sha-256","TInrSlzsaz9jfL7abgvJ2roo2P93Jozst3x3OU_afNg"]`), &d,
	))
	assert.Equal(t, Digest{Alg: eat.IntOrStringFromString("sha-256"), Value: testDigestValue}, d)

	data, err := json.Marshal(d)
	require.NoError(t, err)
	assert.JSONEq(t, `["sha-256","TInrSlzsaz9jfL7abgvJ2roo2P93Jozst3x3OU_afNg"]`, string(data))

	require.NoError(t, json.Unmarshal(
		[]byte(`[1,"TInrSlzsaz9jfL7abgvJ2roo2P93Jozst3x3OU_afNg="]`), &d,
	))
	assert.Equal(t, Digest{Alg: eat.IntOrStringFromInt(1), Value: testDigestValue}, d)

	assert.ErrorContains(t, json.Unmarshal([]byte(`{}`), &d), "cannot unmarshal")
	assert.EqualError(t, json.Unmarshal([]byte(`[1]`), &d), "expected a two-element list, got []interface {}")
	assert.EqualError(t, json.Unmarshal([]byte(`[1,"!"]`), &d), "value: illegal base64 data at input byte 0")
	assert.EqualError(t, json.Unmarshal([]byte(`[1,2]`), &d), "value: expected bytes or string, got float64")
	assert.EqualError(t, json.Unmarshal([]byte(`[[],"AA"]`), &d), "alg: cannot convert [] ([]interface {}) to IntOrString")
	assert.EqualError(t, json.Unmarshal([]byte(`[1,"AA"]`), &d), "value length 1 does not match sha-256 (32)")

	_, err = json.Marshal(Digest{})
	assert.ErrorContains(t, err, "missing alg")
}

func TestDigest_CBOR(t *testing.T) {
	d := Digest{Alg: eat.IntOrStringFromInt(1), Value: testDigestValue}

	data, err := em.Marshal(d)
	require.NoError(t, err)

	expected := append([]byte{0x82, 0x01, 0x58, 0x20}, testDigestValue...)
	assert.Equal(t, expected, data)

	var decoded Digest
	require.NoError(t, dm.Unmarshal(data, &decoded))
	assert.Equal(t, d, decoded)

	// [1, "AA"]: value must be a byte string in CBOR
	assert.EqualError(t, dm.Unmarshal([]byte{0x82, 0x01, 0x62, 0x41, 0x41}, &decoded), "value: expected bytes, got string")
	assert.Error(t, dm.Unmarshal([]byte{0xa0}, &decoded))

	_, err = em.Marshal(Digest{Alg: eat.IntOrStringFromInt(1)})
	assert.ErrorContains(t, err, "empty value")
}

func TestNewDigest(t *testing.T) {
	input := []byte("appraisal request")
	sum := sha256.Sum256(input)

	d, err := NewDigest(crypto.SHA256, input)
	require.NoError(t, err)
	assert.Equal(t, &Digest{Alg: eat.IntOrStringFromInt(1), Value: sum[:]}, d)
	assert.NoError(t, d.Verify(input))
	assert.EqualError(t, d.Verify([]byte("tampered")), "digest mismatch")

	for _, h := range []crypto.Hash{
		crypto.SHA384, crypto.SHA512,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	} {
		d, err := NewDigest(h, input)
		require.NoError(t, err, h.String())
		assert.NoError(t, d.Verify(input), h.String())
	}

	_, err = NewDigest(crypto.MD5, input)
	assert.EqualError(t, err, "unsupported hash function MD5")

	truncated := Digest{Alg: eat.IntOrStringFromString("sha-256-128"), Value: sum[:16]}
	assert.NoError(t, truncated.Verify(input))

	unknown := Digest{Alg: eat.IntOrStringFromInt(-16), Value: sum[:]}
	assert.NoError(t, unknown.Validate())
	assert.EqualError(t, unknown.Verify(input), `unsupported hash algorithm "-16"`)
}

func TestDigestFromAny(t *testing.T) {
	d := Digest{Alg: eat.IntOrStringFromInt(1), Value: testDigestValue}

	ret, err := DigestFromAny(d)
	require.NoError(t, err)
	assert.Equal(t, &d, ret)

	ret, err = DigestFromAny(&d)
	require.NoError(t, err)
	assert.Equal(t, &d, ret)

	ret, err = DigestFromAny([]any{uint64(1), testDigestValue})
	require.NoError(t, err)
	assert.Equal(t, &d, ret)

	_, err = DigestFromAny((*Digest)(nil))
	assert.EqualError(t, err, "nil pointer")
}

func TestAttestationResult_InputDigest(t *testing.T) {
	input := []byte("appraisal request")
	digest, err := NewDigest(crypto.SHA256, input)
	require.NoError(t, err)

	result := AttestationResult{
		Profile:     EatProfile,
		IssuedAt:    testIAT,
		VerifierID:  &testVerifierID,
		Submods:     NewSubmods().AddAppraisal("test", &Appraisal{Status: TrustTierAffirming, Extensions: NewExtensions()}),
		InputDigest: digest,
		Extensions:  NewExtensions(),
	}

	data, err := result.MarshalJSON()
	require.NoError(t, err)

	var fromJSON AttestationResult
	require.NoError(t, fromJSON.UnmarshalJSON(data))
	assert.Equal(t, &result, &fromJSON)
	assert.NoError(t, fromJSON.VerifyInputDigest(input))
	assert.EqualError(t, fromJSON.VerifyInputDigest([]byte("x")), "ear_input_digest: digest mismatch")

	var claims map[string]any
	require.NoError(t, json.Unmarshal(data, &claims))
	fromAny, err := AttestationResultFromAny(claims)
	require.NoError(t, err)
	assert.Equal(t, &result, fromAny)

	claims["ear_input_digest"] = []any{1}
	_, err = AttestationResultFromAny(claims)
	assert.EqualError(t, err, "ear_input_digest: expected a two-element list, got []interface {}")

	data, err = result.MarshalCBOR()
	require.NoError(t, err)

	var fromCBOR AttestationResult
	require.NoError(t, fromCBOR.UnmarshalCBOR(data))
	assert.Equal(t, &result, &fromCBOR)

	result.InputDigest = &Digest{Alg: eat.IntOrStringFromInt(1)}
	assert.ErrorContains(t, result.Validate(), "invalid value(s) for ear_input_digest (empty value)")

	result.InputDigest = nil
	assert.EqualError(t, result.VerifyInputDigest(input), "ear_input_digest not present")
}
