// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
)

// SubjectPublicKeyInfo and its SHA-256 digest from the
// draft-ietf-rats-ear-06 examples
const testSPKIb64u = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9-9Ue6GnvHw_GW2ZZaVtszggXIw"

var (
	testSPKI, _       = base64.RawURLEncoding.DecodeString(testSPKIb64u)
	testSPKIDigest, _ = hex.DecodeString("51b944cdfa544d4c3273aa6bf350625a7dd53bbb6a71723274f538b19a207760")
)

func TestTransportIdentityKey_SPKI(t *testing.T) {
	key, err := NewTransportIdentityKeyFromSPKI(testSPKI)
	require.NoError(t, err)

	data, err := json.Marshal(key)
	require.NoError(t, err)
	assert.Equal(t, `"`+testSPKIb64u+`"`, string(data))

	var fromJSON TransportIdentityKey
	require.NoError(t, json.Unmarshal(data, &fromJSON))
	assert.Equal(t, key, &fromJSON)

	data, err = em.Marshal(key)
	require.NoError(t, err)
	assert.Equal(t, append([]byte{0x58, 0x5b}, testSPKI...), data)

	var fromCBOR TransportIdentityKey
	require.NoError(t, dm.Unmarshal(data, &fromCBOR))
	assert.Equal(t, key, &fromCBOR)

	assert.NoError(t, key.Verify(testSPKI))
	assert.EqualError(t, key.Verify(testSPKI[1:]), "SubjectPublicKeyInfo mismatch")

	pub, err := key.PublicKey()
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, pub)

	fromKey, err := NewTransportIdentityKey(pub)
	require.NoError(t, err)
	assert.Equal(t, key, fromKey)

	_, err = NewTransportIdentityKey("not a key")
	assert.ErrorContains(t, err, "unable to marshal public key")
}

func TestTransportIdentityKey_digest(t *testing.T) {
	key, err := NewTransportIdentityKeyDigest(testSPKI, crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, &TransportIdentityKey{
		Digest: &Digest{Alg: eat.IntOrStringFromInt(1), Value: testSPKIDigest},
	}, key)

	data, err := em.Marshal(key)
	require.NoError(t, err)
	assert.Equal(t, append([]byte{0x82, 0x01, 0x58, 0x20}, testSPKIDigest...), data)

	var fromCBOR TransportIdentityKey
	require.NoError(t, dm.Unmarshal(data, &fromCBOR))
	assert.Equal(t, key, &fromCBOR)

	data, err = json.Marshal(key)
	require.NoError(t, err)

	var fromJSON TransportIdentityKey
	require.NoError(t, json.Unmarshal(data, &fromJSON))
	assert.Equal(t, key, &fromJSON)

	assert.NoError(t, key.Verify(testSPKI))
	assert.EqualError(t, key.Verify(testSPKI[1:]), "digest mismatch")

	_, err = key.PublicKey()
	assert.EqualError(t, err, "no SubjectPublicKeyInfo")

	_, err = NewTransportIdentityKeyDigest(nil, crypto.SHA256)
	assert.EqualError(t, err, "empty SubjectPublicKeyInfo")

	_, err = NewTransportIdentityKeyDigest(testSPKI, crypto.MD5)
	assert.EqualError(t, err, "unsupported hash function MD5")
}

func TestTransportIdentityKey_invalid(t *testing.T) {
	both := TransportIdentityKey{SPKI: testSPKI, Digest: &Digest{}}
	assert.EqualError(t, both.Validate(), "both SubjectPublicKeyInfo and digest set")
	assert.EqualError(t, both.Verify(testSPKI), "both SubjectPublicKeyInfo and digest set")

	_, err := json.Marshal(TransportIdentityKey{})
	assert.ErrorContains(t, err, "empty SubjectPublicKeyInfo")

	_, err = em.Marshal(TransportIdentityKey{Digest: &Digest{}})
	assert.ErrorContains(t, err, "digest: missing alg")

	var key TransportIdentityKey
	assert.EqualError(t, json.Unmarshal([]byte(`"!"`), &key), "SubjectPublicKeyInfo: illegal base64 data at input byte 0")
	assert.EqualError(t, json.Unmarshal([]byte(`[1]`), &key), "digest: expected a two-element list, got []interface {}")
	assert.EqualError(t, json.Unmarshal([]byte(`{}`), &key), "expected SubjectPublicKeyInfo or digest, got map[string]interface {}")
	assert.Error(t, json.Unmarshal([]byte(`{`), &key))

	// text string in CBOR
	assert.EqualError(t, dm.Unmarshal([]byte{0x61, 0x41}, &key), "expected SubjectPublicKeyInfo as bytes, got string")
	// [1, "AA"] in CBOR
	assert.EqualError(t, dm.Unmarshal([]byte{0x82, 0x01, 0x62, 0x41, 0x41}, &key), "digest: value: expected bytes, got string")
	assert.Error(t, dm.Unmarshal([]byte{0xff}, &key))

	_, err = TransportIdentityKeyFromAny((*TransportIdentityKey)(nil))
	assert.EqualError(t, err, "nil pointer")

	ret, err := TransportIdentityKeyFromAny(TransportIdentityKey{SPKI: testSPKI})
	require.NoError(t, err)
	assert.Equal(t, testSPKI, ret.SPKI)
}

func TestAppraisal_TransportIdentityKey(t *testing.T) {
	appraisal := &Appraisal{
		Status:               TrustTierAffirming,
		TransportIdentityKey: &TransportIdentityKey{SPKI: testSPKI},
		Extensions:           NewExtensions(),
	}

	data, err := json.Marshal(appraisal)
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(data, &claims))
	assert.Equal(t, testSPKIb64u, claims["eat_transport_identity_key"])

	fromAny, err := AppraisalFromAny(claims)
	require.NoError(t, err)
	assert.Equal(t, appraisal, fromAny)

	data, err = appraisal.MarshalCBOR()
	require.NoError(t, err)

	var fromCBOR Appraisal
	require.NoError(t, fromCBOR.UnmarshalCBOR(data))
	assert.Equal(t, appraisal, &fromCBOR)

	claims["eat_transport_identity_key"] = 1
	_, err = AppraisalFromAny(claims)
	assert.EqualError(t, err, "eat_transport_identity_key: expected SubjectPublicKeyInfo or digest, got int")

	appraisal.TransportIdentityKey = &TransportIdentityKey{}
	assert.EqualError(t, appraisal.Validate(), "eat_transport_identity_key: empty SubjectPublicKeyInfo")
}
