// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func Test_CWT_sign_verify(t *testing.T) {
	payload := []byte{
		0xa2, 0x04, 0x1b, 0x00, 0x00, 0x00, 0x02, 0x54,
		0x0b, 0xe3, 0xff, 0x06, 0x1a, 0x6a, 0xd1, 0xe2,
		0xe0,
	}

	key, err := jwk.ParseKey([]byte(testECDSAPrivateKey))
	require.NoError(t, err)

	alg, signer, err := SignerFromJWK(key)
	require.NoError(t, err)

	signedCWT, err := signCWT(payload, alg, signer, nil)
	assert.NoError(t, err)

	jwkPubKey, err := key.PublicKey()
	require.NoError(t, err)

	pubKey, err := jwk.Export[*ecdsa.PublicKey](jwkPubKey)
	require.NoError(t, err)

	unwrapped, err := verifyAndUnwrapCWT(signedCWT, alg, pubKey)
	assert.NoError(t, err)
	assert.Equal(t, payload, unwrapped)

	coseSign1 := signedCWT[2:]
	unwrapped, err = verifyAndUnwrapCWT(coseSign1, alg, pubKey)
	assert.NoError(t, err)
	assert.Equal(t, payload, unwrapped)

	unwrapped, err = unwrapCWT(signedCWT)
	assert.NoError(t, err)
	assert.Equal(t, payload, unwrapped)

	unwrapped, err = unwrapCWT(coseSign1)
	assert.NoError(t, err)
	assert.Equal(t, payload, unwrapped)

	jwkPubKey, err = jwk.ParseKey([]byte(testECDSAPublicKeyOther))
	require.NoError(t, err)

	pubKey, err = jwk.Export[*ecdsa.PublicKey](jwkPubKey)
	require.NoError(t, err)

	_, err = verifyAndUnwrapCWT(signedCWT, alg, pubKey)
	assert.ErrorContains(t, err, "COSE_Sign1: verification error")
}

func Test_CWT_unwrap_negative(t *testing.T) {
	jwkPubKey, err := jwk.ParseKey([]byte(testECDSAPublicKeyOther))
	require.NoError(t, err)

	pubKey, err := jwk.Export[*ecdsa.PublicKey](jwkPubKey)
	require.NoError(t, err)

	testCases := []struct {
		title string
		input []byte
		err   string
	}{
		{
			title: "err empty",
			err:   "EOF",
		},
		{
			title: "err bad type",
			input: []byte{0x01},
			err:   "cbor: cannot unmarshal positive integer into Go value of type cbor.RawTag",
		},
		{
			title: "err bad tag",
			input: []byte{0xc1, 0x01},
			err:   "expected CWT or COSE_Sign1, found tag 1",
		},
		{
			title: "err bad inner type",
			input: []byte{0xd2, 0x01},
			err:   "cbor: invalid COSE_Sign1_Tagged object",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			_, err = verifyAndUnwrapCWT(tc.input, cose.AlgorithmES256, pubKey)
			assert.ErrorContains(t, err, tc.err)

			_, err = unwrapCWT(tc.input)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func Test_epocTime_UnmarshalCBOR(t *testing.T) {
	testCases := []struct {
		title    string
		input    []byte
		expected time.Time
		err      string
	}{
		{
			title:    "ok uint",
			input:    []byte{0x01},
			expected: time.Unix(1, 0).UTC(),
		},
		{
			title:    "ok nint",
			input:    []byte{0x20},
			expected: time.Unix(-1, 0).UTC(),
		},
		{
			title: "ok float64",
			input: []byte{
				0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99,
				0x9a,
			},
			expected: time.Unix(1, 1e8).UTC(),
		},
		{
			title: "err empty",
			input: []byte{},
			err:   "EOF",
		},
		{
			title: "err bad type",
			input: []byte{0xf5},
			err:   "unexpected type bool for time value",
		},
		{
			title: "err overflow",
			input: []byte{
				0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00,
			},
			err: "overflow",
		},
		{
			title: "err NaN",
			input: []byte{
				0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00,
			},
			err: "cannot convert to int64: NaN",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			var epocTime epochTime
			err := epocTime.UnmarshalCBOR(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, epocTime.Time())
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}

}

func Test_checkValidity(t *testing.T) {
	now := time.Unix(1792147122, 0).UTC()
	testCases := []struct {
		title string
		input []byte
		err   string
	}{
		{
			title: "ok",
			input: []byte{
				0xa2,                                           // map(2) [validityStruct]
				0x04,                                           // . key: 4 [exp]
				0x1b,                                           // . value: int(8)
				0x00, 0x00, 0x00, 0x02, 0x54, 0x0b, 0xe3, 0xff, // . . 9999999999
				0x06,                   //                         . key: 6 [nbf]
				0x1a,                   //                         . value: int(4)
				0x6a, 0xd1, 0xe2, 0xe0, //                         . . 1792140000
			},
		},
		{
			title: "ok no expiry",
			input: []byte{
				0xa1, // map(1)
				0x01, // . key: 1
				0x01, // . value: 1
			},
		},
		{
			title: "err expired",
			input: []byte{
				0xa2,                   // map(2) [validityStruct]
				0x04,                   // . key: 4 [exp]
				0x1a,                   //                         . value: int(4)
				0x6a, 0xd1, 0xe2, 0xe0, //                         . . 1792140000
				0x06,                   //                         . key: 6 [nbf]
				0x1a,                   //                         . value: int(4)
				0x6a, 0xd1, 0xe2, 0xe0, //                         . . 1792140000
			},
			err: "CWT expired",
		},
		{
			title: "err premature",
			input: []byte{
				0xa2,                                           // map(2) [validityStruct]
				0x04,                                           // . key: 4 [exp]
				0x1b,                                           // . value: int(8)
				0x00, 0x00, 0x00, 0x02, 0x54, 0x0b, 0xe3, 0xff, // . . 9999999999
				0x06,                                           // . key: 6 [nbf]
				0x1b,                                           // . value: int(8)
				0x00, 0x00, 0x00, 0x02, 0x54, 0x0b, 0xe3, 0xff, // . . 9999999999
			},
			err: "CWT not yet valid",
		},
		{
			title: "err empty",
			input: []byte{},
			err:   "EOF",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			err := checkValidity(tc.input, now)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
