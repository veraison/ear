// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	_ "crypto/sha256" // register SHA-256 with crypto.Hash
	_ "crypto/sha3"   // register SHA3 with crypto.Hash
	_ "crypto/sha512" // register SHA-384 and SHA-512 with crypto.Hash

	"github.com/veraison/eat"
)

// namedInfoHash is an entry of the IANA "Named Information Hash Algorithm
// Registry".
type namedInfoHash struct {
	id   int
	name string
	hash crypto.Hash
	size int // truncated digest size in bytes
}

var namedInfoHashes = []namedInfoHash{
	{1, "sha-256", crypto.SHA256, 32},
	{2, "sha-256-128", crypto.SHA256, 16},
	{3, "sha-256-120", crypto.SHA256, 15},
	{4, "sha-256-96", crypto.SHA256, 12},
	{5, "sha-256-64", crypto.SHA256, 8},
	{6, "sha-256-32", crypto.SHA256, 4},
	{7, "sha-384", crypto.SHA384, 48},
	{8, "sha-512", crypto.SHA512, 64},
	{9, "sha3-224", crypto.SHA3_224, 28},
	{10, "sha3-256", crypto.SHA3_256, 32},
	{11, "sha3-384", crypto.SHA3_384, 48},
	{12, "sha3-512", crypto.SHA3_512, 64},
}

func lookupNamedInfoHash(alg eat.IntOrString) (namedInfoHash, bool) {
	for _, entry := range namedInfoHashes {
		if (alg.IsInt() && alg.Int() == entry.id) ||
			(alg.IsString() && alg.String() == entry.name) {
			return entry, true
		}
	}

	return namedInfoHash{}, false
}

// Digest is a cryptographic digest as defined in Section 4.2 of
// draft-ietf-rats-eat-measured-component. It serializes as [alg, value], with
// the value base64url-encoded in JSON. Alg identifies the hash algorithm by
// its ID or name in the IANA "Named Information Hash Algorithm Registry".
type Digest struct {
	Alg   eat.IntOrString
	Value []byte
}

// NewDigest computes the digest of data using the specified hash function.
// The algorithm is identified by its integer ID. An error is returned if the
// hash function has no entry in the Named Information Hash Algorithm Registry
// or is not available.
func NewDigest(hash crypto.Hash, data []byte) (*Digest, error) {
	for _, entry := range namedInfoHashes {
		if entry.hash == hash && entry.size == hash.Size() {
			value, err := entry.sum(data)
			if err != nil {
				return nil, err
			}

			return &Digest{Alg: eat.IntOrStringFromInt(entry.id), Value: value}, nil
		}
	}

	return nil, fmt.Errorf("unsupported hash function %s", hash.String())
}

// DigestFromAny returns a pointer to a Digest obtained from the provided
// value, which must be a Digest (or a pointer to one), or a two-element list
// containing the algorithm and the value (as bytes or as a base64url-encoded
// string).
func DigestFromAny(value any) (*Digest, error) {
	switch t := value.(type) {
	case *Digest:
		if t == nil {
			return nil, errors.New("nil pointer")
		}
		return t, t.Validate()
	case Digest:
		return &t, t.Validate()
	}

	list, ok := value.([]any)
	if !ok || len(list) != 2 {
		return nil, fmt.Errorf("expected a two-element list, got %T", value)
	}

	alg, err := eat.IntOrStringFromAny(list[0])
	if err != nil {
		return nil, fmt.Errorf("alg: %w", err)
	}

	var digestValue []byte
	switch t := list[1].(type) {
	case []byte:
		digestValue = t
	case string:
		digestValue, err = decodeBase64URL(t)
		if err != nil {
			return nil, fmt.Errorf("value: %w", err)
		}
	default:
		return nil, fmt.Errorf("value: expected bytes or string, got %T", list[1])
	}

	ret := &Digest{Alg: alg, Value: digestValue}

	return ret, ret.Validate()
}

// Validate returns an error if the algorithm is not set, the value is empty,
// or the value length does not match a known algorithm.
func (o Digest) Validate() error {
	if !o.Alg.IsInt() && !o.Alg.IsString() {
		return errors.New("missing alg")
	}

	if len(o.Value) == 0 {
		return errors.New("empty value")
	}

	if entry, ok := lookupNamedInfoHash(o.Alg); ok && len(o.Value) != entry.size {
		return fmt.Errorf(
			"value length %d does not match %s (%d)",
			len(o.Value), entry.name, entry.size,
		)
	}

	return nil
}

// Verify returns nil if the receiver is the digest of data, and an error
// otherwise or if the algorithm is not supported.
func (o Digest) Verify(data []byte) error {
	entry, ok := lookupNamedInfoHash(o.Alg)
	if !ok {
		return fmt.Errorf("unsupported hash algorithm %q", o.Alg.String())
	}

	expected, err := entry.sum(data)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(expected, o.Value) != 1 {
		return errors.New("digest mismatch")
	}

	return nil
}

func (o Digest) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	alg, err := o.Alg.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return json.Marshal([]any{
		json.RawMessage(alg),
		base64.RawURLEncoding.EncodeToString(o.Value),
	})
}

func (o *Digest) UnmarshalJSON(data []byte) error {
	var list []any
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	ret, err := DigestFromAny(list)
	if err != nil {
		return err
	}

	*o = *ret

	return nil
}

func (o Digest) MarshalCBOR() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	alg, err := o.Alg.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	value, err := em.Marshal(o.Value)
	if err != nil {
		return nil, err
	}

	return append(append([]byte{0x82}, alg...), value...), nil
}

func (o *Digest) UnmarshalCBOR(data []byte) error {
	var list []any
	if err := dm.Unmarshal(data, &list); err != nil {
		return err
	}

	if len(list) == 2 {
		if _, ok := list[1].([]byte); !ok {
			return fmt.Errorf("value: expected bytes, got %T", list[1])
		}
	}

	ret, err := DigestFromAny(list)
	if err != nil {
		return err
	}

	*o = *ret

	return nil
}

func (o namedInfoHash) sum(data []byte) ([]byte, error) {
	if !o.hash.Available() {
		return nil, fmt.Errorf("hash function %s not available", o.hash.String())
	}

	h := o.hash.New()
	h.Write(data)

	return h.Sum(nil)[:o.size], nil
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
