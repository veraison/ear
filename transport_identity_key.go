// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// TransportIdentityKey identifies the key an attester uses to authenticate
// itself in a secure channel, e.g., the end-entity key of a TLS certificate
// (eat_transport_identity_key). It carries either the DER-encoded
// SubjectPublicKeyInfo of the key or a digest of it. Exactly one of SPKI and
// Digest must be set.
type TransportIdentityKey struct {
	SPKI   []byte
	Digest *Digest
}

// NewTransportIdentityKey returns a TransportIdentityKey carrying the DER
// SubjectPublicKeyInfo of the provided key. The encoding must match the one
// the attester presents to its peer, so prefer NewTransportIdentityKeyFromSPKI
// when the encoded bytes are available (e.g., from a certificate).
func NewTransportIdentityKey(pub crypto.PublicKey) (*TransportIdentityKey, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	}

	return NewTransportIdentityKeyFromSPKI(spki)
}

// NewTransportIdentityKeyFromSPKI returns a TransportIdentityKey carrying the
// provided DER SubjectPublicKeyInfo.
func NewTransportIdentityKeyFromSPKI(spki []byte) (*TransportIdentityKey, error) {
	ret := &TransportIdentityKey{SPKI: spki}

	return ret, ret.Validate()
}

// NewTransportIdentityKeyDigest returns a TransportIdentityKey carrying the
// digest of the provided DER SubjectPublicKeyInfo computed with the specified
// hash function.
func NewTransportIdentityKeyDigest(spki []byte, hash crypto.Hash) (*TransportIdentityKey, error) {
	if len(spki) == 0 {
		return nil, errors.New("empty SubjectPublicKeyInfo")
	}

	digest, err := NewDigest(hash, spki)
	if err != nil {
		return nil, err
	}

	return &TransportIdentityKey{Digest: digest}, nil
}

// TransportIdentityKeyFromAny returns a pointer to a TransportIdentityKey
// obtained from the provided value: a TransportIdentityKey (or a pointer to
// one), the SubjectPublicKeyInfo as bytes or as a base64url-encoded string, or
// a digest.
func TransportIdentityKeyFromAny(value any) (*TransportIdentityKey, error) {
	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return nil, errors.New("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	var ret TransportIdentityKey

	switch t := value.(type) {
	case TransportIdentityKey:
		ret = t
	case []byte:
		ret.SPKI = t
	case string:
		spki, err := decodeBase64URL(t)
		if err != nil {
			return nil, fmt.Errorf("SubjectPublicKeyInfo: %w", err)
		}
		ret.SPKI = spki
	case []any:
		digest, err := DigestFromAny(t)
		if err != nil {
			return nil, fmt.Errorf("digest: %w", err)
		}
		ret.Digest = digest
	default:
		return nil, fmt.Errorf("expected SubjectPublicKeyInfo or digest, got %T", value)
	}

	return &ret, ret.Validate()
}

// Validate returns an error unless exactly one of SPKI and Digest is set and
// valid.
func (o TransportIdentityKey) Validate() error {
	switch {
	case o.SPKI != nil && o.Digest != nil:
		return errors.New("both SubjectPublicKeyInfo and digest set")
	case o.Digest != nil:
		if err := o.Digest.Validate(); err != nil {
			return fmt.Errorf("digest: %w", err)
		}
	case len(o.SPKI) == 0:
		return errors.New("empty SubjectPublicKeyInfo")
	}

	return nil
}

// Verify checks that the receiver identifies the key with the provided DER
// SubjectPublicKeyInfo, i.e. the one the relying party authenticated in the
// secure channel (e.g., x509.Certificate.RawSubjectPublicKeyInfo). The
// SubjectPublicKeyInfo is compared byte for byte, or hashed with the
// algorithm of the digest. A mismatch must be treated as an attestation
// failure.
func (o TransportIdentityKey) Verify(spki []byte) error {
	if err := o.Validate(); err != nil {
		return err
	}

	if o.Digest != nil {
		return o.Digest.Verify(spki)
	}

	if !bytes.Equal(o.SPKI, spki) {
		return errors.New("SubjectPublicKeyInfo mismatch")
	}

	return nil
}

// PublicKey returns the public key parsed from the SubjectPublicKeyInfo. An
// error is returned if the receiver carries a digest or the key cannot be
// parsed by x509.ParsePKIXPublicKey.
func (o TransportIdentityKey) PublicKey() (crypto.PublicKey, error) {
	if o.SPKI == nil {
		return nil, errors.New("no SubjectPublicKeyInfo")
	}

	return x509.ParsePKIXPublicKey(o.SPKI)
}

func (o TransportIdentityKey) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	if o.Digest != nil {
		return o.Digest.MarshalJSON()
	}

	return json.Marshal(base64.RawURLEncoding.EncodeToString(o.SPKI))
}

func (o *TransportIdentityKey) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	ret, err := TransportIdentityKeyFromAny(value)
	if err != nil {
		return err
	}

	*o = *ret

	return nil
}

func (o TransportIdentityKey) MarshalCBOR() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	if o.Digest != nil {
		return o.Digest.MarshalCBOR()
	}

	return em.Marshal(o.SPKI)
}

func (o *TransportIdentityKey) UnmarshalCBOR(data []byte) error {
	var value any
	if err := dm.Unmarshal(data, &value); err != nil {
		return err
	}

	switch value.(type) {
	case string:
		return errors.New("expected SubjectPublicKeyInfo as bytes, got string")
	case []any:
		var digest Digest
		if err := digest.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("digest: %w", err)
		}

		*o = TransportIdentityKey{Digest: &digest}

		return nil
	}

	ret, err := TransportIdentityKeyFromAny(value)
	if err != nil {
		return err
	}

	*o = *ret

	return nil
}
