// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const CBORTagsCWT = 61

var (
	em, emError = initCBOREncMode()
	dm, dmError = initCBORDecMode()
)

func signCWT(payload []byte, alg cose.Algorithm, key crypto.Signer, headers *cose.Headers) ([]byte, error) {
	signer, err := cose.NewSigner(alg, key)
	if err != nil {
		return nil, err
	}

	if headers == nil {
		headers = &cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: alg,
			},
		}
	}

	coseSign1, err := cose.Sign1(rand.Reader, signer, *headers, payload, nil)
	if err != nil {
		return nil, err
	}

	tag := cbor.RawTag{
		Number:  CBORTagsCWT,
		Content: coseSign1,
	}

	return em.Marshal(tag)
}

func verifyAndUnwrapCWT(data []byte, alg cose.Algorithm, key crypto.PublicKey) ([]byte, error) {
	verifier, err := cose.NewVerifier(alg, key)
	if err != nil {
		return nil, err
	}

	coseSign1, err := unpackCoseSign1(data)
	if err != nil {
		return nil, err
	}

	if err := coseSign1.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("COSE_Sign1: %w", err)
	}

	if err := checkValidity(coseSign1.Payload, time.Now().UTC()); err != nil {
		return nil, err
	}

	return coseSign1.Payload, nil
}

func unwrapCWT(data []byte) ([]byte, error) {
	coseSign1, err := unpackCoseSign1(data)
	if err != nil {
		return nil, err
	}

	return coseSign1.Payload, nil
}

func unpackCoseSign1(data []byte) (cose.Sign1Message, error) {
	var tag cbor.RawTag
	if err := dm.Unmarshal(data, &tag); err != nil {
		return cose.Sign1Message{}, err
	}

	var coseSign1Bytes []byte
	switch tag.Number {
	case CBORTagsCWT:
		coseSign1Bytes = tag.Content
	case cose.CBORTagSign1Message:
		coseSign1Bytes = data
	default:
		return cose.Sign1Message{}, fmt.Errorf("expected CWT or COSE_Sign1, found tag %d", tag.Number)
	}

	var coseSign1 cose.Sign1Message
	if err := coseSign1.UnmarshalCBOR(coseSign1Bytes); err != nil {
		return cose.Sign1Message{}, err
	}

	return coseSign1, nil
}

type epochTime time.Time

func (e *epochTime) UnmarshalCBOR(data []byte) error {
	var raw any
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case int64:
		*e = epochTime(time.Unix(v, 0).UTC())
	case uint64:
		if v > uint64(math.MaxInt64) {
			return errors.New("overflow")
		}
		*e = epochTime(time.Unix(int64(v), 0).UTC())
	case float64:
		if math.IsNaN(v) || v >= float64(math.MaxInt64) || v <= float64(math.MinInt64) {
			return fmt.Errorf("cannot convert to int64: %f", v)
		}
		sec := int64(v)
		nsec := int64((v - float64(sec)) * 1e9)
		*e = epochTime(time.Unix(sec, nsec).UTC())
	default:
		return fmt.Errorf("unexpected type %T for time value", raw)
	}
	return nil
}

func (e epochTime) Time() time.Time {
	return time.Time(e)
}

func checkValidity(data []byte, now time.Time) error {
	type validityClaims struct {
		Expiry    *epochTime `cbor:"4,keyasint,omitempty"`
		NotBefore *epochTime `cbor:"6,keyasint,omitempty"`
	}

	var validity validityClaims
	if err := dm.Unmarshal(data, &validity); err != nil {
		return err
	}

	if validity.NotBefore != nil && now.Before(validity.NotBefore.Time()) {
		return fmt.Errorf("CWT not yet valid: nbf=%s, now=%s", validity.NotBefore.Time(), now)
	}

	if validity.Expiry != nil && !now.Before(validity.Expiry.Time()) {
		return fmt.Errorf("CWT expired: exp=%s, now=%s", validity.Expiry.Time(), now)
	}

	return nil
}

func initCBOREncMode() (en cbor.EncMode, err error) {
	encOpt := cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		IndefLength:   cbor.IndefLengthForbidden,
		NilContainers: cbor.NilContainerAsEmpty,
		TimeTag:       cbor.EncTagRequired,
	}
	return encOpt.EncMode()
}

func initCBORDecMode() (dm cbor.DecMode, err error) {
	decOpt := cbor.DecOptions{
		IndefLength: cbor.IndefLengthAllowed,
		TimeTag:     cbor.DecTagOptional,
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	}
	return decOpt.DecMode()
}

func init() {
	if emError != nil {
		panic(emError)
	}
	if dmError != nil {
		panic(dmError)
	}
}
