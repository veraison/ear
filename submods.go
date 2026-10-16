// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/veraison/eat"
)

// Submod is an attestation result submodule, an entry under "submods" EAT
// claim. It may contain an Appraisal, an AttestationResult, or an
// eat.NestedToken.
type Submod struct {
	value any
}

// SubmodFromAny returns a pointer to a Submod obtained from the provided
// input. If the input is itself a submod, the pointer to the same Submod is
// returned, otherwise a new Submod is constructed from the input. And error is
// returned if submod construction fails.
// (Note: conversion is performed by round tripping through JSON.)
func SubmodFromAny(value any) (*Submod, error) {
	switch t := value.(type) {
	case Submod:
		return &t, nil
	case *Submod:
		return t, nil
	}

	// going via JSON is a bit of a cop-out, but given the complexities of
	// the NestedToken, this seems preferable to writing conversion code by
	// hand.
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encoding JSON: %w", err)
	}

	var submod Submod
	if err := submod.UnmarshalJSON(encoded); err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return &submod, nil
}

// Value returns Submod's underlying value.
func (o Submod) Value() any {
	return o.value
}

// Appraisal returns a pointer to the Appraisal contained by the Submod. If the
// Submod does not contain an Appraisal, nil is returned instead.
func (o Submod) Appraisal() *Appraisal {
	ret, ok := o.value.(*Appraisal)
	if !ok {
		return nil
	}

	return ret
}

// AttestationResult returns a pointer to the AttestationResult contained by
// the Submod. If the Submod does not contain an AttestationResult, nil is
// returned instead.
func (o Submod) AttestationResult() *AttestationResult {
	ret, ok := o.value.(*AttestationResult)
	if !ok {
		return nil
	}

	return ret
}

// NestedToken returns a pointer to the eat.NestedToken contained by the
// Submod. If the Submod does not contain an eat.NestedToken, nil is returned
// instead.
func (o Submod) NestedToken() *eat.NestedToken {
	ret, ok := o.value.(*eat.NestedToken)
	if !ok {
		return nil
	}

	return ret
}

func (o Submod) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.value)
}

func (o *Submod) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return errors.New("truncated input")
	}

	switch text[0] {
	case '[':
		// array -> JSON-Selector -> Nested-Token
		var token eat.NestedToken
		if err := token.UnmarshalJSON(data); err != nil {
			return fmt.Errorf("nested token: %w", err)
		}

		o.value = &token
	case '{': // nolint:dupl
		// object -> Appraisal or AttestationResult
		type resultChecker struct {
			Iat *int64 `json:"iat"`
		}

		var checker resultChecker

		if err := json.Unmarshal(data, &checker); err != nil {
			return err
		}

		if checker.Iat == nil {
			// missing iat -> Appraisal
			var appraisal Appraisal
			if err := appraisal.UnmarshalJSON(data); err != nil {
				return fmt.Errorf("appraisal: %w", err)
			}

			o.value = &appraisal
		} else {
			// iat present -> AttestationResult
			var result AttestationResult
			if err := result.UnmarshalJSON(data); err != nil {
				return fmt.Errorf("attestation result: %w", err)
			}

			o.value = &result
		}
	default:
		return fmt.Errorf("invalid JSON type (expected object or array): %q", text)
	}

	return nil
}

func (o Submod) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.value)
}

func (o *Submod) UnmarshalCBOR(data []byte) error {
	if len(data) == 0 {
		return errors.New("truncated input")
	}

	majorType := (data[0] & 0xe0) >> 5
	switch majorType {
	case 3, 4:
		// ( string -> JWT | array -> JSON-Selector ) -> Nested-Token
		var token eat.NestedToken
		if err := token.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("nested token: %w", err)
		}

		o.value = &token
	case 5: // nolint:dupl
		// map -> Appraisal or AttestationResult
		type resultChecker struct {
			Iat *int64 `cbor:"6,keyasint"`
		}

		var checker resultChecker

		if err := dm.Unmarshal(data, &checker); err != nil {
			return err
		}

		if checker.Iat == nil {
			// missing iat -> Appraisal
			var appraisal Appraisal
			if err := appraisal.UnmarshalCBOR(data); err != nil {
				return fmt.Errorf("appraisal: %w", err)
			}

			o.value = &appraisal
		} else {
			// iat present -> AttestationResult
			var result AttestationResult
			if err := result.UnmarshalCBOR(data); err != nil {
				return fmt.Errorf("attestation result: %w", err)
			}

			o.value = &result
		}
	default:
		return fmt.Errorf("unexpected CBOR major type %d (expected 3, 4, or 5)", majorType)
	}

	return nil
}

// Submods is a collection of named submodule claims. Each submodule is either
// an AttestationResult, an Appraisal, or a eat.NestedToken.
type Submods map[string]*Submod

// SubmodsFromAny returns Submods obtained from provided value. If the value is
// a Submods, the same Submods is returned, otherwise Submods is constructed
// from provided input. If construction fails, an error is returned.
func SubmodsFromAny(value any) (Submods, error) {
	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return nil, errors.New("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	switch t := value.(type) {
	case Submods:
		return t, nil
	case map[string]*Submod:
		return Submods(t), nil
	case map[string]any:
		ret := NewSubmods()
		for label, submodValue := range t {
			submod, err := SubmodFromAny(submodValue)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}

			ret[label] = submod
		}

		return ret, nil
	default:
		return nil, fmt.Errorf("unexpected Submods type %T", value)
	}
}

// NewSubmods returns a pointer to an empty Submods:
func NewSubmods() Submods {
	ret := Submods(make(map[string]*Submod))
	return ret
}

// AddAppraisal adds the provided *Appraisal to the Submods under the
// specified name, overwriting any existing submod under that name. Pointer to
// the Submods is returned to allow chaining with other adds. Panics if the
// provided *Appraisal is nil.
func (o Submods) AddAppraisal(name string, appraisal *Appraisal) Submods {
	if appraisal == nil {
		panic("nil nested token")
	}

	o[name] = &Submod{appraisal}

	return o
}

// AddAttestationResult adds the provided *AttestationResult to the Submods
// under the specified name, overwriting any existing submod under that name.
// Pointer to the Submods is returned to allow chaining with other adds. Panics
// if the provided *AttestationResult is nil.
func (o Submods) AddAttestationResult(name string, result *AttestationResult) Submods {
	if result == nil {
		panic("nil nested token")
	}

	o[name] = &Submod{result}
	return o
}

// AddNestedToken adds the provided *NestedToken to the Submods under the
// specified name, overwriting any existing submod under that name. Pointer to
// the Submods is returned to allow chaining with other adds. Panics if the
// provided *NestedToken is nil.
func (o Submods) AddNestedToken(name string, token *eat.NestedToken) Submods {
	if token == nil {
		panic("nil nested token")
	}

	o[name] = &Submod{token}
	return o
}

// AddJWT adds the provided JWT bytes to the Submods as a NestedToken under the
// specified name, overwriting any existing submod under that name. Pointer to
// the Submods is returned to allow chaining with other adds. Panics if the
// provided []byte does not appear to contain a valid JWT.
func (o Submods) AddJWT(name string, jwtBytes []byte) Submods {
	// The JWT inside NestedToken is encoded as a JSON string; jwtBytes given
	// here are the "raw" JWT, so we need to quote to provide the string
	// encoding.
	tokenBytes := []byte(fmt.Sprintf("%q", string(jwtBytes)))

	token, err := eat.NewNestedToken(eat.NestedTokenJWT, tokenBytes)
	if err != nil {
		panic(err)
	}

	o.AddNestedToken(name, token)
	return o
}

// AddCWT adds the provided CWT bytes to the Submods as a NestedToken under the
// specified name, overwriting any existing submod under that name. Pointer to
// the Submods is returned to allow chaining with other adds. Panics if the
// provided []byte does not appear to contain a valid CWT.
func (o Submods) AddCWT(name string, cwtBytes []byte) Submods {
	token, err := eat.NewNestedToken(eat.NestedTokenCBOR, cwtBytes)
	if err != nil {
		panic(err)
	}

	o.AddNestedToken(name, token)
	return o
}

// Get retrieves a submod's value by name. If name is not in the collection,
// nil is returned.
func (o Submods) Get(name string) any {
	submod, ok := o[name]
	if !ok {
		return nil
	}

	return submod.value
}

// GetAppraisal returns the *Appraisal associated with the provided name. If
// the name is not in Submods or the associated submod is not a *Appraisal, an
// error is returned.
func (o Submods) GetAppraisal(name string) (*Appraisal, error) {
	value := o.Get(name)
	if value == nil {
		return nil, fmt.Errorf("no submod named %q", name)
	}

	appraisal, ok := value.(*Appraisal)
	if !ok {
		return nil, fmt.Errorf("submod %q is not an appraisal", name)
	}

	return appraisal, nil
}

// GetAttestationResult returns the *AttestationResult associated with the
// provided name. If the name is not in Submods or the associated submod is not
// a *AttestationResult, an error is returned.
func (o Submods) GetAttestationResult(name string) (*AttestationResult, error) {
	value := o.Get(name)
	if value == nil {
		return nil, fmt.Errorf("no submod named %q", name)
	}

	appraisal, ok := value.(*AttestationResult)
	if !ok {
		return nil, fmt.Errorf("submod %q is not an attestation result", name)
	}

	return appraisal, nil
}

// GetNestedToken returns the *NestedToken associated with the provided
// name. If the name is not in Submods or the associated submod is not a
// *NestedToken, an error is returned.
func (o Submods) GetNestedToken(name string) (*eat.NestedToken, error) {
	value := o.Get(name)
	if value == nil {
		return nil, fmt.Errorf("no submod named %q", name)
	}

	token, ok := value.(*eat.NestedToken)
	if !ok {
		return nil, fmt.Errorf("submod %q is not a nested token", name)
	}

	return token, nil
}

// IsEmpty returns true if the Submods does not contain any submodules.
func (o Submods) IsEmpty() bool {
	return len(o) == 0
}

// Validate returns an error if the Submods is empty or if contained submods
// are invalid.
func (o Submods) Validate() error {
	if o.IsEmpty() {
		return errors.New("no submods defined")
	}

	for label, submod := range o {
		if submod == nil || submod.value == nil {
			return fmt.Errorf("%s: null submod", label)
		}

		switch t := submod.value.(type) {
		case *Appraisal:
			if err := t.Validate(); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		case *AttestationResult:
			if err := t.Validate(); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		case *eat.NestedToken:
			_, err := AttestationResultFromNestedToken(t)
			if err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		default:
			// cases are exhaustive
			panic(t)
		}
	}

	return nil
}
