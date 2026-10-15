// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veraison/eat"
)

// Appraisal represents the result of an evidence appraisal
// by the verifier.  It wraps the AR4SI trustworthiness vector together with
// other metadata that are relevant to establish the appraisal context - the
// evidence itself, the appraisal policy used, the time of appraisal.
type Appraisal struct {
	Profile            *eat.Profile            `cbor:"265,keyasint,omitempty" json:"eat_profile,omitempty"`
	Status             TrustTier               `cbor:"1000,keyasint" json:"ear_status"`
	TrustVector        *TrustVector            `cbor:"1001,keyasint,omitempty" json:"ear_trustworthiness_vector,omitzero"`
	AppraisalPolicyIDs []string                `cbor:"1003,keyasint,omitempty" json:"ear_appraisal_policy_ids,omitempty"`
	Nonce              *eat.Nonce              `cbor:"10,keyasint,omitempty" json:"eat_nonce,omitempty"`
	AttesterClaims     map[eat.IntOrString]any `cbor:"1005,keyasint,omitempty" json:"ear_attester_claims,omitempty"`
	VerifierClaims     map[eat.IntOrString]any `cbor:"1006,keyasint,omitempty" json:"ear_verifier_claims,omitempty"`
	Extensions         *Extensions             `cbor:"-" json:"-"`
}

// NewAppraisal returns a new Appraisal with its status set to TrustTierNone
// and all its claims set to NoClaim.
func NewAppraisal() *Appraisal {
	return &Appraisal{
		Status:      TrustTierNone,
		TrustVector: NewTrustVector(),
		Extensions:  NewExtensions(),
	}
}

// AppraisalFromAny returns a pointer to an Appraisal obtained from provided
// input. If input is already an Appraisal (or a pointer to one) then a pointer
// to that Appraisal is returned. Otherwise, a conversion is attempted and an
// error is returned if it fails.
func AppraisalFromAny(input any) (*Appraisal, error) {
	switch t := input.(type) {
	case *Appraisal:
		return t, nil
	case Appraisal:
		return &t, nil
	}

	var appraisal Appraisal
	var extensions Extensions

	claims, err := eat.IntOrStringMapFromAny(input)
	if err != nil {
		return nil, err
	}

	for key, value := range claims {
		switch key {
		case eat.IntOrStringFromString("eat_profile"), eat.IntOrStringFromInt(265):
			profileText, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("eat_profile: expected a string, got %T", value)
			}

			profile, err := eat.NewProfile(profileText)
			if err != nil {
				return nil, fmt.Errorf("eat_profile: %w", err)
			}

			appraisal.Profile = profile
		case eat.IntOrStringFromString("ear_status"), eat.IntOrStringFromInt(1000):
			tier, err := TrustTierFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_status: %w", err)
			}

			appraisal.Status = tier
		case eat.IntOrStringFromString("ear_trustworthiness_vector"), eat.IntOrStringFromInt(1001):
			vector, err := TrustVectorFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_trustworthiness_vector: %w", err)
			}

			appraisal.TrustVector = vector
		case eat.IntOrStringFromString("ear_appraisal_policy_ids"), eat.IntOrStringFromInt(1003):
			rawIds, ok := value.([]any)
			if !ok {
				return nil, fmt.Errorf(
					"ear_appraisal_policy_ids: expected an []any, got %T",
					value,
				)
			}

			ids := make([]string, len(rawIds))
			for i, id := range rawIds {
				ids[i], ok = id.(string)
				if !ok {
					return nil, fmt.Errorf(
						"ear_appraisal_policy_ids[%d]: expected a string, got %T",
						i, value,
					)
				}
			}

			appraisal.AppraisalPolicyIDs = ids
		case eat.IntOrStringFromString("eat_nonce"), eat.IntOrStringFromInt(10):
			nonce, err := eat.NonceFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("eat_nonce: %w", err)
			}

			appraisal.Nonce = nonce
		case eat.IntOrStringFromString("ear_attester_claims"), eat.IntOrStringFromInt(1005):
			claims, err := eat.IntOrStringMapFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_attester_claims: %w", err)
			}

			appraisal.AttesterClaims = claims
		case eat.IntOrStringFromString("ear_verifier_claims"), eat.IntOrStringFromInt(1006):
			claims, err := eat.IntOrStringMapFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_verifier_claims: %w", err)
			}

			appraisal.VerifierClaims = claims
		default:
			extensions.Set(key, value)
		}
	}

	appraisal.Extensions = &extensions

	if err := appraisal.Validate(); err != nil {
		return nil, err
	}

	return &appraisal, nil
}

// UpdateStatusFromTrustVector ensure that Status trustworthiness is not higher
// than is warranted by trust vector claims. For every claim that has been made
// (i.e. is not NoClaim), if the claim's trust tier is lower than that of the
// Status, adjust the status to the claim's tier. This means that the overall
// result will not assert to be more trustworthy than individual vector claims
// (though it could be less trustworthy if had been manually set that way).
func (o *Appraisal) UpdateStatusFromTrustVector() {
	if o.TrustVector == nil {
		return
	}

	for _, claimValue := range o.TrustVector.Map() {
		claimTier := claimValue.Tier()
		if claimTier.WorseThan(o.Status) {
			o.Status = claimTier
		}
	}
}

// Validate makes sure that the value of status is no better than any of the
// elements of the trust vector. This makes sure that it is always no more
// trustworthy than the trust vector components.
func (o *Appraisal) Validate() error {
	if o.Status != TrustTierNone {
		claimName, claimTier := o.TrustVector.WorstTier()
		if claimTier.WorseThan(o.Status) {
			return fmt.Errorf(
				"status %d has higher trustworthiness than %s trust vector element(%d)",
				o.Status.Int(), claimName, claimTier.Int(),
			)
		}
	}

	return nil
}

func (o *Appraisal) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	claims, err := structWithExtensionsToMap(o, "json")
	if err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}

func (o *Appraisal) UnmarshalJSON(data []byte) error { // nolint:dupl
	type appraisalUnmarshalHelper Appraisal

	if err := json.Unmarshal(data, (*appraisalUnmarshalHelper)(o)); err != nil {
		return err
	}

	var claims map[eat.IntOrString]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return err
	}

	var extensions Extensions
	seenStatus := false
	knownLabels := getTagLabels(o, "json")
	for label, value := range claims {
		if label == eat.IntOrStringFromString("ear_status") {
			seenStatus = true
		}

		if _, isKnown := knownLabels[label]; !isKnown {
			extensions.Set(label, value)
		}
	}

	if !seenStatus {
		return errors.New(`missing mandatory "ear_status" claim`)
	}

	o.Extensions = &extensions

	if err := o.Validate(); err != nil {
		return err
	}

	return nil
}

func (o *Appraisal) MarshalCBOR() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	claims, err := structWithExtensionsToMap(o, "cbor")
	if err != nil {
		return nil, err
	}

	return em.Marshal(claims)
}

func (o *Appraisal) UnmarshalCBOR(data []byte) error { // nolint:dupl
	type appraisalUnmarshalHelper Appraisal

	if err := dm.Unmarshal(data, (*appraisalUnmarshalHelper)(o)); err != nil {
		return err
	}

	var claims map[eat.IntOrString]any
	if err := dm.Unmarshal(data, &claims); err != nil {
		return err
	}

	var extensions Extensions
	seenStatus := false
	knownLabels := getTagLabels(o, "cbor")
	for label, value := range claims {
		if label == eat.IntOrStringFromInt(1000) {
			seenStatus = true
		}

		if _, isKnown := knownLabels[label]; !isKnown {
			extensions.Set(label, value)
		}
	}

	if !seenStatus {
		return errors.New(`missing mandatory claim 1000 (ear_status)`)
	}

	o.Extensions = &extensions

	if err := o.Validate(); err != nil {
		return err
	}

	return nil
}
