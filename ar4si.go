// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// EatProfile is the EAT profile implemented by this package
const EatProfile = "tag:github.com/veraison/ar4si,2022-10-17"

// TrustTier represents the overall state of an evidence appraisal.
//
// TrustTierNone means appraisal could not be conducted for whatever reason
// (e.g., a processing error).
//
// TrustTierAffirming means appraisal was fully successful and the attester can
// be considered trustworthy.
//
// TrustTierWarning means appraisal was mostly successful, but there are
// specific checks that need further attention from the relying party to assess
// whether the attester can be considered trustworthy or not.
//
// TrustTierContraindicated means some specific checks have failed and the
// attester cannot be considered trustworthy.
type TrustTier int8

const (
	TrustTierNone            TrustTier = 0
	TrustTierAffirming       TrustTier = 2
	TrustTierWarning         TrustTier = 32
	TrustTierContraindicated TrustTier = 96
)

var (
	StatusTierToString = map[TrustTier]string{
		TrustTierNone:            "none",
		TrustTierAffirming:       "affirming",
		TrustTierWarning:         "warning",
		TrustTierContraindicated: "contraindicated",
	}

	StringToTrustTier = map[string]TrustTier{
		"none":            TrustTierNone,
		"affirming":       TrustTierAffirming,
		"warning":         TrustTierWarning,
		"contraindicated": TrustTierContraindicated,
	}
)

func (o TrustTier) MarshalJSON() ([]byte, error) {
	var (
		s  string
		ok bool
	)

	s, ok = StatusTierToString[o]
	if !ok {
		return nil, fmt.Errorf("unknown trust tier '%d'", o)
	}

	return json.Marshal(s)
}

func (o *TrustTier) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unable to decode trust tier '%s': %w", string(data), err)
	}

	r, ok := StringToTrustTier[s]
	if !ok {
		return fmt.Errorf("unknown trust tier '%s'", s)
	}

	*o = r

	return nil
}

// AttestationResult represents the result of an evidence appraisal by the
// verifier.  It wraps the AR4SI trustworthiness vector together with other
// metadata that are relevant to establish the appraisal context - the evidence
// itself, the appraisal policy used, the time of appraisal.
// The AttestationResult is serialized to JSON and signed by the verifier using
// JWT.
type AttestationResult struct {
	Status            *TrustTier   `json:"ear.status"`
	Profile           *string      `json:"eat_profile"`
	TrustVector       *TrustVector `json:"ear.trustworthiness-vector,omitempty"`
	RawEvidence       *[]byte      `json:"ear.raw-evidence,omitempty"`
	IssuedAt          *int64       `json:"iat"`
	AppraisalPolicyID *string      `json:"ear.appraisal-policy-id,omitempty"`
	Extensions
}

// ToJSON validates and serializes to JSON an AttestationResult object
func (o AttestationResult) ToJSON() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(o)
}

// FromJSON de-serializes an AttestationResult object from its JSON
// representation and validates it.
func (o *AttestationResult) FromJSON(data []byte) error {
	err := json.Unmarshal(data, o)
	if err == nil {
		return o.validate()
	}
	return err
}

func (o AttestationResult) validate() error {
	var missing, invalid, summary []string

	if o.Profile == nil {
		missing = append(missing, "'eat_profile'")
	} else if *o.Profile != EatProfile {
		invalid = append(invalid, fmt.Sprintf("eat_profile (%s)", *o.Profile))
	}

	if o.Status == nil {
		missing = append(missing, "'status'")
	}

	if o.IssuedAt == nil {
		missing = append(missing, "'iat'")
	}

	if len(missing) == 0 && len(invalid) == 0 {
		return nil
	}

	if len(missing) != 0 {
		summary = append(summary, fmt.Sprintf("missing mandatory %s", strings.Join(missing, ", ")))
	}

	if len(invalid) != 0 {
		summary = append(summary, fmt.Sprintf("invalid value(s) for %s", strings.Join(invalid, ", ")))
	}

	return errors.New(strings.Join(summary, "; "))
}

// Extensions contains any proprietary claims that can be optionally attached to the
// AttestationResult.  For now only veraison-specific extensions are supported.
type Extensions struct {
	VeraisonProcessedEvidence   *map[string]interface{} `json:"veraison.processed-evidence,omitempty"`
	VeraisonVerifierAddedClaims *map[string]interface{} `json:"veraison.verifier-added-claims,omitempty"`
}

// Verify cryptographically verifies the JWT data using the supplied key and
// algorithm.  The payload is then parsed and validated.  On success, the target
// AttestationResult object is populated with the decoded claims (possibly
// including the Trustworthiness vector).
func (o *AttestationResult) Verify(data []byte, alg jwa.KeyAlgorithm, key interface{}) error {
	buf, err := jws.Verify(data, jws.WithKey(alg, key))
	if err != nil {
		return fmt.Errorf("failed verifying JWT message: %w", err)
	}

	// TODO(tho) add any JWT specific checks on top of the base JWS verification
	// See https://github.com/veraison/ar4si/issues/6

	var ar AttestationResult

	err = ar.FromJSON(buf)
	if err != nil {
		return fmt.Errorf("failed parsing JWT payload: %w", err)
	}

	*o = ar

	return nil
}

// Sign validates the AttestationResult object, encodes it to JSON and wraps it
// in a JWT using the supplied private key for signing.  The key must be
// compatible with the requested signing algorithm.  On success, the complete
// JWT token is returned.
func (o AttestationResult) Sign(alg jwa.KeyAlgorithm, key interface{}) ([]byte, error) {
	payload, err := o.ToJSON()
	if err != nil {
		return nil, err
	}

	return jws.Sign(payload, jws.WithKey(alg, key))
}
