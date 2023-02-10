// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// EatProfile is the EAT profile implemented by this package
const EatProfile = "tag:github.com,2022:veraison/ear"

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
	RawEvidence       *B64Url      `json:"ear.raw-evidence,omitempty"`
	IssuedAt          *int64       `json:"iat"`
	AppraisalPolicyID *string      `json:"ear.appraisal-policy-id,omitempty"`
	Extensions
}

// B64Url is base64url (§5 of RFC4648) without padding.
// bstr MUST be base64url encoded as per EAT §7.2.2 "JSON Interoperability".
type B64Url []byte

func (o B64Url) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		base64.RawURLEncoding.EncodeToString(o),
	)
}

// NewAttestationResult returns a pointer to a new fully-initialized
// AttestationResult.
func NewAttestationResult() *AttestationResult {
	status := TrustTierNone
	iat := time.Now().Unix()
	profile := EatProfile

	return &AttestationResult{
		Status:      &status,
		Profile:     &profile,
		TrustVector: &TrustVector{},
		IssuedAt:    &iat,
	}
}

// MarshalJSON validates and serializes to JSON an AttestationResult object
func (o AttestationResult) MarshalJSON() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	return json.Marshal(o.AsMap())
}

// MarshalJSONIndent is like MarshalJSON but applies Indent to format the
// output. Each JSON element in the output will begin on a new line beginning
// with prefix followed by one or more copies of indent according to the
// indentation nesting.
func (o AttestationResult) MarshalJSONIndent(prefix, indent string) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	return json.MarshalIndent(o.AsMap(), prefix, indent)
}

// UnmarshalJSON de-serializes an AttestationResult object from its JSON
// representation and validates it.
func (o *AttestationResult) UnmarshalJSON(data []byte) error {
	var oMap map[string]interface{}
	if err := json.Unmarshal(data, &oMap); err != nil {
		return err
	}

	if err := o.populateFromMap(oMap); err != nil {
		return err
	}

	return o.validate()
}

// AsMap returns a map[string]interface{} with EAR claim names mapped onto
// corresponding values.
func (o AttestationResult) AsMap() map[string]interface{} {
	oMap := make(map[string]interface{})

	if o.Status != nil {
		oMap["ear.status"] = *o.Status
	}

	if o.Profile != nil {
		oMap["eat_profile"] = *o.Profile
	}

	if o.IssuedAt != nil {
		oMap["iat"] = *o.IssuedAt
	}

	if o.TrustVector != nil {
		oMap["ear.trustworthiness-vector"] = o.TrustVector.AsMap()
	}

	if o.RawEvidence != nil {
		oMap["ear.raw-evidence"] = *o.RawEvidence
	}

	if o.AppraisalPolicyID != nil {
		oMap["ear.appraisal-policy-id"] = *o.AppraisalPolicyID
	}

	if o.VeraisonProcessedEvidence != nil {
		oMap["ear.veraison.processed-evidence"] = *o.VeraisonProcessedEvidence
	}

	if o.VeraisonVerifierAddedClaims != nil {
		oMap["ear.veraison.verifier-added-claims"] = *o.VeraisonVerifierAddedClaims
	}

	return oMap
}

// UpdateStatusFromTrustVector  ensure that Status trustworthiness is not
// higher than is warranted by trust vector claims. For every claim that has
// been made (i.e. is not in TrustTierNone), if the claim's trust tier is lower
// than that of the Status, adjust the status to the claim's tier. This means
// that the overall result will not assert to be more trustworthy than
// individual vector claims (though it could be less trustworthy if had been
// manually set that way).
func (o *AttestationResult) UpdateStatusFromTrustVector() {
	for _, claimValue := range o.TrustVector.AsMap() {
		claimTier := claimValue.GetTier()
		if *o.Status < claimTier {
			*o.Status = claimTier
		}
	}
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
	VeraisonProcessedEvidence   *map[string]interface{} `json:"ear.veraison.processed-evidence,omitempty"`
	VeraisonVerifierAddedClaims *map[string]interface{} `json:"ear.veraison.verifier-added-claims,omitempty"`
}

// Verify cryptographically verifies the JWT data using the supplied key and
// algorithm.  The payload is then parsed and validated.  On success, the target
// AttestationResult object is populated with the decoded claims (possibly
// including the Trustworthiness vector).
func (o *AttestationResult) Verify(data []byte, alg jwa.KeyAlgorithm, key interface{}) error {
	token, err := jwt.Parse(data, jwt.WithKey(alg, key))
	if err != nil {
		return fmt.Errorf("failed verifying JWT message: %w", err)
	}

	claims := token.PrivateClaims()
	claims["iat"] = token.IssuedAt().Unix()

	return o.populateFromMap(claims)
}

// Sign validates the AttestationResult object, encodes it to JSON and wraps it
// in a JWT using the supplied private key for signing.  The key must be
// compatible with the requested signing algorithm.  On success, the complete
// JWT token is returned.
func (o AttestationResult) Sign(alg jwa.KeyAlgorithm, key interface{}) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	token := jwt.New()
	for k, v := range o.AsMap() {
		if err := token.Set(k, v); err != nil {
			return nil, fmt.Errorf("setting %s: %w", k, err)
		}
	}

	return jwt.Sign(token, jwt.WithKey(alg, key))
}

func (o *AttestationResult) populateFromMap(m map[string]interface{}) error {
	// entries not explicitly listed will use the stringPtrParser
	parsers := map[string]parser{
		"ear.status": func(iface interface{}) (interface{}, error) {
			return ToTrustTier(iface)
		},
		"iat": int64PtrParser,
		"ear.trustworthiness-vector": func(iface interface{}) (interface{}, error) {
			return ToTrustVector(iface)
		},
		"ear.raw-evidence":                   b64urlBytesPtrParser,
		"ear.veraison.processed-evidence":    stringMapPtrParser,
		"ear.veraison.verifier-added-claims": stringMapPtrParser,
	}

	return populateStructFromMap(o, m, "json", parsers, stringPtrParser)
}
