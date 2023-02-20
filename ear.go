// Copyright 2022-2023 Contributors to the Veraison project.
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
const EatProfile = "tag:github.com,2023:veraison/ear"

// AttestationResult represents the result of one or more evidence Appraisals
// by the verifier.  It is serialized to JSON and signed by the verifier using
// JWT.
type AttestationResult struct {
	Profile     *string               `json:"eat_profile"`
	VerifierID  *VerifierIdentity     `json:"ear.verifier-id"`
	RawEvidence *B64Url               `json:"ear.raw-evidence,omitempty"`
	IssuedAt    *int64                `json:"iat"`
	Nonce       *string               `json:"eat_nonce,omitempty"`
	Submods     map[string]*Appraisal `json:"submods"`
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
func NewAttestationResult(
	submodName string,
	verifierBuild string,
	verifierDeveloper string,
) *AttestationResult {
	status := TrustTierNone
	iat := time.Now().Unix()
	profile := EatProfile

	return &AttestationResult{
		Profile:  &profile,
		IssuedAt: &iat,
		Submods: map[string]*Appraisal{
			submodName: {
				TrustVector: &TrustVector{},
				Status:      &status,
			},
		},
		VerifierID: &VerifierIdentity{
			Build:     &verifierBuild,
			Developer: &verifierDeveloper,
		},
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
	m, err := structAsMap(o, "json")
	if err != nil {
		// An error can only be returned if there is issue in implmentation of
		// AttestationResult; specificically, if any of its
		// constituents incorrectly implment AsMap() themselves.
		panic(err)
	}
	return m
}

// UpdateStatusFromTrustVector ensure that Status trustworthiness of each
// Appraisal is not higher than is warranted by its trust vector claims. For every
// claim that has been made (i.e. is not in TrustTierNone), if the claim's
// trust tier is lower than that of the Status, adjust the status to the
// claim's tier. This means that the overall result will not assert to be more
// trustworthy than individual vector claims (though it could be less
// trustworthy if had been manually set that way).
func (o *AttestationResult) UpdateStatusFromTrustVector() {
	for _, appraisal := range o.Submods {
		appraisal.UpdateStatusFromTrustVector()
	}
}

func (o AttestationResult) validate() error {
	var missing, invalid, summary []string

	if o.Profile == nil {
		missing = append(missing, "'eat_profile'")
	} else if *o.Profile != EatProfile {
		invalid = append(invalid, fmt.Sprintf("eat_profile (%s)", *o.Profile))
	}

	if o.IssuedAt == nil {
		missing = append(missing, "'iat'")
	}

	if o.VerifierID == nil {
		missing = append(missing, "'verifier-id'")
	}

	if o.Nonce != nil {
		nLen := len(*o.Nonce)
		if nLen > 74 || nLen < 10 {
			invalid = append(invalid, fmt.Sprintf("eat_nonce (%d bytes)", nLen))
		}
	}

	if len(o.Submods) == 0 {
		missing = append(missing, "'submods' (at least one appraisal must be present)")
	} else {
		for submodName, appraisal := range o.Submods {
			if err := appraisal.validate(); err != nil {
				msg := fmt.Sprintf("submods[%s]: %s", submodName, err.Error())
				invalid = append(invalid, msg)
			}
		}
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
		"iat": int64PtrParser,
		"ear.trustworthiness-vector": func(v interface{}) (interface{}, error) {
			return ToTrustVector(v)
		},
		"ear.verifier-id": func(v interface{}) (interface{}, error) {
			return ToVerifierIdentity(v)
		},
		"ear.raw-evidence": b64urlBytesPtrParser,
		"submods": func(v interface{}) (interface{}, error) {
			vMap, ok := v.(map[string]interface{})
			if !ok {
				return nil, errors.New("not a map object")
			}

			ret := map[string]*Appraisal{}
			var problems []string

			for key, val := range vMap {
				appraisal, err := ToAppraisal(val)
				if err != nil {
					problems = append(problems,
						fmt.Sprintf("%s: %s", key, err.Error()))
					continue
				}

				ret[key] = appraisal
			}

			if len(problems) > 0 {
				return nil, errors.New(strings.Join(problems, "; "))
			}

			return ret, nil
		},
	}

	return populateStructFromMap(o, m, "json", parsers, stringPtrParser, true)
}
