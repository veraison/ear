// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/veraison/eat"
	cose "github.com/veraison/go-cose"
)

// EatProfile is the EAT profile implemented by this package
const EatProfile = "tag:github.com,2023:veraison/ear"

// Trustee profile name which is an alias for the Veraison one.
// Both names will be replaced with a neutral one:
// https://github.com/ietf-rats-wg/draft-ietf-rats-ear/pull/47
const EatTrusteeProfile = "tag:github.com,2024:confidential-containers/Trustee"

// AttestationResult represents the result of one or more evidence Appraisals
// by the verifier.  It is serialized to JSON and signed by the verifier using
// JWT.
type AttestationResult struct {
	Profile     *string               `cbor:"265,keyasint" json:"eat_profile"`
	VerifierID  *VerifierIdentity     `cbor:"1004,keyasint" json:"ear.verifier-id"`
	RawEvidence *B64Url               `cbor:"1002,keyasint,omitempty" json:"ear.raw-evidence,omitempty"`
	IssuedAt    *int64                `cbor:"6,keyasint" json:"iat"`
	Nonce       *eat.Nonce            `cbor:"10,keyasint,omitempty" json:"eat_nonce,omitempty"`
	Submods     map[string]*Appraisal `cbor:"266,keyasint" json:"submods"`

	AttestationResultExtensions
}

type AttestationResultExtensions struct {
	VeraisonTeeInfo *VeraisonTeeInfo `cbor:"65001" json:"ear.veraison.tee-info,omitempty"`
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
		// An error can only be returned if there is issue in implementation of
		// AttestationResult; specifically, if any of its
		// constituents incorrectly implement AsMap() themselves.
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
	} else if *o.Profile != EatProfile && *o.Profile != EatTrusteeProfile {
		invalid = append(invalid, fmt.Sprintf("eat_profile (%s)", *o.Profile))
	}

	if o.IssuedAt == nil {
		missing = append(missing, "'iat'")
	}

	if o.VerifierID == nil {
		missing = append(missing, "'verifier-id'")
	}

	if o.Nonce != nil {
		if err := o.Nonce.Validate(); err != nil {
			invalid = append(invalid, fmt.Sprintf("eat_nonce (%s)", err.Error()))
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

	claims := make(map[string]any)
	for _, k := range token.Keys() {
		var v any
		if err := token.Get(k, &v); err != nil {
			return fmt.Errorf(`failed to get claim %s: %w`, k, err)
		}
		claims[k] = v
	}
	iat, _ := token.IssuedAt()
	claims["iat"] = iat.Unix()

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
		"ear.veraison.tee-info": func(v interface{}) (interface{}, error) {
			return ToVeraisonTeeInfo(v)
		},
	}

	return populateStructFromMap(o, m, "json", parsers, stringPtrParser, true)
}

// MarshalCBOR validates and serializes to JSON an AttestationResult object
func (o AttestationResult) ToCBOR() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	return cbor.Marshal(o)
}

// UnmarshalCBOR de-serializes an AttestationResult object from its JSON
// representation and validates it.
func (o *AttestationResult) FromCBOR(data []byte) error {
	if err := cbor.Unmarshal(data, o); err != nil {
		return err
	}

	return o.validate()
}

// Verify cryptographically verifies the CWT data using the supplied key and
// algorithm.  The payload is then parsed and validated.  On success, the target
// AttestationResult object is populated with the decoded claims (possibly
// including the Trustworthiness vector).
func (o *AttestationResult) VerifyCWT(data []byte, alg cose.Algorithm, publicKey crypto.PublicKey) error {
	// create a verifier from a trusted private key
	verifier, err := cose.NewVerifier(alg, publicKey)
	if err != nil {
		return err
	}

	// Try COSE_Sign1
	var sign1 cose.Sign1Message
	if err := sign1.UnmarshalCBOR(data); err == nil {
		if err := sign1.Verify(nil, verifier); err != nil {
			return fmt.Errorf("failed verifying COSE_Sign1 message: %w", err)
		}
		if err := o.FromCBOR(sign1.Payload); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("failed to parse CWT message (only COSE_Sign1 is supported now): %w", err)
}

// Sign validates the AttestationResult object, encodes it to JSON and wraps it
// in a JWT using the supplied private key for signing.  The key must be
// compatible with the requested signing algorithm.  On success, the complete
// JWT token is returned.
func (o AttestationResult) SignCWT(alg cose.Algorithm, privateKey crypto.Signer) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	signer, err := cose.NewSigner(alg, privateKey)
	if err != nil {
		return nil, err
	}

	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
		},
	}

	data, err := o.ToCBOR()
	if err != nil {
		return nil, err
	}

	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, data, nil)
}
