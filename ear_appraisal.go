// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// Appraisal represents the result of an evidence appraisal
// by the verifier.  It wraps the AR4SI trustworthiness vector together with
// other metadata that are relevant to establish the appraisal context - the
// evidence itself, the appraisal policy used, the time of appraisal.
type Appraisal struct {
	Status            *TrustTier   `json:"ear.status"`
	TrustVector       *TrustVector `json:"ear.trustworthiness-vector,omitempty"`
	AppraisalPolicyID *string      `json:"ear.appraisal-policy-id,omitempty"`

	AppraisalExtensions
}

// AppraisalExtensions contains any proprietary claims that can be optionally
// attached to the Appraisal.  For now only veraison-specific extensions are
// supported.
type AppraisalExtensions struct {
	VeraisonAnnotatedEvidence *map[string]interface{} `json:"ear.veraison.annotated-evidence,omitempty"`
	VeraisonPolicyClaims      *map[string]interface{} `json:"ear.veraison.policy-claims,omitempty"`
	VeraisonKeyAttestation    *map[string]interface{} `json:"ear.veraison.key-attestation,omitempty"`
}

// SetKeyAttestation sets the value of `akpub` in the
// "ear.veraison.key-attestation" claim.
// The following key types are currently supported: *rsa.PublicKey,
// *ecdsa.PublicKey, ed25519.PublicKey (not a pointer).
// Unsupported key types result in an error.
func (o *AppraisalExtensions) SetKeyAttestation(pub any) error {
	switch v := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return fmt.Errorf("unsupported type for public key: %T", v)
	}

	k, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	akpub := base64.RawURLEncoding.EncodeToString(k)

	o.VeraisonKeyAttestation = &map[string]interface{}{
		"akpub": akpub,
	}

	return nil
}

// GetKeyAttestation returns the decoded public key carried in the
// "ear.veraison.key-attestation" claim.
// The returned key type is one supported by x509.ParsePKIXPublicKey.
func (o AppraisalExtensions) GetKeyAttestation() (any, error) {
	if o.VeraisonKeyAttestation == nil {
		return nil, errors.New(`"ear.veraison.key-attestation" claim not found`)
	}

	v, ok := (*o.VeraisonKeyAttestation)["akpub"]
	if !ok {
		return nil, errors.New(`"akpub" claim not found in "ear.veraison.key-attestation"`)
	}

	akpub, ok := v.(string)
	if !ok {
		return nil, errors.New(`"ear.veraison.key-attestation" malformed: "akpub" must be string`)
	}

	k, err := base64.RawURLEncoding.DecodeString(akpub)
	if err != nil {
		return nil, fmt.Errorf(`"ear.veraison.key-attestation" malformed: decoding "akpub": %w`, err)
	}

	pub, err := x509.ParsePKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf(`parsing "akpub" failed: %w`, err)
	}

	return pub, nil
}

// UpdateStatusFromTrustVector ensure that Status trustworthiness is not
// higher than is warranted by trust vector claims. For every claim that has
// been made (i.e. is not in TrustTierNone), if the claim's trust tier is lower
// than that of the Status, adjust the status to the claim's tier. This means
// that the overall result will not assert to be more trustworthy than
// individual vector claims (though it could be less trustworthy if had been
// manually set that way).
func (o *Appraisal) UpdateStatusFromTrustVector() {
	for _, claimValue := range o.TrustVector.AsMap() {
		claimTier := claimValue.GetTier()
		if *o.Status < claimTier {
			*o.Status = claimTier
		}
	}
}

// AsMap returns a map[string]interface{} with EAR Appraisal claim names mapped
// onto corresponding values.
func (o Appraisal) AsMap() map[string]interface{} {
	m, err := structAsMap(o, "json")
	if err != nil {
		// An error can only be returned if there is issue in implementation of
		// AttestationResult; specifically, if any of its
		// constituents incorrectly implement AsMap() themselves.
		panic(err)
	}
	return m
}

func (o Appraisal) validate() error {
	if o.Status == nil {
		return errors.New("missing mandatory 'ear.status'")
	}

	return nil
}

func ToAppraisal(v interface{}) (*Appraisal, error) {
	var appraisal Appraisal

	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, errors.New("not a JSON object")
	}

	parsers := map[string]parser{
		"ear.status": func(v interface{}) (interface{}, error) {
			return ToTrustTier(v)
		},
		"ear.trustworthiness-vector": func(v interface{}) (interface{}, error) {
			return ToTrustVector(v)
		},
		"ear.veraison.annotated-evidence": stringMapPtrParser,
		"ear.veraison.policy-claims":      stringMapPtrParser,
		"ear.veraison.key-attestation":    stringMapPtrParser,
	}

	err := populateStructFromMap(&appraisal, m, "json", parsers, stringPtrParser, true)

	return &appraisal, err
}
