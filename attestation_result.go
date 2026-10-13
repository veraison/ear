// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/veraison/cmw"
	"github.com/veraison/eat"
)

var (
	// EatProfile is the EAT profile implemented by this package
	EatProfile = eat.MustNewProfile("tag:ietf.org,2026:rats/ear#04")

	// Trustee profile name which is an alias for the Veraison one.
	// Both names will be replaced with a neutral one:
	// https://github.com/ietf-rats-wg/draft-ietf-rats-ear/pull/47
	EatTrusteeProfile = eat.MustNewProfile("tag:github.com,2024:confidential-containers/Trustee")
)

// JWTKeyEntry contains a key used to verify JWT signatures.
type JWTKeyEntry struct {
	// Alg is the algorithm the Key is intended to be used with.
	Alg jwa.KeyAlgorithm
	// Key is the key used to verify JWT signatures.
	Key any
}

// AttestationResult represents the result of one or more evidence Appraisals
// by the verifier.  It is serialized to JSON and signed by the verifier using
// JWT.
type AttestationResult struct {
	Profile        *eat.Profile      `json:"eat_profile"`
	Status         *TrustTier        `json:"ear_status,omitempty"`
	IssuedAt       int64             `json:"iat"`
	Expiry         *int64            `json:"exp,omitempty"`
	VerifierID     *VerifierIdentity `json:"ear_verifier_id"`
	RawEvidence    *cmw.CMW          `json:"ear_raw_evidence,omitempty"`
	Submods        Submods           `json:"submods"`
	Nonce          *eat.Nonce        `json:"eat_nonce,omitempty"`
	DeviceTopology DeviceTopology    `json:"ear_device_topology,omitempty"`
	Extensions     *Extensions       `json:"-"`
}

// NewAttestationResult returns a pointer to a new AttestationResult.
func NewAttestationResult(
	verifierBuild string,
	verifierDeveloper string,
) *AttestationResult {
	iat := time.Now().Unix()

	return &AttestationResult{
		Profile:    EatProfile,
		IssuedAt:   iat,
		Submods:    NewSubmods(),
		VerifierID: NewVerifierIdentity(verifierBuild, verifierDeveloper),
		Extensions: NewExtensions(),
	}
}

// NewAttestationResultWithAppraisal returns a pointer to a new
// AttestationResult that has a single submod Appraisal under the specified
// submod name.
func NewAttestationResultWithAppraisal(
	submodName string,
	verifierBuild string,
	verifierDeveloper string,
) *AttestationResult {
	result := NewAttestationResult(verifierBuild, verifierDeveloper)
	result.Submods.AddAppraisal(submodName, NewAppraisal())
	return result
}

// AttestationResultFromVerifiedJWT returns a pointer to an AttestationResult
// extracted from the provided JWT after verifying its signature using the
// provided key and algorithm.
func AttestationResultFromVerifiedJWT(
	data []byte,
	keyEntry *JWTKeyEntry,
) (*AttestationResult, error) {
	var ret AttestationResult
	if err := ret.FromVerifiedJWT(data, keyEntry.Alg, keyEntry.Key); err != nil {
		return nil, err
	}

	return &ret, nil
}

// AttestationResultFromUnverifiedJWT returns a pointer to an AttestationResult
// extracted from the provided JWT without verifying its signature.
func AttestationResultFromUnverifiedJWT(data []byte) (*AttestationResult, error) {
	var ret AttestationResult
	if err := ret.FromUnverifiedJWT(data); err != nil {
		return nil, err
	}

	return &ret, nil
}

// AttestationResultFromNestedToken returns a pointer to an AttestationResult
// extracted from the provided NestedToken. An error is returned if the
// NestedToken does not contain a valid AttestationResult. No signature
// verification is performed.
func AttestationResultFromNestedToken(token *eat.NestedToken) (*AttestationResult, error) {
	switch token.Type {
	case eat.NestedTokenBundle, eat.NestedTokenDigest, eat.NestedTokenInvalid:
		return nil, fmt.Errorf("cannot create AttestationResult from %s", token.Type.String())
	case eat.NestedTokenCBOR:
		// TODO(setrofim): this requires CBOR/CWT support
		return nil, fmt.Errorf("CBOR encoding not supported")
	case eat.NestedTokenJWT:
		var encodedToken string
		if err := json.Unmarshal(token.Data, &encodedToken); err != nil {
			return nil, err
		}

		return AttestationResultFromUnverifiedJWT([]byte(encodedToken))
	default:
		// The cases are exhaustive.
		panic(token.Type)
	}
}

// AttestationResultFromAny converts provided input into an AttestationResult,
// returning a pointer to it or an error if conversion is not possible or the
// AttestationResult is invalid.
func AttestationResultFromAny(input any) (*AttestationResult, error) {
	var result AttestationResult

	switch t := input.(type) {
	case *AttestationResult:
		return t, nil
	case AttestationResult:
		return &t, nil
	case *eat.NestedToken:
		return AttestationResultFromNestedToken(t)
	case eat.NestedToken:
		return AttestationResultFromNestedToken(&t)
	}

	claims, err := eat.IntOrStringMapFromAny(input)
	if err != nil {
		return nil, err
	}

	var extensions Extensions

	for key, value := range claims {
		switch key {
		case eat.IntOrStringFromString("eat_profile"):
			profileText, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("eat_profile: expected a string, got %T", value)
			}

			profile, err := eat.NewProfile(profileText)
			if err != nil {
				return nil, fmt.Errorf("eat_profile: %w", err)
			}

			result.Profile = profile
		case eat.IntOrStringFromString("ear_status"):
			tier, err := TrustTierFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_status: %w", err)
			}

			result.Status = &tier
		case eat.IntOrStringFromString("iat"):
			iat, err := Int64FromAny(value)
			if err != nil {
				return nil, fmt.Errorf("iat: %w", err)
			}

			result.IssuedAt = iat
		case eat.IntOrStringFromString("exp"):
			exp, err := Int64FromAny(value)
			if err != nil {
				return nil, fmt.Errorf("exp: %w", err)
			}

			result.Expiry = &exp
		case eat.IntOrStringFromString("ear_verifier_id"):
			verifierID, err := VerifierIdentityFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_verifier_id: %w", err)
			}

			result.VerifierID = verifierID
		case eat.IntOrStringFromString("ear_raw_evidence"):
			evidence, err := CMWFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_raw_evidence: %w", err)
			}

			result.RawEvidence = evidence
		case eat.IntOrStringFromString("submods"):
			submods, err := SubmodsFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("submods: %w", err)
			}

			result.Submods = submods
		case eat.IntOrStringFromString("eat_nonce"):
			nonce, err := eat.NonceFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("eat_nonce: %w", err)
			}

			result.Nonce = nonce
		case eat.IntOrStringFromString("ear_device_topology"):
			topology, err := DeviceTopologyFromAny(value)
			if err != nil {
				return nil, fmt.Errorf("ear_device_topology: %w", err)
			}

			result.DeviceTopology = topology
		default:
			extensions.Set(key, value)
		}
	}

	result.Extensions = &extensions

	if err := result.Validate(); err != nil {
		return nil, err
	}

	return &result, nil
}

// Map returns a map[string]any with EAR claim names mapped onto corresponding
// values. If there are conflicts between standard claims and extension values,
// nil is returned instead.
func (o *AttestationResult) Map() map[eat.IntOrString]any {
	ret, _ := structWithExtensionsToMap(o, "json")
	return ret
}

// UpdateStatusFromSubmods ensure that Status trustworthiness of each submod
// Appraisal or AttestationResult is not higher than is warranted by its trust
// vector claims. For every claim that has been made (i.e. is not NoClaim), if
// the claim's trust tier is lower than that of the Status, adjust the status
// to the claim's tier. This means that the overall result will not assert to
// be more trustworthy than individual vector claims (though it could be less
// trustworthy if had been manually set that way). If submods contain nested
// tokens, an attempt is made to verify its signature using provided keys. If
// no keys were provided, or if verification fails using all provided keys,
// status is set to TrustTierIncomplete.
func (o *AttestationResult) UpdateStatusFromSubmods(keys ...*JWTKeyEntry) {
	status := TrustTierNone
	if o.Status != nil {
		status = *o.Status
	}

	for _, submod := range o.Submods {
		if submod == nil || submod.value == nil {
			continue
		}

		switch t := submod.Value().(type) {
		case *Appraisal:
			t.UpdateStatusFromTrustVector()
			if t.Status.WorseThan(status) {
				status = t.Status
			}
		case *AttestationResult:
			t.UpdateStatusFromSubmods(keys...)
			if t.Status.WorseThan(status) {
				status = *t.Status
			}
		case *eat.NestedToken:
			if t.Type != eat.NestedTokenJWT {
				status = TrustTierIncomplete
				continue
			}

			var jwtText string
			if err := json.Unmarshal(t.Data, &jwtText); err != nil {
				status = TrustTierIncomplete
				continue
			}

			verified := false
			for _, keyEntry := range keys {
				result, err := AttestationResultFromVerifiedJWT([]byte(jwtText), keyEntry)
				if err != nil {
					continue
				}

				verified = true

				result.UpdateStatusFromSubmods(keys...)
				if result.Status.WorseThan(status) {
					status = *result.Status
				}
			}

			if !verified {
				status = TrustTierIncomplete
			}
		default:
			// cases are exhaustive
			panic(fmt.Sprintf("unexpected submod type %T", t))
		}
	}

	o.Status = &status
}

// Validate returns an error if any of the AttestationResult fields contain
// invalid values or if mandatory claims are missing.
func (o *AttestationResult) Validate() error {
	var missing, invalid, summary []string

	if o.Profile == nil {
		missing = append(missing, "'eat_profile'")
	} else if o.Profile.String() != EatProfile.String() &&
		o.Profile.String() != EatTrusteeProfile.String() {
		invalid = append(invalid, fmt.Sprintf("eat_profile (%s)", *o.Profile))
	}

	if o.IssuedAt == 0 {
		missing = append(missing, "'iat'")
	}

	if o.VerifierID == nil {
		missing = append(missing, "'ear_verifier_id'")
	}

	if o.Submods.IsEmpty() {
		missing = append(missing, "'submods'")
	} else if err := o.Submods.Validate(); err != nil {
		invalid = append(invalid, fmt.Sprintf("submods: %s", err.Error()))
	}

	var badTopologyEntries []string
	for submodName := range o.DeviceTopology {
		_, ok := o.Submods[submodName]
		if !ok {
			badTopologyEntries = append(badTopologyEntries, submodName)
		}
	}
	if len(badTopologyEntries) != 0 {
		bad := strings.Join(badTopologyEntries, ",")
		invalid = append(invalid, fmt.Sprintf("ear_device_topology entries not in submods: %s", bad))
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

// SignJWT validates the AttestationResult object, encodes it to JSON and wraps it
// in a JWT using the supplied private key for signing.  The key must be
// compatible with the requested signing algorithm.  On success, the complete
// JWT token is returned.
func (o *AttestationResult) SignJWT(alg jwa.KeyAlgorithm, key any) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	claims := o.Map()
	if claims == nil {
		return nil, fmt.Errorf("extensions conflict with standard claims")
	}

	token := jwt.New()
	for k, v := range claims {
		// token.Set() will convert int64 but not *int64 to time.Time
		// when setting exp claim.
		if k == eat.IntOrStringFromString("exp") {
			v = *v.(*int64)
		}

		if err := token.Set(k.String(), v); err != nil {
			return nil, fmt.Errorf("setting %s: %w", k, err)
		}
	}

	return jwt.Sign(token, jwt.WithKey(alg, key))
}

// FromVerifiedJWT cryptographically verifies the JWT data using the supplied key and
// algorithm.  The payload is then parsed and validated.  On success, the target
// AttestationResult object is populated with the decoded claims (possibly
// including the Trustworthiness vector).
func (o *AttestationResult) FromVerifiedJWT(data []byte, alg jwa.KeyAlgorithm, key any) error {
	token, err := jwt.Parse(data, jwt.WithKey(alg, key), jwt.WithStrictBase64Encoding(false))
	if err != nil {
		return fmt.Errorf("jwt: %w", err)
	}

	return o.fromJWTToken(token)
}

// FromUnverifiedJWT populates the AttestationResult using claims parsed from
// the provided JWT. No signature verification is performed.
func (o *AttestationResult) FromUnverifiedJWT(data []byte) error {
	token, err := jwt.ParseInsecure(data, jwt.WithStrictBase64Encoding(false))
	if err != nil {
		return fmt.Errorf("jwt: %w", err)
	}

	return o.fromJWTToken(token)
}

// MarshalJSON validates and serializes to JSON an AttestationResult object
func (o *AttestationResult) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	claims, err := structWithExtensionsToMap(o, "json")
	if err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}

// MarshalJSONIndent is like MarshalJSON but applies Indent to format the
// output. Each JSON element in the output will begin on a new line beginning
// with prefix followed by one or more copies of indent according to the
// indentation nesting.
func (o *AttestationResult) MarshalJSONIndent(prefix, indent string) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	claims, err := structWithExtensionsToMap(o, "json")
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(claims, prefix, indent)
}

type resultUnmarshalHelper AttestationResult

// UnmarshalJSON de-serializes an AttestationResult object from its JSON
// representation and validates it.
func (o *AttestationResult) UnmarshalJSON(data []byte) error { // nolint:dupl
	if err := json.Unmarshal(data, (*resultUnmarshalHelper)(o)); err != nil {
		return err
	}

	var claims map[eat.IntOrString]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return err
	}

	var extensions Extensions
	knownLabels := getTagLabels(o, "json")
	for label, value := range claims {
		if _, isKnown := knownLabels[label]; !isKnown {
			extensions.Set(label, value)
		}
	}

	o.Extensions = &extensions

	if err := o.Validate(); err != nil {
		return err
	}

	return nil
}

func (o *AttestationResult) fromJWTToken(token jwt.Token) error {
	claims := maps.Collect(token.Claims())
	if iat, ok := token.IssuedAt(); ok {
		claims["iat"] = iat.Unix()
	}
	if exp, ok := token.Expiration(); ok {
		claims["exp"] = exp.Unix()
	}

	result, err := AttestationResultFromAny(claims)
	if err != nil {
		return err
	}

	*o = *result

	return nil
}
