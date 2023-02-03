// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// EatProfile is the EAT profile implemented by this package
const EatProfile = "tag:github.com,2022:veraison/ear"

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
	TrustTierToString = map[TrustTier]string{
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

	IntToTrustTier = map[int]TrustTier{
		0:  TrustTierNone,
		2:  TrustTierAffirming,
		32: TrustTierWarning,
		96: TrustTierContraindicated,
	}
)

// NewTrustTier returns a pointer to a newly-created TrustTier that has the
// specified value. If the provided value is invalid for a TrustTier,
// TrustTierNone will be used instead.
// (This is essentially a Must- wrapper for ToTrustTier().)
func NewTrustTier(v interface{}) *TrustTier {
	tt, err := ToTrustTier(v)

	if err != nil {
		none := TrustTierNone
		return &none
	}

	return tt
}

func getTrustTierFromInt(i int) (TrustTier, error) {
	tier, ok := IntToTrustTier[i]
	if !ok {
		return TrustTierNone, fmt.Errorf("not a valid TrustTier value: %d", i)
	}

	return tier, nil
}

func getTrustTierFromString(s string) (TrustTier, error) {
	tier, ok := StringToTrustTier[s]
	if !ok {
		i, err := strconv.Atoi(s)
		if err == nil {
			return getTrustTierFromInt(i)
		}
		return TrustTierNone, fmt.Errorf("not a valid TrustTier name: %q", s)
	}

	return tier, nil
}

func ToTrustTier(v interface{}) (*TrustTier, error) {
	var (
		err error
		ok  bool

		tier = TrustTierNone
	)

	switch t := v.(type) {
	case string:
		tier, err = getTrustTierFromString(t)
	case []byte:
		tier, err = getTrustTierFromString(string(t))
	case TrustClaim:
		tier = t.GetTier()
	case int:
		tier, err = getTrustTierFromInt(t)
	case int8:
		tier, err = getTrustTierFromInt(int(t))
	case int16:
		tier, err = getTrustTierFromInt(int(t))
	case int32:
		tier, err = getTrustTierFromInt(int(t))
	case int64:
		tier, err = getTrustTierFromInt(int(t))
	case uint8:
		tier, err = getTrustTierFromInt(int(t))
	case uint16:
		tier, err = getTrustTierFromInt(int(t))
	case uint32:
		tier, err = getTrustTierFromInt(int(t))
	case uint:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustTier value: %d", t)
		} else {
			tier, err = getTrustTierFromInt(int(t))
		}
	case uint64:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustTier value: %d", t)

		} else {
			tier, err = getTrustTierFromInt(int(t))
		}
	case float64:
		tier, ok = IntToTrustTier[int(t)]
		if !ok {
			err = fmt.Errorf("not a valid TrustTier value: %f (%d)", t, int(t))
		}
	case json.Number:
		i, e := t.Int64()
		if e != nil {
			err = fmt.Errorf("not a valid TrustTier value: %v: %w", t, err)
		} else {
			tier, ok = IntToTrustTier[int(i)]
			if !ok {
				err = fmt.Errorf("not a valid TrustTier value: %v (%d)", t, int(i))
			}
		}
	default:
		err = fmt.Errorf("cannot convert %v (type %T) to TrustTier", t, t)
	}

	return &tier, err
}

func (o TrustTier) Format(color bool) string {
	if color {
		return o.ColorString()
	}

	return o.String()
}

func (o TrustTier) String() string {
	return TrustTierToString[o]
}

func (o TrustTier) ColorString() string {
	const (
		reset  = `\033[0m`
		red    = `\033[41m`
		yellow = `\033[43m`
		green  = `\033[42m`
		white  = `\033[47m`

		unexpected = `\033[1;33;41m`
	)

	var color string
	switch o {
	case TrustTierNone:
		color = white
	case TrustTierAffirming:
		color = green
	case TrustTierWarning:
		color = yellow
	case TrustTierContraindicated:
		color = red
	default:
		color = unexpected
	}

	return color + o.String() + reset
}

func (o TrustTier) MarshalJSON() ([]byte, error) {
	var (
		s  string
		ok bool
	)

	s, ok = TrustTierToString[o]
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
	var err error

	var missing, invalid []string

	expected := []string{
		"ear.status",
		"eat_profile",
		"iat",
		"ear.trustworthiness-vector",
		"ear.raw-evidence",
		"ear.appraisal-policy-id",
		"ear.veraison.processed-evidence",
		"ear.veraison.verifier-added-claims",
	}
	extra := getExtraKeys(m, expected)

	v, ok := m["ear.status"]
	if ok {
		o.Status, err = ToTrustTier(v)
		if err != nil {
			invalid = append(invalid, "'ear.status'")
		}
	} else {
		missing = append(missing, "'ear.status'")
	}

	v, ok = m["eat_profile"]
	if ok {
		profile, okay := v.(string)
		if !okay {
			invalid = append(invalid, "'eat_profiles'")
		}
		o.Profile = &profile

	} else {
		missing = append(missing, "'eat_profile'")
	}

	v, ok = m["iat"]
	if ok {
		var iat int64
		switch t := v.(type) {
		case float64:
			iat = int64(t)
		case int:
			iat = int64(t)
		case int64:
			iat = t
		default:
			invalid = append(invalid, "'iat'")
		}
		o.IssuedAt = &iat
	} else {
		missing = append(missing, "'iat'")
	}

	v, ok = m["ear.trustworthiness-vector"]
	if ok {
		o.TrustVector, err = ToTrustVector(v)
		if err != nil {
			invalid = append(invalid, fmt.Sprintf("'ear.trustworthiness-vector' (%s)", err))
		}
	}

	v, ok = m["ear.raw-evidence"]
	if ok {
		rawEvString, okay := v.(string)
		if !okay {
			invalid = append(invalid, "'ear.raw-evidence'")
		}

		decodedRawEv, err := base64.RawURLEncoding.DecodeString(rawEvString)
		if err != nil {
			invalid = append(invalid, "'ear.raw-evidence'")
		}

		o.RawEvidence = (*B64Url)(&decodedRawEv)
	}

	v, ok = m["ear.appraisal-policy-id"]
	if ok {
		stringVal, okay := v.(string)
		if !okay {
			invalid = append(invalid, "'ear.appraisal-policy-id'")
		}
		o.AppraisalPolicyID = &stringVal
	}

	v, ok = m["ear.veraison.processed-evidence"]
	if ok {
		processedEvidence, okay := v.(map[string]interface{})
		if !okay {
			invalid = append(invalid, "'ear.veraison.processed-evidence'")
		}
		o.VeraisonProcessedEvidence = &processedEvidence
	}

	v, ok = m["ear.veraison.verifier-added-claims"]
	if ok {
		addedClaims, okay := v.(map[string]interface{})
		if !okay {
			invalid = append(invalid, "'ear.veraison.verifier-added-claims'")
		}
		o.VeraisonVerifierAddedClaims = &addedClaims

	}

	var problems []string

	if len(missing) > 0 {
		msg := fmt.Sprintf("missing mandatory %s", strings.Join(missing, ", "))
		problems = append(problems, msg)
	}

	if len(invalid) > 0 {
		msg := fmt.Sprintf("invalid values(s) for %s", strings.Join(invalid, ", "))
		problems = append(problems, msg)
	}

	if len(extra) > 0 {
		msg := fmt.Sprintf("unexpected %s", strings.Join(extra, ", "))
		problems = append(problems, msg)
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}

	return nil
}
