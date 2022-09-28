// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

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

type TrustVector struct {
	InstanceIdentity int8 `json:"instance-identity"`
	Configuration    int8 `json:"configuration"`
	Executables      int8 `json:"executables"`
	FileSystem       int8 `json:"file-system"`
	Hardware         int8 `json:"hardware"`
	RuntimeOpaque    int8 `json:"runtime-opaque"`
	StorageOpaque    int8 `json:"storage-opaque"`
	SourcedData      int8 `json:"sourced-data"`
}

type AttestationResults struct {
	Status            *TrustTier   `json:"status"`
	TrustVector       *TrustVector `json:"trust-vector,omitempty"`
	RawEvidence       *[]byte      `json:"raw-evidence,omitempty"`
	Timestamp         *time.Time   `json:"timestamp"`
	AppraisalPolicyID *string      `json:"appraisal-policy-id"`
	Extensions
}

func (o AttestationResults) ToJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(o)
}

func (o *AttestationResults) FromJSON(data []byte) error {
	err := json.Unmarshal(data, o)
	if err == nil {
		return o.Validate()
	}
	return err
}

func (o AttestationResults) Validate() error {
	missing := []string{}

	if o.Status == nil {
		missing = append(missing, "'status'")
	}

	if o.Timestamp == nil {
		missing = append(missing, "'timestamp'")
	}

	if o.AppraisalPolicyID == nil {
		missing = append(missing, "'appraisal-policy-id'")
	}

	if len(missing) == 0 {
		return nil
	}

	return fmt.Errorf("missing mandatory field(s): %s", strings.Join(missing, ", "))
}

type Extensions struct {
	VeraisonProcessedEvidence   *map[string]interface{} `json:"veraison.processed-evidence,omitempty"`
	VeraisonVerifierAddedClaims *map[string]interface{} `json:"veraison.verifier-added-claims,omitempty"`
}

func (o *AttestationResults) Verify(data []byte, alg jwa.KeyAlgorithm, key interface{}) error {
	buf, err := jws.Verify(data, jws.WithKey(alg, key))
	if err != nil {
		return fmt.Errorf("failed verifying JWT message: %w", err)
	}

	// TODO(tho) add any JWT specific checks on top of the base JWS verification

	var ar AttestationResults

	err = ar.FromJSON(buf)
	if err != nil {
		return fmt.Errorf("failed parsing JWT payload: %w", err)
	}

	*o = ar

	return nil
}

func (o AttestationResults) Sign(alg jwa.KeyAlgorithm, key interface{}) ([]byte, error) {
	payload, err := o.ToJSON()
	if err != nil {
		return nil, err
	}

	return jws.Sign(payload, jws.WithKey(alg, key))
}
