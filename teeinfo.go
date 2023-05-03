// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/base64"
	"errors"
	"fmt"
)

type VeraisonTeeInfo struct {
	TeeName    *string `json:"tee-name"`
	EvidenceID *string `json:"evidence-id"`
	Evidence   *[]byte `json:"evidence,omitempty"`
}

func str(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func ToVeraisonTeeInfo(v interface{}) (*VeraisonTeeInfo, error) {
	vMap, ok := v.(map[string]interface{})
	if !ok {
		return nil, errors.New(`unexpected format for "tee-info"`)
	}

	var teeInfo VeraisonTeeInfo

	for key, val := range vMap {
		s := str(val)
		switch key {
		case "tee-name":
			teeInfo.TeeName = &s
		case "evidence-id":
			teeInfo.EvidenceID = &s
		case "evidence":
			buf, err := base64.StdEncoding.DecodeString(str(val))
			if err != nil {
				return nil, fmt.Errorf(`decoding "evidence": %w`, err)
			}
			teeInfo.Evidence = &buf
		default:
			return nil, fmt.Errorf(`found unknown key %q in "tee-info" object`, key)
		}
	}

	if err := teeInfo.Validate(); err != nil {
		return nil, fmt.Errorf(`"tee-info" validation failed: %w`, err)
	}

	return &teeInfo, nil
}

func (o VeraisonTeeInfo) Validate() error {
	// NOTE: checking that (optional) evidence is base64-encoded is already
	// taken care of in ToVeraisonTeeInfo()

	if o.TeeName == nil || *o.TeeName == "" {
		return errors.New(`empty or missing "tee-name"`)
	}

	if o.EvidenceID == nil || *o.EvidenceID == "" {
		return errors.New(`empty or missing "evidence-id"`)
	}

	return nil
}
