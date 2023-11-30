// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import "fmt"

// UnprocessedEvidence contains the details of Evidence
// which te Verifier could not Appraise
type UnprocessedEvidence struct {
	// Build uniquely identifies the software build running the verifier.
	MediaType *string `json:"media_type"`
	// Developer uniquely identifies the organizational unit responsible
	// for this build.
	Data *[]byte `json:"data"`
}

func (o *UnprocessedEvidence) SetMediaType(mt *string) error {
	if *mt == "" {
		return fmt.Errorf("nil mt string")
	}
	o.MediaType = mt
	return nil
}

func (o *UnprocessedEvidence) SetEvidence(data *[]byte) error {
	if len(*data) == 0 {
		return fmt.Errorf("nil data supplied")
	}
	o.Data = data
	return nil
}
