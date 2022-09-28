// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
	"fmt"
)

func Example_encode_minimalist() {
	ar := AttestationResults{
		Status:            &testStatus,
		Timestamp:         &testTimestamp,
		AppraisalPolicyID: &testPolicyID,
	}

	j, _ := ar.ToJSON()

	fmt.Println(string(j))

	// Output:
	// {"status":"affirming","timestamp":"2022-09-26T17:29:00Z","appraisal-policy-id":"https://veraison.example/policy/1/60a0068d"}
}

func Example_encode_hefty() {
	rawEvidence := []byte{0xde, 0xad, 0xbe, 0xef}

	ar := AttestationResults{
		Status: &testStatus,
		TrustVector: &TrustVector{
			InstanceIdentity: 2,
			Configuration:    2,
			Executables:      3,
			FileSystem:       2,
			Hardware:         2,
			RuntimeOpaque:    2,
			StorageOpaque:    2,
			SourcedData:      2,
		},
		RawEvidence:       &rawEvidence,
		Timestamp:         &testTimestamp,
		AppraisalPolicyID: &testPolicyID,
	}

	j, _ := ar.ToJSON()

	fmt.Println(string(j))

	// Output:
	// {"status":"affirming","trust-vector":{"instance-identity":2,"configuration":2,"executables":3,"file-system":2,"hardware":2,"runtime-opaque":2,"storage-opaque":2,"sourced-data":2},"raw-evidence":"3q2+7w==","timestamp":"2022-09-26T17:29:00Z","appraisal-policy-id":"https://veraison.example/policy/1/60a0068d"}
}

func Example_encode_veraison_extensions() {
	ar := testAttestationResultsWithVeraisonExtns

	j, _ := ar.ToJSON()

	fmt.Println(string(j))

	// Output:
	// {"status":"affirming","timestamp":"2022-09-26T17:29:00Z","appraisal-policy-id":"https://veraison.example/policy/1/60a0068d","veraison.processed-evidence":{"k1":"v1","k2":"v2"},"veraison.verifier-added-claims":{"bar":"baz","foo":"bar"}}
}

func Example_decode_veraison_extensions() {
	j := `{
		"status": "affirming",
		"timestamp": "2022-09-26T17:29:00Z",
		"appraisal-policy-id": "https://veraison.example/policy/1/60a0068d",
		"veraison.processed-evidence": {
			"k1": "v1",
			"k2": "v2"
		},
		"veraison.verifier-added-claims": {
			"bar": "baz",
			"foo": "bar"
		}
	}`
	var ar AttestationResults
	_ = ar.FromJSON([]byte(j))

	fmt.Println(StatusTierToString[*ar.Status])
	fmt.Println((*ar.VeraisonProcessedEvidence)["k1"])
	fmt.Println((*ar.VeraisonVerifierAddedClaims)["bar"])

	// Output:
	// affirming
	// v1
	// baz
}
