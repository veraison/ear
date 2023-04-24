// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"
)

func Example_encode_minimalist() {
	ar := AttestationResult{
		Submods: map[string]*Appraisal{
			"test": {
				Status:            &testStatus,
				AppraisalPolicyID: &testPolicyID,
			},
		},

		IssuedAt:   &testIAT,
		VerifierID: &testVerifierID,
		Profile:    &testProfile,
	}

	j, _ := ar.MarshalJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear.verifier-id":{"build":"rrtrap-v1.0.0","developer":"Acme Inc."},"eat_profile":"tag:github.com,2023:veraison/ear","iat":1666091373,"submods":{"test":{"ear.appraisal-policy-id":"policy://test/01234","ear.status":"affirming"}}}
}

func Example_encode_hefty() {
	rawEvidence := B64Url{0xde, 0xad, 0xbe, 0xef}

	ar := AttestationResult{
		Submods: map[string]*Appraisal{
			"test": {
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
				AppraisalPolicyID: &testPolicyID,
			},
		},
		RawEvidence: &rawEvidence,
		IssuedAt:    &testIAT,
		VerifierID:  &testVerifierID,
		Profile:     &testProfile,
	}

	j, _ := ar.MarshalJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear.raw-evidence":"3q2-7w","ear.verifier-id":{"build":"rrtrap-v1.0.0","developer":"Acme Inc."},"eat_profile":"tag:github.com,2023:veraison/ear","iat":1666091373,"submods":{"test":{"ear.appraisal-policy-id":"policy://test/01234","ear.status":"affirming","ear.trustworthiness-vector":{"configuration":2,"executables":3,"file-system":2,"hardware":2,"instance-identity":2,"runtime-opaque":2,"sourced-data":2,"storage-opaque":2}}}}
}

func Example_encode_veraison_extensions() {
	ar := testAttestationResultsWithVeraisonExtns

	j, _ := ar.MarshalJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear.verifier-id":{"build":"rrtrap-v1.0.0","developer":"Acme Inc."},"eat_profile":"tag:github.com,2023:veraison/ear","iat":1666091373,"submods":{"test":{"ear.appraisal-policy-id":"policy://test/01234","ear.status":"affirming","ear.veraison.annotated-evidence":{"k1":"v1","k2":"v2"},"ear.veraison.key-attestation":{"key1":"testkey"},"ear.veraison.policy-claims":{"bar":"baz","foo":"bar"}}}}
}

func Example_decode_veraison_extensions() {
	j := `{
		"eat_profile": "tag:github.com,2023:veraison/ear",
		"iat": 1666091373,
		"submods": {
			"test": {
				"ear.status": "affirming",
				"ear.appraisal-policy-id": "policy://test/01234",
				"ear.veraison.annotated-evidence": {
					"k1": "v1",
					"k2": "v2"
				},
				"ear.veraison.key-attestation":{
					"key1":"testkey"
				},
				"ear.veraison.policy-claims": {
					"bar": "baz",
					"foo": "bar"
				}
			}
		}
	}`
	var ar AttestationResult
	_ = ar.UnmarshalJSON([]byte(j))

	fmt.Println(TrustTierToString[*ar.Submods["test"].Status])
	fmt.Println((*ar.Submods["test"].VeraisonAnnotatedEvidence)["k1"])
	fmt.Println((*ar.Submods["test"].VeraisonPolicyClaims)["bar"])

	// Output:
	// affirming
	// v1
	// baz
}

func Example_colors() {
	j := `{
		"submods": {
			"test": {
				"ear.status": "contraindicated",
				"ear.appraisal-policy-id": "policy://test/01234",
				"ear.trustworthiness-vector": {
					"instance-identity": 96,
					"configuration": 96,
					"executables": 32,
					"hardware": 2
				}
			}
		},
		"iat":1666091373,
		"eat_profile": "tag:github.com,2023:veraison/ear"
	}`

	var ar AttestationResult
	_ = ar.UnmarshalJSON([]byte(j))

	short, color := true, true

	fmt.Print(ar.Submods["test"].TrustVector.Report(short, color))

	// Output:
	// Instance Identity [\033[41mcontraindicated\033[0m]: recognized but not trustworthy
	// Configuration [\033[41mcontraindicated\033[0m]: unacceptable security vulnerabilities
	// Executables [\033[43mwarning\033[0m]: recognized but known bugs or vulnerabilities
	// File System [\033[47mnone\033[0m]: no claim being made
	// Hardware [\033[42maffirming\033[0m]: genuine
	// Runtime Opaque [\033[47mnone\033[0m]: no claim being made
	// Storage Opaque [\033[47mnone\033[0m]: no claim being made
	// Sourced Data [\033[47mnone\033[0m]: no claim being made
}
