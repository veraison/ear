// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
	"fmt"
)

func Example_encode_minimalist() {
	ar := AttestationResult{
		Status: &testStatus,

		IssuedAt:          &testIAT,
		AppraisalPolicyID: &testPolicyID,
		Profile:           &testProfile,
	}

	j, _ := ar.ToJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear.status":"affirming","eat_profile":"tag:github.com/veraison/ar4si,2022-10-17","iat":1666091373,"ear.appraisal-policy-id":"https://veraison.example/policy/1/60a0068d"}
}

func Example_encode_hefty() {
	rawEvidence := []byte{0xde, 0xad, 0xbe, 0xef}

	ar := AttestationResult{
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
		IssuedAt:          &testIAT,
		AppraisalPolicyID: &testPolicyID,
		Profile:           &testProfile,
	}

	j, _ := ar.ToJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear.status":"affirming","eat_profile":"tag:github.com/veraison/ar4si,2022-10-17","ear.trustworthiness-vector":{"instance-identity":2,"configuration":2,"executables":3,"file-system":2,"hardware":2,"runtime-opaque":2,"storage-opaque":2,"sourced-data":2},"ear.raw-evidence":"3q2+7w==","iat":1666091373,"ear.appraisal-policy-id":"https://veraison.example/policy/1/60a0068d"}
}

func Example_encode_veraison_extensions() {
	ar := testAttestationResultsWithVeraisonExtns

	j, _ := ar.ToJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear.status":"affirming","eat_profile":"tag:github.com/veraison/ar4si,2022-10-17","iat":1666091373,"ear.appraisal-policy-id":"https://veraison.example/policy/1/60a0068d","veraison.processed-evidence":{"k1":"v1","k2":"v2"},"veraison.verifier-added-claims":{"bar":"baz","foo":"bar"}}
}

func Example_decode_veraison_extensions() {
	j := `{
		"ear.status": "affirming",
		"iat":1666091373,
		"ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d",
		"veraison.processed-evidence": {
			"k1": "v1",
			"k2": "v2"
		},
		"veraison.verifier-added-claims": {
			"bar": "baz",
			"foo": "bar"
		},
		"eat_profile": "tag:github.com/veraison/ar4si,2022-10-17"
	}`
	var ar AttestationResult
	_ = ar.FromJSON([]byte(j))

	fmt.Println(StatusTierToString[*ar.Status])
	fmt.Println((*ar.VeraisonProcessedEvidence)["k1"])
	fmt.Println((*ar.VeraisonVerifierAddedClaims)["bar"])

	// Output:
	// affirming
	// v1
	// baz
}

func Example_colors() {
	j := `{
		"ear.status": "contraindicated",
		"iat":1666091373,
		"ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d",
		"ear.trustworthiness-vector": {
			"instance-identity": 96,
			"configuration": 96,
			"executables": 32,
			"hardware": 2
		},
		"eat_profile": "tag:github.com/veraison/ar4si,2022-10-17"
	}`

	var ar AttestationResult
	_ = ar.FromJSON([]byte(j))

	short, color := true, true

	fmt.Print(ar.TrustVector.Report(short, color))

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
