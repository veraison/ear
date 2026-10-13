// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"

	"github.com/veraison/cmw"
	"github.com/veraison/eat"
)

func Example_encode_minimalist() {
	ar := AttestationResult{
		Submods: NewSubmods().AddAppraisal("test", &Appraisal{
			Status:             TrustTierAffirming,
			AppraisalPolicyIDs: []string{"policy://test/01234"},
		}),

		IssuedAt: 1666091373,
		VerifierID: &VerifierIdentity{
			Build:     "rrtrap-v1.0.0",
			Developer: "Acme Inc.",
		},
		Profile: eat.MustNewProfile("tag:ietf.org,2026:rats/ear#04"),
	}

	j, _ := ar.MarshalJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear_verifier_id":{"developer":"Acme Inc.","build":"rrtrap-v1.0.0"},"eat_profile":"tag:ietf.org,2026:rats/ear#04","iat":1666091373,"submods":{"test":{"ear_appraisal_policy_ids":["policy://test/01234"],"ear_status":"affirming"}}}
}

func Example_encode_hefty() {
	rawEvidence, _ := cmw.NewMonad("application/octet-stream", []byte{0xde, 0xad, 0xbe, 0xef})

	ar := AttestationResult{
		Submods: NewSubmods().AddAppraisal("test", &Appraisal{
			Status: TrustTierAffirming,
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
			AppraisalPolicyIDs: []string{"policy://test/01234"},
		}),

		IssuedAt:    1666091373,
		RawEvidence: rawEvidence,
		VerifierID: &VerifierIdentity{
			Build:     "rrtrap-v1.0.0",
			Developer: "Acme Inc.",
		},
		Profile: eat.MustNewProfile("tag:ietf.org,2026:rats/ear#04"),
	}

	j, _ := ar.MarshalJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear_raw_evidence":["application/octet-stream","3q2-7w"],"ear_verifier_id":{"developer":"Acme Inc.","build":"rrtrap-v1.0.0"},"eat_profile":"tag:ietf.org,2026:rats/ear#04","iat":1666091373,"submods":{"test":{"ear_appraisal_policy_ids":["policy://test/01234"],"ear_status":"affirming","ear_trustworthiness_vector":{"instance-identity":2,"configuration":2,"executables":3,"file-system":2,"hardware":2,"runtime-opaque":2,"storage-opaque":2,"sourced-data":2}}}}
}

func Example_encode_veraison_extensions() {
	ar := AttestationResult{
		Submods: NewSubmods().AddAppraisal("test", &Appraisal{
			Status:             TrustTierAffirming,
			AppraisalPolicyIDs: []string{"policy://test/01234"},
			AttesterClaims: map[eat.IntOrString]any{
				eat.IntOrStringFromString("k1"): "v1",
				eat.IntOrStringFromString("k2"): "v2",
			},
			VerifierClaims: map[eat.IntOrString]any{
				eat.IntOrStringFromString("bar"): "baz",
				eat.IntOrStringFromString("foo"): "bar",
			},
			Extensions: NewExtensions().StringSet(
				"ear_veraison_key_attestation",
				map[string]any{
					"akpub": "YWtwdWIK",
				},
			),
		}),

		IssuedAt: 1666091373,
		VerifierID: &VerifierIdentity{
			Build:     "rrtrap-v1.0.0",
			Developer: "Acme Inc.",
		},
		Profile: eat.MustNewProfile("tag:ietf.org,2026:rats/ear#04"),
	}

	j, _ := ar.MarshalJSON()

	fmt.Println(string(j))

	// Output:
	// {"ear_verifier_id":{"developer":"Acme Inc.","build":"rrtrap-v1.0.0"},"eat_profile":"tag:ietf.org,2026:rats/ear#04","iat":1666091373,"submods":{"test":{"ear_appraisal_policy_ids":["policy://test/01234"],"ear_attester_claims":{"k1":"v1","k2":"v2"},"ear_status":"affirming","ear_veraison_key_attestation":{"akpub":"YWtwdWIK"},"ear_verifier_claims":{"bar":"baz","foo":"bar"}}}}
}

func Example_decode_veraison_extensions() {
	j := `{
		"eat_profile": "tag:ietf.org,2026:rats/ear#04",
		"iat": 1666091373,
		"submods": {
			"test": {
				"ear_status": "affirming",
				"ear_appraisal_policy_ids": ["policy://test/01234"],
				"ear_attester_claims": {
					"k1": "v1",
					"k2": "v2"
				},
				"ear_veraison_key_attestation": {
					"akpub": "YWtwdWIK"
				},
				"ear_verifier_claims": {
					"bar": "baz",
					"foo": "bar"
				}
			}
		},
		"ear_verifier_id": {
			"developer": "Contributors to the Veraison project",
			"build": "v1.1.23"
		}
	}`
	var ar AttestationResult
	_ = ar.UnmarshalJSON([]byte(j))

	fmt.Println(ar.Submods["test"].Appraisal().Status.String())
	fmt.Println(ar.Submods["test"].Appraisal().AttesterClaims[eat.IntOrStringFromString("k1")])
	fmt.Println(ar.Submods["test"].Appraisal().VerifierClaims[eat.IntOrStringFromString("bar")])

	keyAttest, _ := ar.Submods["test"].Appraisal().Extensions.GetStringMap("ear_veraison_key_attestation")
	fmt.Println(keyAttest["akpub"])

	// Output:
	// affirming
	// v1
	// baz
	// YWtwdWIK
}

func Example_colors() {
	j := `{
		"submods": {
			"test": {
				"ear_status": "contraindicated",
				"ear_appraisal_policy_ids": ["policy://test/01234"],
				"ear_trustworthiness_vector": {
					"instance-identity": 96,
					"configuration": 96,
					"executables": 32,
					"hardware": 2
				}
			}
		},
		"iat":1666091373,
		"eat_profile": "tag:ietf.org,2026:rats/ear#04"
	}`

	var ar AttestationResult
	_ = ar.UnmarshalJSON([]byte(j))

	short, color := true, true

	fmt.Print(ar.Submods["test"].Appraisal().TrustVector.Report(short, color))

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
