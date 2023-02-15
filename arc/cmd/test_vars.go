// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

var (
	testEmptyKey = []byte{}
	testSKey     = []byte(`{
    "kty": "EC",
    "crv": "P-256",
    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
}`)
	testPKey = []byte(`{
    "kty": "EC",
    "crv": "P-256",
    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
}`)
	testEmptyClaimsSet = []byte(`{}`)
	testMiniClaimsSet  = []byte(`{
    "submods": {
	    "test": {
		    "ear.status": "affirming",
		    "ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d"
	    }
    },
    "eat_profile": "tag:github.com,2023:veraison/ear",
    "iat": 1666091373,
    "ear.verifier-id": {
	    "build": "rrtrap-v1.0.0",
	    "developer": "Acme Inc."
    }
}`)
	testJWT = []byte(`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIucmF3LWV2aWRlbmNlIjoiM3EyLTd3IiwiaWF0IjoxNjY2MDkxMzczLCJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJycnRyYXAtdjEuMC4wIiwiZGV2ZWxvcGVyIjoiQWNtZSBJbmMuIn0sImVhdF9wcm9maWxlIjoidGFnOmdpdGh1Yi5jb20sMjAyMzp2ZXJhaXNvbi9lYXIiLCJzdWJtb2RzIjp7InRlc3QiOnsiZWFyLnN0YXR1cyI6ImFmZmlybWluZyIsImVhci50cnVzdHdvcnRoaW5lc3MtdmVjdG9yIjp7Imluc3RhbmNlLWlkZW50aXR5IjoyLCJjb25maWd1cmF0aW9uIjoyLCJleGVjdXRhYmxlcyI6MywiZmlsZS1zeXN0ZW0iOjIsImhhcmR3YXJlIjoyLCJydW50aW1lLW9wYXF1ZSI6Miwic3RvcmFnZS1vcGFxdWUiOjIsInNvdXJjZWQtZGF0YSI6Mn0sImVhci5hcHByYWlzYWwtcG9saWN5LWlkIjoiaHR0cHM6Ly92ZXJhaXNvbi5leGFtcGxlL3BvbGljeS8xLzYwYTAwNjhkIn19fQ.8_kjzkq4nwp-LV04mK5a86FPMzllaKipboE3rg3T973lHdgsb1LG5Gndfj9R_zRAc6M4XIyt6ce8bQNVdIKtmg`)
)
