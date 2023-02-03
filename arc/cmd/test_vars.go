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
    "ear.status": "affirming",
    "eat_profile": "tag:github.com,2022:veraison/ear",
    "iat": 1666091373,
    "ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d"
}`)
	testJWT = []byte(`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIuYXBwcmFpc2FsLXBvbGljeS1pZCI6Imh0dHBzOi8vdmVyYWlzb24uZXhhbXBsZS9wb2xpY3kvMS82MGEwMDY4ZCIsImVhci5yYXctZXZpZGVuY2UiOiIzcTItN3ciLCJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWFyLnRydXN0d29ydGhpbmVzcy12ZWN0b3IiOnsiY29uZmlndXJhdGlvbiI6MiwiZXhlY3V0YWJsZXMiOjMsImZpbGUtc3lzdGVtIjoyLCJoYXJkd2FyZSI6MiwiaW5zdGFuY2UtaWRlbnRpdHkiOjIsInJ1bnRpbWUtb3BhcXVlIjoyLCJzb3VyY2VkLWRhdGEiOjIsInN0b3JhZ2Utb3BhcXVlIjoyfSwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIyOnZlcmFpc29uL2VhciIsImlhdCI6MTY2NjA5MTM3M30.o7svjuK-8DxfePggisE_8H24hO6mpeIspYRDEnaTh0yGC6HG_IS9nXDmn3PllJEg0-Nara4YGhs7I5Tfi9gOsA`)
)
