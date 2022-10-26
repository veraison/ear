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
    "eat_profile": "tag:github.com/veraison/ar4si,2022-10-17",
    "iat": 1666091373,
    "ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d"
}`)
	testJWT = []byte(`eyJhbGciOiJFUzI1NiJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbS92ZXJhaXNvbi9hcjRzaSwyMDIyLTEwLTE3IiwiZWFyLnRydXN0d29ydGhpbmVzcy12ZWN0b3IiOnsiaW5zdGFuY2UtaWRlbnRpdHkiOjIsImNvbmZpZ3VyYXRpb24iOjIsImV4ZWN1dGFibGVzIjozLCJmaWxlLXN5c3RlbSI6MiwiaGFyZHdhcmUiOjIsInJ1bnRpbWUtb3BhcXVlIjoyLCJzdG9yYWdlLW9wYXF1ZSI6Miwic291cmNlZC1kYXRhIjoyfSwiZWFyLnJhdy1ldmlkZW5jZSI6IjNxMis3dz09IiwiaWF0IjoxNjY2MDkxMzczLCJlYXIuYXBwcmFpc2FsLXBvbGljeS1pZCI6Imh0dHBzOi8vdmVyYWlzb24uZXhhbXBsZS9wb2xpY3kvMS82MGEwMDY4ZCJ9.p0qLmOjCJchaMAiMQdFla_CWCzlcaY_dlUTjMhOTZJvKfyibsDKVSIPNJ-bxT7PpsjKDHwCGHggbihw68iZ5UA`)
)
