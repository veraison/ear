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
	testJWT = []byte(`eyJhbGciOiJFUzI1NiJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIyOnZlcmFpc29uL2VhciIsImVhci50cnVzdHdvcnRoaW5lc3MtdmVjdG9yIjp7Imluc3RhbmNlLWlkZW50aXR5IjoyLCJjb25maWd1cmF0aW9uIjoyLCJleGVjdXRhYmxlcyI6MywiZmlsZS1zeXN0ZW0iOjIsImhhcmR3YXJlIjoyLCJydW50aW1lLW9wYXF1ZSI6Miwic3RvcmFnZS1vcGFxdWUiOjIsInNvdXJjZWQtZGF0YSI6Mn0sImVhci5yYXctZXZpZGVuY2UiOiIzcTIrN3c9PSIsImlhdCI6MTY2NjA5MTM3MywiZWFyLmFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQifQ.ZA_UPhIYr6n4e5h56jPieVDs6Zu39cI1fwrfqWKbZ9k0iXSt7ikEj4mlfW3RZX-_UYDI234JE7L-caltAtaRow`)
)
