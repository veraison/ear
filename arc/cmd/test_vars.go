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
    "ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d",
    "ear.verifier-id": {
	    "build": "rrtrap-v1.0.0",
	    "developer": "Acme Inc."
    }
}`)
	testJWT = []byte(`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIyOnZlcmFpc29uL2VhciIsImVhci50cnVzdHdvcnRoaW5lc3MtdmVjdG9yIjp7Imluc3RhbmNlLWlkZW50aXR5IjoyLCJjb25maWd1cmF0aW9uIjoyLCJleGVjdXRhYmxlcyI6MywiZmlsZS1zeXN0ZW0iOjIsImhhcmR3YXJlIjoyLCJydW50aW1lLW9wYXF1ZSI6Miwic3RvcmFnZS1vcGFxdWUiOjIsInNvdXJjZWQtZGF0YSI6Mn0sImVhci5yYXctZXZpZGVuY2UiOiIzcTItN3ciLCJpYXQiOjE2NjYwOTEzNzMsImVhci52ZXJpZmllci1pZCI6eyJidWlsZCI6InJydHJhcC12MS4wLjAiLCJkZXZlbG9wZXIiOiJBY21lIEluYy4ifSwiZWFyLmFwcHJhaXNhbC1wb2xpY3ktaWQiOiJodHRwczovL3ZlcmFpc29uLmV4YW1wbGUvcG9saWN5LzEvNjBhMDA2OGQifQ.76tnHC95AeP3iQWXqcb4yI5BUeQ17UiOhyKKn3Xvv4F32ZByY3nCFvXv8nyP_6J2twf1ul4BRWNSmTnd3wnrEQ`)
)
