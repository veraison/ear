// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package ear implements an EAT attestation result format based on the
information model defined in
https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/

# Construction

An AttestationResult object is constructed by populating the relevant fields.
The mandatory attributes are: status, issued_at, profile, submods, and verifier_id.
For example, a simple AttestationResult payload with only the bare minimum
claims could be created as follows:

    myStatus := TrustTierAffirming
    myTimestamp := time.Now().Unix()
    myPolicyID := `https://veraison.example/policy/1A4DF345-B512-4F3B-8461-967DE7F60ECA`
    myProfile := EatProfile

    ar := AttestationResult{
        Profile:  &myProfile,
        IssuedAt: &myTimestamp,
        Submods: map[string]*Appraisal{
            "submodName": {
                TrustVector: &TrustVector{},
                Status:      &myStatus,
            },
        },
        VerifierID: &VerifierIdentity{
            Build:     &verifierBuild,
            Developer: &verifierDeveloper,
        },
    }

A richer one would normally include the Trustworthiness Vector, which provides
details about the appraised attester components. In the example below, the
attester has been assessed as genuine, i.e., all claims are in the "affirming"
range. (See §2.3 of draft-ietf-rats-ar4si-03 for details about the allowed values
and their meaning.)

    tv := TrustVector{
        InstanceIdentity: 2,
        Configuration:    2,
        Executables:      2,
        Hardware:         2,
    }

    ar.Submods["submodName"].TrustVector = &tv

# Signing and Serializing

Once the AttestationResult is populated, it can be signed (i.e., wrapped in a
JWT) by invoking the Sign method:

    myECDSAPrivateKey := `{
        "kty": "EC",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
    }`

    sigK, _ := jwk.ParseKey([]byte(myECDSAPrivateKey))

    buf, _ := ar.Sign(jwa.ES256, sigK)

In this case, the returned buf contains a signed ES256 JWT with the JSON
serialization of the AttestationResult object as its payload. This is the usual
JWT format that can be used as-is for interchange with other applications.

# Parsing and Verifying

On the consumer end of the protocol, when the EAT containing the attestation
result is received from a veraison verifier, the relying party needs to first
parse it and verify the signature using the Verify method:

    myECDSAPublicKey := `{
        "kty": "EC",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
    }`

    vfyK, _ := jwk.ParseKey([]byte(myECDSAPublicKey))

    var ar AttestationResult

    err := ar.Verify(token, jwa.ES256, vfyK)
    if err != nil {
        // handle verification error
    }

If there are no errors, the relying party can trust the attestation result and
inspect the relevant fields to decide about the trustworthiness of the attested
entity.

    if *ar.Submods["submodName"].Status != TrustTierAffirming {
        // handle troubles with appraisal
    }

# Pretty printing

The package provides a Report method that allows pretty printing of the
Trustworthiness Vector. The caller can request a short summary or a detailed
printout, as well as using colors when displaying the claims' values.

    short, color := true, true

    fmt.Print(ar.Submods["submodName"].TrustVector.Report(short, color))
*/
package ear
