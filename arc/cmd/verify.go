// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/ear"
)

// The default value for pkey parameter
const defaultPKey = "pkey.json"

var (
	verifyInput   string
	verifyAlg     string
	verifyPKey    string
	verifyColor   bool
	verifyVerbose bool
)

var verifyCmd = NewVerifyCmd()

func NewVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [flags] <jwt-file>",
		Short: "Read a signed EAR from jwt-file, verify it and pretty-print its content",
		Long: `Read a signed EAR from jwt-file, verify it and pretty-print its content

Verify the signed EAR in "my-ear.jwt" using the public key from a key file.
If the default key file name "pkey.json" is used and file is missing then
use the public key from JWT header.
If cryptographic verification is successful, print the
embedded EAR claims-set and present a report of the trustworthiness vector.

	arc verify my-ear.jwt
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				claimsSet, arBytes []byte
				vfyK               jwk.Key
				vfyAlg             jwa.KeyAlgorithm
				ar                 ear.AttestationResult
				err                error
				ok                 bool
			)

			if err = checkVerifyArgs(args); err != nil {
				return fmt.Errorf("validating arguments: %w", err)
			}

			verifyInput = args[0]

			if arBytes, err = afero.ReadFile(fs, verifyInput); err != nil {
				return fmt.Errorf("loading signed EAR from %q: %w", verifyInput, err)
			}

			// read the verification key from verifyPKey
			if pKey, err := afero.ReadFile(fs, verifyPKey); err != nil {
				if verifyPKey != defaultPKey {
					return fmt.Errorf("loading verification key from %q: %w", verifyPKey, err)
				}
				fmt.Println("Using JWK key from JWT header")
				msg, err := jws.Parse(arBytes)
				if err != nil {
					return fmt.Errorf("failed to parse serialized JWT: %s", err)
				}
				// While JWT enveloped with JWS in compact format only has 1 signature,
				// a generic JWS message may have multiple signatures. Therefore, we
				// need to access the first element
				if vfyK, ok = msg.Signatures()[0].ProtectedHeaders().JWK(); !ok || vfyK == nil {
					return fmt.Errorf("failed to get JWK key from JWT header")
				}
				if vfyAlg, ok = msg.Signatures()[0].ProtectedHeaders().Algorithm(); !ok {
					return fmt.Errorf("failed to get key algorithm from JWT header")
				}
				verifyPKey = "JWK header"
			} else {
				if vfyK, err = jwk.ParseKey(pKey); err != nil {
					return fmt.Errorf("parsing verification key from %q: %w", verifyPKey, err)
				}
				if vfyAlg, err = jwa.KeyAlgorithmFrom(verifyAlg); err != nil {
					return fmt.Errorf("parsing algorithm from %q: %w", verifyAlg, err)
				}
			}

			if err = ar.Verify(arBytes, vfyAlg, vfyK); err != nil {
				return fmt.Errorf("verifying signed EAR from %q using %q key: %w", verifyInput, verifyPKey, err)
			}

			fmt.Printf(">> %q signature successfully verified using %q key\n", verifyInput, verifyPKey)

			fmt.Println("[claims-set]")
			if claimsSet, err = ar.MarshalJSONIndent("", "    "); err != nil {
				return fmt.Errorf("unable to re-serialize the EAR claims-set: %w", err)
			}
			fmt.Println(string(claimsSet))

			fmt.Println("[trustworthiness vectors]")
			for submodName, appraisal := range ar.Submods {
				fmt.Printf("submod(%s):\n", submodName)
				if appraisal.TrustVector != nil {
					fmt.Println(appraisal.TrustVector.Report(!verifyVerbose, verifyColor))
				} else {
					fmt.Println("not present")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(
		&verifyPKey, "pkey", "p", defaultPKey, "verification key in JWK format",
	)

	cmd.Flags().StringVarP(
		&verifyAlg, "alg", "a", "ES256", "verification algorithm ("+algList()+")",
	)

	cmd.Flags().BoolVarP(
		&verifyVerbose, "verbose", "v", false, "verbose trustworthiness vector report (default is brief)",
	)

	cmd.Flags().BoolVarP(
		&verifyColor, "color", "c", false, "render trustworthiness vector tiers with colors (default is b&w)",
	)

	return cmd
}

func checkVerifyArgs(args []string) error {
	if len(args) != 1 {
		return errors.New("no input file supplied")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
