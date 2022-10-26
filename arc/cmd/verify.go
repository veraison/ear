// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/ar4si"
)

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

Verify the signed EAR in "my-ear.jwt" using the public key in the default key
file "pkey.json".  If cryptographic verification is successful, print the
embedded EAR claims-set and present a report of the trustworthiness vector.

	arc verify my-ear.jwt
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				claimsSet, pKey, ear []byte
				vfyK                 jwk.Key
				ar                   ar4si.AttestationResult
				err                  error
			)

			if err = checkVerifyArgs(args); err != nil {
				return fmt.Errorf("validating arguments: %w", err)
			}

			verifyInput = args[0]

			if ear, err = afero.ReadFile(fs, verifyInput); err != nil {
				return fmt.Errorf("loading signed EAR from %q: %w", verifyInput, err)
			}

			// read the verification key from verifyPKey
			if pKey, err = afero.ReadFile(fs, verifyPKey); err != nil {
				return fmt.Errorf("loading verification key from %q: %w", verifyPKey, err)
			}

			if vfyK, err = jwk.ParseKey(pKey); err != nil {
				return fmt.Errorf("parsing verification key from %q: %w", verifyPKey, err)
			}

			if err = ar.Verify(ear, jwa.KeyAlgorithmFrom(verifyAlg), vfyK); err != nil {
				return fmt.Errorf("verifying signed EAR from %s: %w", verifyInput, err)
			}

			fmt.Printf(">> %q signature successfully verified using %q\n", verifyInput, verifyPKey)

			fmt.Println("[claims-set]")
			if claimsSet, err = ar.ToJSONPretty(); err != nil {
				return fmt.Errorf("unable to re-serialize the EAR claims-set: %w", err)
			}
			fmt.Println(string(claimsSet))

			fmt.Println("[trustworthiness vector]")
			if ar.TrustVector != nil {
				fmt.Println(ar.TrustVector.Report(!verifyVerbose, verifyColor))
			} else {
				fmt.Println("not present")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(
		&verifyPKey, "pkey", "p", "pkey.json", "verification key in JWK format",
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
