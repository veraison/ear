// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/ear"
)

var (
	createClaims string
	createSKey   string
	createAlg    string
	createOutput string
	createCWT    bool
)

var createCmd = NewCreateCmd()

func NewCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [flags] <outfile>",
		Short: "Read the EAR claims-set from a JSON file, sign it and save the resulting JWT (or CWT) to outfile",
		Long: `Read the EAR claims-set from a JSON file, sign it and save the resulting JWT (or CWT) to outfile
Create an EAR from the default claims-set file "ear-claims.json".  Sign it with
the key in the default key file "skey.json", and save the result to "my-ear.jwt".

Note: for CWT, only ES256, ES384, and ES512 signature algorithms are supported.

	arc create my-ear.jwt
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				claimsSet, sKey, arBytes []byte
				sigK                     jwk.Key
				ar                       ear.AttestationResult
				alg                      jwa.KeyAlgorithm
				err                      error
			)

			if err = checkCreateArgs(args); err != nil {
				return fmt.Errorf("validating arguments: %w", err)
			}

			createOutput = args[0]

			if claimsSet, err = afero.ReadFile(fs, createClaims); err != nil {
				return fmt.Errorf("loading EAR claims-set from %q: %w", createClaims, err)
			}

			if err = ar.UnmarshalJSON(claimsSet); err != nil {
				return fmt.Errorf("decoding EAR claims-set from %q: %w", createClaims, err)
			}

			// read the signing key from createSKey
			if sKey, err = afero.ReadFile(fs, createSKey); err != nil {
				return fmt.Errorf("loading signing key from %q: %w", createSKey, err)
			}

			if sigK, err = jwk.ParseKey(sKey); err != nil {
				return fmt.Errorf("parsing signing key from %q: %w", createSKey, err)
			}

			if createCWT {
				signerAlg, signer, err := ear.SignerFromJWK(sigK)
				if err != nil {
					return fmt.Errorf("obtaining signer from key: %w", err)
				}

				if arBytes, err = ar.SignCWT(signerAlg, signer, nil); err != nil {
					return fmt.Errorf("signing EAR: %w", err)
				}
			} else {
				if alg, err = jwa.KeyAlgorithmFrom(createAlg); err != nil {
					return fmt.Errorf("parsing algorithm from %q: %w", createAlg, err)
				}

				if arBytes, err = ar.SignJWT(alg, sigK); err != nil {
					return fmt.Errorf("signing EAR: %w", err)
				}
			}

			// save to createOutput
			if err = afero.WriteFile(fs, createOutput, arBytes, 0644); err != nil {
				return fmt.Errorf("saving signer EAR to file %q: %w", createOutput, err)
			}

			fmt.Printf(">> created %q from %q using %q as signing key\n", createOutput, createClaims, createSKey)

			return nil
		},
	}

	cmd.Flags().StringVarP(
		&createSKey, "skey", "s", "skey.json", "signing key in JWK format",
	)

	cmd.Flags().StringVarP(
		&createClaims, "claims", "c", "ear-claims.json", "EAR claims-set in JSON",
	)

	cmd.Flags().StringVarP(
		&createAlg, "alg", "a", "ES256", "JWT signing algorithm ("+algList()+"); (this is not used for CWT)",
	)

	cmd.Flags().BoolVarP(
		&createCWT, "cwt", "C", false, "Create a CWT (JWT is created by default)",
	)

	return cmd
}

func checkCreateArgs(args []string) error {
	if len(args) != 1 {
		return errors.New("no output file supplied")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(createCmd)
}
