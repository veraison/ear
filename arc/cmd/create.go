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
	createClaims string
	createSKey   string
	createAlg    string
	createOutput string
)

var createCmd = NewCreateCmd()

func NewCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [flags] <jwt-file>",
		Short: "Read the EAR claims-set from a JSON file, sign it and save the resulting JWT to jwt-file",
		Long: `Read the EAR claims-set from a JSON file, sign it and save the resulting JWT to jwt-file

Create an EAR from the default claims-set file "ear-claims.json".  Sign it with
the key in the default key file "skey.json", and save the result to "my-ear.jwt".

	arc create my-ear.jwt
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				claimsSet, sKey, ear []byte
				sigK                 jwk.Key
				ar                   ar4si.AttestationResult
				err                  error
			)

			if err = checkCreateArgs(args); err != nil {
				return fmt.Errorf("validating arguments: %w", err)
			}

			createOutput = args[0]

			if claimsSet, err = afero.ReadFile(fs, createClaims); err != nil {
				return fmt.Errorf("loading EAR claims-set from %q: %w", createClaims, err)
			}

			if err = ar.FromJSON(claimsSet); err != nil {
				return fmt.Errorf("decoding EAR claims-set from %q: %w", createClaims, err)
			}

			// read the signing key from createSKey
			if sKey, err = afero.ReadFile(fs, createSKey); err != nil {
				return fmt.Errorf("loading signing key from %q: %w", createSKey, err)
			}

			if sigK, err = jwk.ParseKey(sKey); err != nil {
				return fmt.Errorf("parsing signing key from %q: %w", createSKey, err)
			}

			if ear, err = ar.Sign(jwa.KeyAlgorithmFrom(createAlg), sigK); err != nil {
				return fmt.Errorf("signing EAR: %w", err)
			}

			// save to createOutput
			if err = afero.WriteFile(fs, createOutput, ear, 0644); err != nil {
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
		&createAlg, "alg", "a", "ES256", "signing algorithm ("+algList()+")",
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
