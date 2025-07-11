// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	printInput string
)

var printCmd = NewPrintCmd()

func NewPrintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "print [flags] <jwt-file>",
		Short: "Read an EAR from a file and print its header and payload",
		Long: `Read an EAR from a file and print its header and payload

Neither EAR validation nor verification is executed.

	arc print my-ear.jwt
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				data, arBytes []byte
				err           error
				token         jwt.Token
			)

			if err = checkPrintArgs(args); err != nil {
				return fmt.Errorf("validating arguments: %w", err)
			}

			printInput = args[0]

			if arBytes, err = afero.ReadFile(fs, printInput); err != nil {
				return fmt.Errorf("reading JWT from %q: %w", printInput, err)
			}

			msg, err := jws.Parse(arBytes)
			if err != nil {
				return fmt.Errorf("failed to parse serialized JWT: %s", err)
			}
			// While JWT enveloped with JWS in compact format only has 1 signature,
			// a generic JWS message may have multiple signatures. Therefore, we
			// need to access the first element
			if data, err = json.MarshalIndent(msg.Signatures()[0].ProtectedHeaders(), "", "    "); err != nil {
				return fmt.Errorf("unable to re-serialize the EAR claims-set: %w", err)
			}
			fmt.Println("[header]")
			fmt.Println(string(data))

			if token, err = jwt.ParseInsecure(arBytes); err != nil {
				return fmt.Errorf("failed to parse JWT message: %w", err)
			}

			claims := make(map[string]any)
			for _, k := range token.Keys() {
				var v any
				if err = token.Get(k, &v); err != nil {
					return fmt.Errorf(`failed to get claim %s: %w`, k, err)
				}
				claims[k] = v
			}
			if data, err = json.MarshalIndent(claims, "", "    "); err != nil {
				return fmt.Errorf("unable to re-serialize the EAR claims-set: %w", err)
			}
			fmt.Println("[payload]")
			fmt.Println(string(data))

			return nil
		},
	}

	return cmd
}

func checkPrintArgs(args []string) error {
	if len(args) != 1 {
		return errors.New("no input file supplied")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(printCmd)
}
