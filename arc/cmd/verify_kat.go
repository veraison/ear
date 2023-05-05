// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hf/nitrite"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	verifyKatInput        string
	verifyKatAttesterType string
	verifyKatRefValues    string
	verifyKatEndorsements string
	verifyKatClockSkew    time.Duration
)

var verifyKatCmd = NewVerifyKatCmd()

func NewVerifyKatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-kat [flags] <KAT file>",
		Short: "verify a key attestation of a EAR signing key",
		Long: `Verify a key attestation of a EAR signing key using optional
endorsements and reference values.

	The following example verifies the key (and platform) attestation of a
	Veraison deployment that runs in a AWS Nitro enclave.  This assumes the key
	attestation is verified offline at a later point in time.  Therefore, a
	clock skew of 10 hours is give to adjust the key attestation key validity.

	arc verify-kat \
		--attester aws-nitro \
		--refval data/nitro-ref-values.json \
		--clock-skew -10h \
		data/nitro-key-attestation.cbor

		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				katBytes []byte
				err      error
			)

			if err = checkVerifyKatArgs(args); err != nil {
				return fmt.Errorf("validating arguments: %w", err)
			}

			verifyKatInput = args[0]

			if katBytes, err = afero.ReadFile(fs, verifyKatInput); err != nil {
				return fmt.Errorf("loading key attestation from %q: %w", verifyKatInput, err)
			}

			// at this point the verifyKatAttesterType argument has already been
			// sanitized by checkVerifyKatArgs
			verify := attesterHandler[verifyKatAttesterType]

			return verify(katBytes, verifyKatRefValues, verifyKatClockSkew)
		},
	}

	cmd.Flags().StringVarP(
		&verifyKatAttesterType,
		"attester",
		"a",
		"",
		fmt.Sprintf("attester type, one of: %s", strings.Join(supportedAttesterTypes(), ",")),
	)
	_ = cmd.MarkFlagRequired("attester")

	cmd.Flags().StringVarP(
		&verifyKatRefValues,
		"refval",
		"r",
		"",
		"file containing reference values",
	)

	cmd.Flags().StringVarP(
		&verifyKatEndorsements,
		"endorsements",
		"e",
		"",
		"file containing endorsements",
	)

	cmd.Flags().DurationVarP(
		&verifyKatClockSkew,
		"clock-skew",
		"c",
		0,
		"clock skew expressed as time duration (e.g., 10h, -2h45m)",
	)

	return cmd
}

type AttesterHandler func(kat []byte, rv string, clockSkew time.Duration) error

type NitroRefValues struct {
	Measurements NitroMeasurements
}

type NitroMeasurements struct {
	HashAlgorithm string
	PCR0          HexString
	PCR1          HexString
	PCR2          HexString
	PCR3          HexString
	PCR4          HexString
	PCR8          HexString
}

type HexString []byte

func (o *HexString) UnmarshalJSON(b []byte) error {
	var (
		s   string
		err error
	)

	if err = json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("unmarshaling hex string: %w", err)
	}

	if *o, err = hex.DecodeString(s); err != nil {
		return fmt.Errorf("decoding hex string: %w", err)
	}

	return nil
}

func nitroLoadRefValues(rv string) (*NitroMeasurements, error) {
	var m NitroRefValues

	b, err := afero.ReadFile(fs, rv)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	if err = json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling JSON: %w", err)
	}

	return &m.Measurements, nil
}

func NitroHandler(kat []byte, rvFile string, clockSkew time.Duration) error {
	var (
		rvs *NitroMeasurements
		err error
	)

	if rvFile != "" {
		rvs, err = nitroLoadRefValues(rvFile)
		if err != nil {
			return fmt.Errorf("loading aws-nitro reference values from %q: %w", rvFile, err)
		}
	}

	t := time.Now().Add(clockSkew)
	opts := nitrite.VerifyOptions{CurrentTime: t}

	res, err := nitrite.Verify(kat, opts)
	if err != nil {
		return fmt.Errorf("verification of aws-nitro attestation document failed: %w", err)
	}

	if rvs != nil {
		var expected, actual []byte

		for _, i := range []uint{0, 1, 2, 3, 4, 8} {
			switch i {
			case 0:
				expected = rvs.PCR0
			case 1:
				expected = rvs.PCR1
			case 2:
				expected = rvs.PCR2
			case 3:
				expected = rvs.PCR3
			case 4:
				expected = rvs.PCR4
			case 8:
				expected = rvs.PCR8
			}

			if len(expected) == 0 {
				continue
			}

			actual = res.Document.PCRs[i]

			if bytes.Equal(expected, actual) {
				fmt.Printf("PCR[%d] ok\n", i)
			} else {
				return fmt.Errorf("PCR[%d] check failed: want %x, got %x", i, expected, actual)
			}
		}
	}

	fmt.Printf(">> Attested public key: %s\n\n", string(res.Document.PublicKey))

	return nil
}

var attesterHandler = map[string]AttesterHandler{
	"aws-nitro": NitroHandler,
}

func supportedAttesterTypes() []string {
	a := make([]string, 0, len(attesterHandler))

	for k := range attesterHandler {
		a = append(a, k)
	}

	return a
}

func checkVerifyKatArgs(args []string) error {
	if len(args) != 1 {
		return errors.New("no KAT file supplied")
	}

	_, ok := attesterHandler[verifyKatAttesterType]
	if !ok {
		return fmt.Errorf("unsupported attester type: %s", verifyKatAttesterType)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(verifyKatCmd)
}
