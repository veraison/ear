// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/huandu/xstrings"
)

// trustworthiness claim
type TrustClaim int8

// Description of a particular claim
// tag: an itentifier-compantible label to be used in serialized values as an
//
//	alternative to integers.
//
// short: a short description for embedding in error messages, etc
// long: a longer, more descriptive explanation of the claim.
type details struct {
	tag, short, long string
}

type detailsMap map[TrustClaim]details

const (
	// See details definitions below for detailed claim value interpretations.

	// general
	VerifierMalfunctionClaim    = TrustClaim(-1)
	NoClaim                     = TrustClaim(0)
	UnexpectedEvidenceClaim     = TrustClaim(1)
	CryptoValidationFailedClaim = TrustClaim(99)

	// instance identity
	TrustworthyInstanceClaim   = TrustClaim(2)
	UntrustworthyInstanceClaim = TrustClaim(96)
	UnrecognizedInstanceClaim  = TrustClaim(97)

	// config
	ApprovedConfigClaim      = TrustClaim(2)
	NoConfigVulnsClaim       = TrustClaim(3)
	UnsafeConfigClaim        = TrustClaim(32)
	UnsupportableConfigClaim = TrustClaim(96)

	// executables & runtime
	ApprovedRuntimeClaim        = TrustClaim(2)
	ApprovedBootClaim           = TrustClaim(3)
	UnsafeRuntimeClaim          = TrustClaim(32)
	UnrecognizedRuntimeClaim    = TrustClaim(33)
	ContraindicatedRuntimeClaim = TrustClaim(96)

	// file system
	ApprovedFilesClaim        = TrustClaim(2)
	UnrecognizedFilesClaim    = TrustClaim(32)
	ContraindicatedFilesClaim = TrustClaim(96)

	// hardware
	GenuineHardwareClaim         = TrustClaim(2)
	UnsafeHardwareClaim          = TrustClaim(32)
	ContraindicatedHardwareClaim = TrustClaim(96)
	UnrecognizedHardwareClaim    = TrustClaim(97)

	// opaque runtime
	EncryptedMemoryRuntimeClaim = TrustClaim(2)
	IsolatedMemoryRuntimeClaim  = TrustClaim(32)
	VisibleMemoryRuntimeClaim   = TrustClaim(96)

	// opaque storage
	HwKeysEncryptedSecretsClaim = TrustClaim(2)
	SwKeysEncryptedSecretsClaim = TrustClaim(32)
	UnencryptedSecretsClaim     = TrustClaim(96)

	// sourced data
	TrustedSourcesClaim         = TrustClaim(2)
	UntrustedSourcesClaim       = TrustClaim(32)
	ContraindicatedSourcesClaim = TrustClaim(96)
)

var (
	// NOTE: tags are used when converting strings to claims. In order for
	// this work, there must be an unabigous mapping between them and
	// claims' integer values. It is OK of mulple claims to have the same
	// tag, as long as their integer values are also the same.
	noneDetails = detailsMap{
		// Value -1: A verifier malfunction occurred during the Verifier's
		// appraisal processing.
		// NOTE: similar to HTTP 5xx (server error)
		VerifierMalfunctionClaim: {
			tag:   "verifier_malfunction",
			short: "verifier malfunction",
			long:  "A verifier malfunction occurred during the Verifier's appraisal processing.",
		},
		// Value 0: The Evidence received is insufficient to make a conclusion.
		// Note: this should always be always treated equivalently by the
		// Relying Party as no claim being made. I.e., the RP's Appraisal Policy
		// for Attestation Results SHOULD NOT make any distinction between a
		// Trustworthiness Claim with enumeration '0', and no Trustworthiness
		// Claim being provided.
		// NOTE: not sure why this is grouped with -1 and 1.
		NoClaim: {
			tag:   "no_claim",
			short: "no claim being made",
			long:  "The Evidence received is insufficient to make a conclusion.",
		},
		// Value 1: The Evidence received contains unexpected elements which the
		// Verifier is unable to parse. An example might be that the wrong type
		// of Evidence has been delivered.
		// NOTE: similar to HTTP 4xx (client error)
		UnexpectedEvidenceClaim: {
			tag:   "unexected_evidence",
			short: "unexpected evidence",
			long:  "The Evidence received contains unexpected elements which the Verifier is unable to parse.",
		},
	}
	// A Verifier has appraised an Attesting Environment's unique identity based
	// upon private key signed Evidence which can be correlated to a unique
	// instantiated instance of the Attester. (Note: this Trustworthiness Claim
	// should only be generated if the Verifier actually expects to recognize
	// the unique identity of the Attester.)
	instanceIdentityDetails = detailsMap{
		TrustworthyInstanceClaim: {
			tag:   "recognized_instance",
			short: "recognized and not compromised",
			long:  "The Attesting Environment is recognized, and the associated instance of the Attester is not known to be compromised.",
		},
		UntrustworthyInstanceClaim: {
			tag:   "untrustworthy_instance",
			short: "recognized but not trustworthy",
			long:  "The Attesting Environment is recognized, but its unique private key indicates a device which is not trustworthy.",
		},
		UnrecognizedInstanceClaim: {
			tag:   "unrecognized_instance",
			short: "not recognized",
			long:  "The Attesting Environment is not recognized; however the Verifier believes it should be.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised an Attester's configuration, and is able to make
	// conclusions regarding the exposure of known vulnerabilities.
	configurationDetails = detailsMap{
		ApprovedConfigClaim: {
			tag:   "approved_config",
			short: "all recognized and approved",
			long:  "The configuration is a known and approved config.",
		},
		NoConfigVulnsClaim: {
			tag:   "safe_config",
			short: "no known vulnerabilities",
			long:  "The configuration includes or exposes no known vulnerabilities",
		},
		UnsafeConfigClaim: {
			tag:   "unsafe_config",
			short: "known vulnerabilities",
			long:  "The configuration includes or exposes known vulnerabilities.",
		},
		UnsupportableConfigClaim: {
			tag:   "unsupportable_config",
			short: "unacceptable security vulnerabilities",
			long:  "The configuration is unsupportable as it exposes unacceptable security vulnerabilities",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised and evaluated relevant runtime files, scripts,
	// and/or other objects which have been loaded into the Target environment's
	// memory.
	executablesDetails = detailsMap{
		ApprovedRuntimeClaim: {
			tag:   "approved_rt",
			short: "recognized and approved boot- and run-time",
			long:  "Only a recognized genuine set of approved executables, scripts, files, and/or objects have been loaded during and after the boot process.", // nolint: lll
		},
		ApprovedBootClaim: {
			tag:   "approved_boot",
			short: "recognized and approved boot-time",
			long:  "Only a recognized genuine set of approved executables have been loaded during the boot process.",
		},
		UnsafeRuntimeClaim: {
			tag:   "unsafe_rt",
			short: "recognized but known bugs or vulnerabilities",
			long:  "Only a recognized genuine set of executables, scripts, files, and/or objects have been loaded. However the Verifier cannot vouch for a subset of these due to known bugs or other known vulnerabilities.", // nolint: lll
		},
		UnrecognizedRuntimeClaim: {
			tag:   "unrecognized_rt",
			short: "unrecognized run-time",
			long:  "Runtime memory includes executables, scripts, files, and/or objects which are not recognized.",
		},
		ContraindicatedRuntimeClaim: {
			tag:   "contraindicated_rt",
			short: "contraindicated run-time",
			long:  "Runtime memory includes executables, scripts, files, and/or object which are contraindicated.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has evaluated a specific set of directories within the
	// Attester's file system. (Note: the Verifier may or may not indicate what
	// these directory and expected files are via an unspecified management
	// interface.)
	fileSystemDetails = detailsMap{
		ApprovedFilesClaim: {
			tag:   "approved_fs",
			short: "all recognized and approved",
			long:  "Only a recognized set of approved files are found.",
		},
		UnrecognizedFilesClaim: {
			tag:   "unrecognized_fs",
			short: "unrecognized item(s) found",
			long:  "The file system includes unrecognized executables, scripts, or files.",
		},
		ContraindicatedFilesClaim: {
			tag:   "contraindicated_fs",
			short: "contraindicated item(s) found",
			long:  "The file system includes contraindicated executables, scripts, or files.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised any Attester hardware and firmware which are
	// able to expose fingerprints of their identity and running code.
	hardwareDetails = detailsMap{
		GenuineHardwareClaim: {
			tag:   "genuine_hw",
			short: "genuine",
			long:  "An Attester has passed its hardware and/or firmware verifications needed to demonstrate that these are genuine/supported.",
		},
		UnsafeHardwareClaim: {
			tag:   "unsafe_hw",
			short: "genuine but known bugs or vulnerabilities",
			long:  "An Attester contains only genuine/supported hardware and/or firmware, but there are known security vulnerabilities.",
		},
		ContraindicatedHardwareClaim: {
			tag:   "contraindicated_hw",
			short: "genuine but contraindicated",
			long:  "Attester hardware and/or firmware is recognized, but its trustworthiness is contraindicated.",
		},
		UnrecognizedHardwareClaim: {
			tag:   "unrecognized_hw",
			short: "unrecognized",
			long:  "A Verifier does not recognize an Attester's hardware or firmware, but it should be recognized.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised the visibility of Attester objects in memory
	// from perspectives outside the Attester.
	runtimeOpaqueDetails = detailsMap{
		EncryptedMemoryRuntimeClaim: {
			tag:   "encrypted_rt",
			short: "memory encryption",
			long:  "the Attester's executing Target Environment and Attesting Environments are encrypted and within Trusted Execution Environment(s) opaque to the operating system, virtual machine manager, and peer applications.", // nolint: lll
		},
		IsolatedMemoryRuntimeClaim: {
			// TODO(tho) not sure about the shorthand
			tag:   "isolated_rt",
			short: "memory isolation",
			long:  "the Attester's executing Target Environment and Attesting Environments are inaccessible from any other parallel application or Guest VM running on the Attester's physical device.", // nolint: lll
		},
		VisibleMemoryRuntimeClaim: {
			tag:   "visible_rt",
			short: "visible",
			long:  "The Verifier has concluded that in memory objects are unacceptably visible within the physical host that supports the Attester.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised that an Attester is capable of encrypting
	// persistent storage.
	storageOpaqueDetails = detailsMap{
		HwKeysEncryptedSecretsClaim: {
			tag:   "hw_encrypted_secrets",
			short: "encrypted secrets with HW-backed keys",
			long:  "the Attester encrypts all secrets in persistent storage via using keys which are never visible outside an HSM or the Trusted Execution Environment hardware.", // nolint: lll
		},
		SwKeysEncryptedSecretsClaim: {
			tag:   "sw_encrypted_secrets",
			short: "encrypted secrets with non HW-backed keys",
			long:  "the Attester encrypts all persistently stored secrets, but without using hardware backed keys.",
		},
		UnencryptedSecretsClaim: {
			tag:   "unencrypted_secrets",
			short: "unencrypted secrets",
			long:  "There are persistent secrets which are stored unencrypted in an Attester.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has evaluated the integrity of data objects from external
	// systems used by the Attester.
	sourcedDataDetails = detailsMap{
		TrustedSourcesClaim: {
			tag:   "trusted_sources",
			short: "from attesters in the affirming tier",
			long:  `All essential Attester source data objects have been provided by other Attester(s) whose most recent appraisal(s) had both no Trustworthiness Claims of "0" where the current Trustworthiness Claim is "Affirming", as well as no "Warning" or "Contraindicated" Trustworthiness Claims.`, // nolint: lll
		},
		UntrustedSourcesClaim: {
			tag:   "untrusted_sources",
			short: "from unattested sources or attesters in the warning tier",
			long:  `Attester source data objects come from unattested sources, or attested sources with "Warning" type Trustworthiness Claims`,
		},
		ContraindicatedSourcesClaim: {
			tag:   "contraindicated_sources",
			short: "from attesters in the contraindicated tier",
			long:  "Attester source data objects come from contraindicated sources.",
		},
		CryptoValidationFailedClaim: {
			tag:   "crypto_failed",
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
)

func getTrustClaimFromInt(i int) (TrustClaim, error) {
	if i > 127 || i < -128 {
		return NoClaim, fmt.Errorf("out of range for TrustClaim: %d", i)
	}
	return TrustClaim(i), nil
}

func getTrustClaimFromString(s string) (TrustClaim, error) {
	i, err := strconv.Atoi(s)
	if err == nil {
		return getTrustClaimFromInt(i)
	}

	detailsMaps := []detailsMap{
		configurationDetails,
		executablesDetails,
		fileSystemDetails,
		hardwareDetails,
		instanceIdentityDetails,
		noneDetails,
		runtimeOpaqueDetails,
		sourcedDataDetails,
		storageOpaqueDetails,
	}

	canon := strings.Trim(xstrings.Translate(xstrings.ToSnakeCase(s), ".- ", "_"), " \t")

	for _, dm := range detailsMaps {
		for claim, deets := range dm {
			if deets.tag == canon {
				return claim, nil
			}
		}
	}

	return NoClaim, fmt.Errorf("not a valid TrustClaim value: %q", s)
}

func ToTrustClaim(v interface{}) (*TrustClaim, error) {
	var (
		claim TrustClaim
		err   error
	)

	switch t := v.(type) {
	case TrustClaim:
		claim = t
	case *TrustClaim:
		claim = *t
	case json.Number:
		i, e := t.Int64()
		if e != nil {
			err = fmt.Errorf("not a valid TrustClaim value: %v: %w", t, err)
		} else {
			claim, err = getTrustClaimFromInt(int(i))
		}
	case string:
		claim, err = getTrustClaimFromString(t)
	case []byte:
		claim, err = getTrustClaimFromString(string(t))
	case int:
		claim, err = getTrustClaimFromInt(t)
	case int8:
		claim, err = getTrustClaimFromInt(int(t))
	case int16:
		claim, err = getTrustClaimFromInt(int(t))
	case int32:
		claim, err = getTrustClaimFromInt(int(t))
	case int64:
		claim, err = getTrustClaimFromInt(int(t))
	case uint8:
		claim, err = getTrustClaimFromInt(int(t))
	case uint16:
		claim, err = getTrustClaimFromInt(int(t))
	case uint32:
		claim, err = getTrustClaimFromInt(int(t))
	case uint:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustClaim value: %d", t)

		} else {
			claim, err = getTrustClaimFromInt(int(t))
		}
	case uint64:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustClaim value: %d", t)

		} else {
			claim, err = getTrustClaimFromInt(int(t))
		}
	case float64:
		claim, err = getTrustClaimFromInt(int(t))
	}

	return &claim, err
}

// TrustTier provides the trust tier bucket of the trustworthiness claim
func (o TrustClaim) GetTier() TrustTier {
	if o.IsNone() {
		return TrustTierNone
	} else if o.IsAffirming() {
		return TrustTierAffirming
	} else if o.IsWarning() {
		return TrustTierWarning
	} else if o.IsContraindicated() {
		return TrustTierContraindicated
	} else {
		panic(o) // should never get here -- above conditions exhaust int8 range
	}
}

func (o TrustClaim) trustTierTag(color bool) string {
	return "[" + o.GetTier().Format(color) + "]"
}

func (o TrustClaim) IsNone() bool {
	// none = [-1, 1]
	return o >= -1 && o <= 1
}

func (o TrustClaim) IsAffirming() bool {
	// affirming = [-32, -2] U [2, 31]
	return (o >= -32 && o <= -2) || (o >= 2 && o <= 31)
}

func (o TrustClaim) IsWarning() bool {
	// warning = [-96, -33] U [32, 95]
	return (o >= -96 && o <= -33) || (o >= 32 && o <= 95)
}

func (o TrustClaim) IsContraindicated() bool {
	// contraindicated = [-128, -97] U [96, 127]
	// o is int8. i.e. math.MinInt8 < o < math.MaxInt8
	return (o <= -97) || (o >= 96)
}

func (o TrustClaim) detailsPrinter(dm detailsMap, short bool, color bool) string {
	// "none" statuses have shared semantics
	if o.IsNone() {
		return noneToString(o, short, color)
	}

	// other statuses are per-category therefore they are dispatched to the
	// associated detailsMap
	s, ok := dm[o]
	if !ok {
		return fmt.Sprintf("unknown code-point %d", o)
	}

	if short {
		return s.short
	}

	return s.long
}

func (o TrustClaim) asInstanceIdentityDetails(short, color bool) string {
	return o.detailsPrinter(instanceIdentityDetails, short, color)
}

func (o TrustClaim) asConfigurationDetails(short, color bool) string {
	return o.detailsPrinter(configurationDetails, short, color)
}

func (o TrustClaim) asExecutablesDetails(short, color bool) string {
	return o.detailsPrinter(executablesDetails, short, color)
}

func (o TrustClaim) asFileSystemDetails(short, color bool) string {
	return o.detailsPrinter(fileSystemDetails, short, color)
}

func (o TrustClaim) asHardwareDetails(short, color bool) string {
	return o.detailsPrinter(hardwareDetails, short, color)
}

func (o TrustClaim) asRuntimeOpaqueDetails(short, color bool) string {
	return o.detailsPrinter(runtimeOpaqueDetails, short, color)
}

func (o TrustClaim) asStorageOpaqueDetails(short, color bool) string {
	return o.detailsPrinter(storageOpaqueDetails, short, color)
}

func (o TrustClaim) asSourcedDataDetails(short, color bool) string {
	return o.detailsPrinter(sourcedDataDetails, short, color)
}

func noneToString(tc TrustClaim, short, color bool) string {
	s, ok := noneDetails[tc]
	if ok {
		if short {
			return s.short
		}
		return s.long
	}
	panic(`not a "none" code point`)
}
