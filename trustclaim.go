// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import "fmt"

// trustworthiness claim
type TrustClaim int8

type details struct {
	short, long string
}

type detailsMap map[TrustClaim]details

const (
	// See details definitions below for detailed claim value interpretations.

	// general
	VerifierMalfunctionClaim    = TrustClaim(-1)
	NoClaim                     = TrustClaim(0)
	UnexpectedEvidenceClaim     = TrustClaim(1)
	AffirmingClaim              = TrustClaim(2)
	CryptoValidationFailedClaim = TrustClaim(99)

	// instance identity
	TrustworthyInstanceClaim       = TrustClaim(2)
	InstanceIdentityAffirmingClaim = TrustClaim(2)
	UntrustworthyInstanceClaim     = TrustClaim(96)
	UnrecognizedInstanceClaim      = TrustClaim(97)

	// config
	ApprovedConfigClaim      = TrustClaim(2)
	NoConfigVulnsClaim       = TrustClaim(3)
	UnsafeConfigClaim        = TrustClaim(32)
	UnsupportableConfigClaim = TrustClaim(96)

	// exectuabes & runtime
	ApprovedRuntimeClaim     = TrustClaim(2)
	ApprovedBootClaim        = TrustClaim(3)
	UnsafeRuntime            = TrustClaim(32)
	UnrecognizedRuntimeClaim = TrustClaim(33)
	ContraindicatedRuntime   = TrustClaim(96)

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
	UntrustedSourcesClaim       = TrustClaim(3)
	ContraindicatedSourcesClaim = TrustClaim(96)
)

var (
	noneDetails = detailsMap{
		// Value -1: A verifier malfunction occurred during the Verifier's
		// appraisal processing.
		// NOTE: similar to HTTP 5xx (server error)
		VerifierMalfunctionClaim: {
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
			short: "no claim being made",
			long:  "The Evidence received is insufficient to make a conclusion.",
		},
		// Value 1: The Evidence received contains unexpected elements which the
		// Verifier is unable to parse. An example might be that the wrong type
		// of Evidence has been delivered.
		// NOTE: similar to HTTP 4xx (client error)
		UnexpectedEvidenceClaim: {
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
			short: "recognized and not compromised",
			long:  "The Attesting Environment is recognized, and the associated instance of the Attester is not known to be compromised.",
		},
		UntrustworthyInstanceClaim: {
			short: "recognized but not trustworthy",
			long:  "The Attesting Environment is recognized, but its unique private key indicates a device which is not trustworthy.",
		},
		UnrecognizedInstanceClaim: {
			short: "not recognized",
			long:  "The Attesting Environment is not recognized; however the Verifier believes it should be.",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised an Attester's configuration, and is able to make
	// conclusions regarding the exposure of known vulnerabilities.
	configurationDetails = detailsMap{
		ApprovedConfigClaim: {
			short: "all recognized and approved",
			long:  "The configuration is a known and approved config.",
		},
		NoConfigVulnsClaim: {
			short: "no known vulnerabilities",
			long:  "The configuration includes or exposes no known vulnerabilities",
		},
		UnsafeConfigClaim: {
			short: "known vulnerabilities",
			long:  "The configuration includes or exposes known vulnerabilities.",
		},
		UnsupportableConfigClaim: {
			short: "unacceptable security vulnerabilities",
			long:  "The configuration is unsupportable as it exposes unacceptable security vulnerabilities",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised and evaluated relevant runtime files, scripts,
	// and/or other objects which have been loaded into the Target environment's
	// memory.
	executablesDetails = detailsMap{
		ApprovedRuntimeClaim: {
			short: "recognized and approved boot- and run-time",
			long:  "Only a recognized genuine set of approved executables, scripts, files, and/or objects have been loaded during and after the boot process.",
		},
		ApprovedBootClaim: {
			short: "recognized and approved boot-time",
			long:  "Only a recognized genuine set of approved executables have been loaded during the boot process.",
		},
		UnsafeRuntime: {
			short: "recognized but known bugs or vulnerabilities",
			long:  "Only a recognized genuine set of executables, scripts, files, and/or objects have been loaded. However the Verifier cannot vouch for a subset of these due to known bugs or other known vulnerabilities.",
		},
		UnrecognizedRuntimeClaim: {
			short: "unrecognized run-time",
			long:  "Runtime memory includes executables, scripts, files, and/or objects which are not recognized.",
		},
		ContraindicatedRuntime: {
			short: "contraindicated run-time",
			long:  "Runtime memory includes executables, scripts, files, and/or object which are contraindicated.",
		},
		CryptoValidationFailedClaim: {
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
			short: "all recognized and approved",
			long:  "Only a recognized set of approved files are found.",
		},
		UnrecognizedFilesClaim: {
			short: "unrecognized item(s) found",
			long:  "The file system includes unrecognized executables, scripts, or files.",
		},
		ContraindicatedFilesClaim: {
			short: "contraindicated item(s) found",
			long:  "The file system includes contraindicated executables, scripts, or files.",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised any Attester hardware and firmware which are
	// able to expose fingerprints of their identity and running code.
	hardwareDetails = detailsMap{
		GenuineHardwareClaim: {
			short: "genuine",
			long:  "An Attester has passed its hardware and/or firmware verifications needed to demonstrate that these are genuine/supported.",
		},
		UnsafeHardwareClaim: {
			short: "genuine but known bugs or vulnerabilities",
			long:  "An Attester contains only genuine/supported hardware and/or firmware, but there are known security vulnerabilities.",
		},
		ContraindicatedHardwareClaim: {
			short: "genuine but contraindicated",
			long:  "Attester hardware and/or firmware is recognized, but its trustworthiness is contraindicated.",
		},
		UnrecognizedHardwareClaim: {
			short: "unrecognized",
			long:  "A Verifier does not recognize an Attester's hardware or firmware, but it should be recognized.",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised the visibility of Attester objects in memory
	// from perspectives outside the Attester.
	runtimeOpaqueDetails = detailsMap{
		EncryptedMemoryRuntimeClaim: {
			short: "memory encryption",
			long:  "the Attester's executing Target Environment and Attesting Environments are encrypted and within Trusted Execution Environment(s) opaque to the operating system, virtual machine manager, and peer applications.",
		},
		IsolatedMemoryRuntimeClaim: {
			// TODO(tho) not sure about the shorthand
			short: "memory isolation",
			long:  "the Attester's executing Target Environment and Attesting Environments are inaccessible from any other parallel application or Guest VM running on the Attester's physical device.",
		},
		VisibleMemoryRuntimeClaim: {
			short: "visible",
			long:  "The Verifier has concluded that in memory objects are unacceptably visible within the physical host that supports the Attester.",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised that an Attester is capable of encrypting
	// persistent storage.
	storageOpaqueDetails = detailsMap{
		HwKeysEncryptedSecretsClaim: {
			short: "encrypted secrets with HW-backed keys",
			long:  "the Attester encrypts all secrets in persistent storage via using keys which are never visible outside an HSM or the Trusted Execution Environment hardware.",
		},
		SwKeysEncryptedSecretsClaim: {
			short: "encrypted secrets with non HW-backed keys",
			long:  "the Attester encrypts all persistently stored secrets, but without using hardware backed keys.",
		},
		UnencryptedSecretsClaim: {
			short: "unencrypted secrets",
			long:  "There are persistent secrets which are stored unencrypted in an Attester.",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has evaluated the integrity of data objects from external
	// systems used by the Attester.
	sourcedDataDetails = detailsMap{
		TrustedSourcesClaim: {
			short: "from attesters in the affirming tier",
			long:  `All essential Attester source data objects have been provided by other Attester(s) whose most recent appraisal(s) had both no Trustworthiness Claims of "0" where the current Trustworthiness Claim is "Affirming", as well as no "Warning" or "Contraindicated" Trustworthiness Claims.`,
		},
		UntrustedSourcesClaim: {
			short: "from unattested sources or attesters in the warning tier",
			long:  `Attester source data objects come from unattested sources, or attested sources with "Warning" type Trustworthiness Claims`,
		},
		ContraindicatedSourcesClaim: {
			short: "from attesters in the contraindicated tier",
			long:  "Attester source data objects come from contraindicated sources.",
		},
		CryptoValidationFailedClaim: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
)

// TrustTier provides the trust tier bucket of the trustworthiness claim
func (o TrustClaim) TrustTier(color bool) string {
	const (
		rst    = `\033[0m`
		red    = `\033[41m`
		yellow = `\033[43m`
		green  = `\033[42m`
		white  = `\033[47m`
	)

	var s string

	switch {
	case o.IsNone():
		s = "none"
		if color {
			s = white + s + rst
		}
	case o.IsAffirming():
		s = "affirming"
		if color {
			s = green + s + rst
		}
	case o.IsWarning():
		s = "warning"
		if color {
			s = yellow + s + rst
		}
	case o.IsContraindicated():
		s = "contraindicated"
		if color {
			s = red + s + rst
		}
	default:
		panic("unreachable")
	}

	return s
}

func (o TrustClaim) trustTierTag(color bool) string {
	return "[" + o.TrustTier(color) + "]"
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
	return (o >= -128 && o <= -97) || (o >= 96 && o <= 127)
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
