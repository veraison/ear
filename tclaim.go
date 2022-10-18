// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import "fmt"

// trustworthiness claim
type TClaim int8

type details struct {
	short, long string
}

type detailsMap map[TClaim]details

var (
	noneDetails = detailsMap{
		// Value -1: A verifier malfunction occurred during the Verifier's
		// appraisal processing.
		// NOTE: similar to HTTP 5xx (server error)
		-1: {
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
		0: {
			short: "no claim being made",
			long:  "The Evidence received is insufficient to make a conclusion.",
		},
		// Value 1: The Evidence received contains unexpected elements which the
		// Verifier is unable to parse. An example might be that the wrong type
		// of Evidence has been delivered.
		// NOTE: similar to HTTP 4xx (client error)
		1: {
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
		2: {
			short: "recognized and not compromised",
			long:  "The Attesting Environment is recognized, and the associated instance of the Attester is not known to be compromised.",
		},
		96: {
			short: "recognized but not trustworthy",
			long:  "The Attesting Environment is recognized, but its unique private key indicates a device which is not trustworthy.",
		},
		97: {
			short: "not recognized",
			long:  "The Attesting Environment is not recognized; however the Verifier believes it should be.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised an Attester's configuration, and is able to make
	// conclusions regarding the exposure of known vulnerabilities.
	configurationDetails = detailsMap{
		2: {
			short: "all recognized and approved",
			long:  "The configuration is a known and approved config.",
		},
		3: {
			short: "no known vulnerabilities",
			long:  "The configuration includes or exposes no known vulnerabilities",
		},
		32: {
			short: "known vulnerabilities",
			long:  "The configuration includes or exposes known vulnerabilities.",
		},
		96: {
			short: "unacceptable security vulnerabilities",
			long:  "The configuration is unsupportable as it exposes unacceptable security vulnerabilities",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised and evaluated relevant runtime files, scripts,
	// and/or other objects which have been loaded into the Target environment's
	// memory.
	executablesDetails = detailsMap{
		2: {
			short: "recognized and approved boot- and run-time",
			long:  "Only a recognized genuine set of approved executables, scripts, files, and/or objects have been loaded during and after the boot process.",
		},
		3: {
			short: "recognized and approved boot-time",
			long:  "Only a recognized genuine set of approved executables have been loaded during the boot process.",
		},
		32: {
			short: "recognized but known bugs or vulnerabilities",
			long:  "Only a recognized genuine set of executables, scripts, files, and/or objects have been loaded. However the Verifier cannot vouch for a subset of these due to known bugs or other known vulnerabilities.",
		},
		33: {
			short: "unrecognized run-time",
			long:  "Runtime memory includes executables, scripts, files, and/or objects which are not recognized.",
		},
		96: {
			short: "contraindicated run-time",
			long:  "Runtime memory includes executables, scripts, files, and/or object which are contraindicated.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has evaluated a specific set of directories within the
	// Attester's file system. (Note: the Verifier may or may not indicate what
	// these directory and expected files are via an unspecified management
	// interface.)
	fileSystemDetails = detailsMap{
		2: {
			short: "all recognized and approved",
			long:  "Only a recognized set of approved files are found.",
		},
		32: {
			short: "unrecognized item(s) found",
			long:  "The file system includes unrecognized executables, scripts, or files.",
		},
		96: {
			short: "contraindicated item(s) found",
			long:  "The file system includes contraindicated executables, scripts, or files.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised any Attester hardware and firmware which are
	// able to expose fingerprints of their identity and running code.
	hardwareDetails = detailsMap{
		2: {
			short: "genuine",
			long:  "An Attester has passed its hardware and/or firmware verifications needed to demonstrate that these are genuine/supported.",
		},
		32: {
			short: "genuine but known bugs or vulnerabilities",
			long:  "An Attester contains only genuine/supported hardware and/or firmware, but there are known security vulnerabilities.",
		},
		96: {
			short: "genuine but contraindicated",
			long:  "Attester hardware and/or firmware is recognized, but its trustworthiness is contraindicated.",
		},
		97: {
			short: "unrecognized",
			long:  "A Verifier does not recognize an Attester's hardware or firmware, but it should be recognized.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised the visibility of Attester objects in memory
	// from perspectives outside the Attester.
	runtimeOpaqueDetails = detailsMap{
		2: {
			short: "memory encryption",
			long:  "the Attester's executing Target Environment and Attesting Environments are encrypted and within Trusted Execution Environment(s) opaque to the operating system, virtual machine manager, and peer applications.",
		},
		32: {
			// TODO(tho) not sure about the shorthand
			short: "memory isolation",
			long:  "the Attester's executing Target Environment and Attesting Environments are inaccessible from any other parallel application or Guest VM running on the Attester's physical device.",
		},
		96: {
			short: "visible",
			long:  "The Verifier has concluded that in memory objects are unacceptably visible within the physical host that supports the Attester.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has appraised that an Attester is capable of encrypting
	// persistent storage.
	storageOpaqueDetails = detailsMap{
		2: {
			short: "encrypted secrets with HW-backed keys",
			long:  "the Attester encrypts all secrets in persistent storage via using keys which are never visible outside an HSM or the Trusted Execution Environment hardware.",
		},
		32: {
			short: "encrypted secrets with non HW-backed keys",
			long:  "the Attester encrypts all persistently stored secrets, but without using hardware backed keys.",
		},
		96: {
			short: "unencrypted secrets",
			long:  "There are persistent secrets which are stored unencrypted in an Attester.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
	// A Verifier has evaluated the integrity of data objects from external
	// systems used by the Attester.
	sourcedDataDetails = detailsMap{
		2: {
			short: "from attesters in the affirming tier",
			long:  `All essential Attester source data objects have been provided by other Attester(s) whose most recent appraisal(s) had both no Trustworthiness Claims of "0" where the current Trustworthiness Claim is "Affirming", as well as no "Warning" or "Contraindicated" Trustworthiness Claims.`,
		},
		32: {
			short: "from unattested sources or attesters in the warning tier",
			long:  `Attester source data objects come from unattested sources, or attested sources with "Warning" type Trustworthiness Claims`,
		},
		96: {
			short: "from attesters in the contraindicated tier",
			long:  "Attester source data objects come from contraindicated sources.",
		},
		99: {
			short: "cryptographic validation failed",
			long:  "Cryptographic validation of the Evidence has failed.",
		},
	}
)

// TrustTier provides the trust tier bucket of the trustworthiness claim
func (o TClaim) TrustTier(color bool) string {
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

func (o TClaim) trustTierTag(color bool) string {
	return "[" + o.TrustTier(color) + "]"
}

func (o TClaim) IsNone() bool {
	// none = [-1, 1]
	return o >= -1 && o <= 1
}

func (o TClaim) IsAffirming() bool {
	// affirming = [-32, -2] U [2, 31]
	return (o >= -32 && o <= -2) || (o >= 2 && o <= 31)
}

func (o TClaim) IsWarning() bool {
	// warning = [-96, -33] U [32, 95]
	return (o >= -96 && o <= -33) || (o >= 32 && o <= 95)
}

func (o TClaim) IsContraindicated() bool {
	// contraindicated = [-128, -97] U [96, 127]
	return (o >= -128 && o <= -97) || (o >= 96 && o <= 127)
}

func (o TClaim) detailsPrinter(dm detailsMap, short bool, color bool) string {
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

func (o TClaim) asInstanceIdentityDetails(short, color bool) string {
	return o.detailsPrinter(instanceIdentityDetails, short, color)
}

func (o TClaim) asConfigurationDetails(short, color bool) string {
	return o.detailsPrinter(configurationDetails, short, color)
}

func (o TClaim) asExecutablesDetails(short, color bool) string {
	return o.detailsPrinter(executablesDetails, short, color)
}

func (o TClaim) asFileSystemDetails(short, color bool) string {
	return o.detailsPrinter(fileSystemDetails, short, color)
}

func (o TClaim) asHardwareDetails(short, color bool) string {
	return o.detailsPrinter(hardwareDetails, short, color)
}

func (o TClaim) asRuntimeOpaqueDetails(short, color bool) string {
	return o.detailsPrinter(runtimeOpaqueDetails, short, color)
}

func (o TClaim) asStorageOpaqueDetails(short, color bool) string {
	return o.detailsPrinter(storageOpaqueDetails, short, color)
}

func (o TClaim) asSourcedDataDetails(short, color bool) string {
	return o.detailsPrinter(sourcedDataDetails, short, color)
}

func noneToString(tc TClaim, short, color bool) string {
	s, ok := noneDetails[tc]
	if ok {
		if short {
			return s.short
		}
		return s.long
	}
	panic(`not a "none" code point`)
}
