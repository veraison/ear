// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
	"fmt"
	"iter"
	"maps"
	"reflect"

	"github.com/veraison/eat"
)

// TrustVector is an implementation of the Trustworthiness Vector (and Claims)
// described in §2.3 of draft-ietf-rats-ar4si-03.
type TrustVector struct {
	InstanceIdentity TrustClaim `cbor:"0,keyasint,omitzero" json:"instance-identity,omitzero"`
	Configuration    TrustClaim `cbor:"1,keyasint,omitzero" json:"configuration,omitzero"`
	Executables      TrustClaim `cbor:"2,keyasint,omitzero" json:"executables,omitzero"`
	FileSystem       TrustClaim `cbor:"3,keyasint,omitzero" json:"file-system,omitzero"`
	Hardware         TrustClaim `cbor:"4,keyasint,omitzero" json:"hardware,omitzero"`
	RuntimeOpaque    TrustClaim `cbor:"5,keyasint,omitzero" json:"runtime-opaque,omitzero"`
	StorageOpaque    TrustClaim `cbor:"6,keyasint,omitzero" json:"storage-opaque,omitzero"`
	SourcedData      TrustClaim `cbor:"7,keyasint,omitzero" json:"sourced-data,omitzero"`
}

// NewTrustVector returns a new TrustVector with all its claims set to NoClaim.
func NewTrustVector() *TrustVector {
	return &TrustVector{}
}

// Map() returns a map[string]TrustClaim with claims names mapped onto
// corresponding TrustClaim values.
func (o *TrustVector) Map() map[string]TrustClaim {
	return maps.Collect(o.Iter())
}

// TrustVectorFromAny returns a pointer to a TrustVector obtained from the
// provided value. If the value is already a TrustVector, the same one is
// returned; otherwise, a new one is created from the value. If creation fails,
// an error is returned.
func TrustVectorFromAny(value any) (*TrustVector, error) {
	if value == nil {
		return nil, nil
	}

	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return nil, errors.New("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	if vector, ok := value.(TrustVector); ok {
		return &vector, nil

	}

	var trustVector TrustVector

	claims, err := eat.IntOrStringMapFromAny(value)
	if err != nil {
		return nil, err
	}

	for key, value := range claims {
		trustClaim, err := TrustClaimFromAny(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key.String(), err)
		}

		switch key {
		case eat.IntOrStringFromString("instance-identity"):
			trustVector.InstanceIdentity = trustClaim
		case eat.IntOrStringFromString("configuration"):
			trustVector.Configuration = trustClaim
		case eat.IntOrStringFromString("executables"):
			trustVector.Executables = trustClaim
		case eat.IntOrStringFromString("file-system"):
			trustVector.FileSystem = trustClaim
		case eat.IntOrStringFromString("hardware"):
			trustVector.Hardware = trustClaim
		case eat.IntOrStringFromString("runtime-opaque"):
			trustVector.RuntimeOpaque = trustClaim
		case eat.IntOrStringFromString("storage-opaque"):
			trustVector.StorageOpaque = trustClaim
		case eat.IntOrStringFromString("sourced-data"):
			trustVector.SourcedData = trustClaim
		default:
			return nil, fmt.Errorf("unknown claim %q", key.String())
		}
	}

	return &trustVector, err
}

// SetAll sets all vector elements to the specified claim. This is primarily
// useful with globally-applicable claims such as -1 (verifier malfunction), 0
// (no claim, in order to "reset" the vector), or 99 (cryptographic validation
// failed).
func (o *TrustVector) SetAll(c TrustClaim) *TrustVector {
	o.InstanceIdentity = c
	o.Configuration = c
	o.Executables = c
	o.FileSystem = c
	o.Hardware = c
	o.RuntimeOpaque = c
	o.StorageOpaque = c
	o.SourcedData = c

	return o
}

// Report provides an annotated view of the TrustVector state.
// short and color are used to control the level of details and the use of
// colors when printing the trust tier, respectively
func (o TrustVector) Report(short, color bool) string {
	s := "Instance Identity " +
		o.InstanceIdentity.trustTierTag(color) +
		": " +
		o.InstanceIdentity.asInstanceIdentityDetails(short, color) +
		"\n"

	s += "Configuration " +
		o.Configuration.trustTierTag(color) +
		": " +
		o.Configuration.asConfigurationDetails(short, color) +
		"\n"

	s += "Executables " +
		o.Executables.trustTierTag(color) +
		": " +
		o.Executables.asExecutablesDetails(short, color) +
		"\n"

	s += "File System " +
		o.FileSystem.trustTierTag(color) +
		": " +
		o.FileSystem.asFileSystemDetails(short, color) +
		"\n"

	s += "Hardware " +
		o.Hardware.trustTierTag(color) +
		": " +
		o.Hardware.asHardwareDetails(short, color) +
		"\n"

	s += "Runtime Opaque " +
		o.RuntimeOpaque.trustTierTag(color) +
		": " +
		o.RuntimeOpaque.asRuntimeOpaqueDetails(short, color) +
		"\n"

	s += "Storage Opaque " +
		o.StorageOpaque.trustTierTag(color) +
		": " +
		o.StorageOpaque.asStorageOpaqueDetails(short, color) +
		"\n"

	s += "Sourced Data " +
		o.SourcedData.trustTierTag(color) +
		": " +
		o.SourcedData.asSourcedDataDetails(short, color) +
		"\n"

	return s
}

// WrostTier returns name of the element that has the worst (highest severity)
// claim value in the vector and its corresponding TrustTier.
func (o *TrustVector) WorstTier() (string, TrustTier) {
	retLabel := "instance-identity"
	retTier := TrustTierNone

	for label, claim := range o.Iter() {
		claimTier := claim.Tier()
		if claimTier.WorseThan(retTier) {
			retLabel = label
			retTier = claimTier
		}
	}

	return retLabel, retTier
}

// Iter iterates over pairs of vector's claim names and corresponding
// TrustClaim values.
func (o *TrustVector) Iter() iter.Seq2[string, TrustClaim] {
	return func(yield func(string, TrustClaim) bool) {
		if o == nil {
			return
		}

		if !yield("instance-identity", o.InstanceIdentity) {
			return
		}

		if !yield("configuration", o.Configuration) {
			return
		}

		if !yield("executables", o.Executables) {
			return
		}

		if !yield("file-system", o.FileSystem) {
			return
		}

		if !yield("hardware", o.Hardware) {
			return
		}

		if !yield("runtime-opaque", o.RuntimeOpaque) {
			return
		}

		if !yield("storage-opaque", o.StorageOpaque) {
			return
		}

		if !yield("sourced-data", o.SourcedData) {
			return
		}
	}
}

// IsZero returns true if the receiver is a zero value (either nil or all
// elements set to NoClaim).
func (o *TrustVector) IsZero() bool {
	if o == nil {
		return true
	}

	return o.InstanceIdentity == NoClaim &&
		o.Configuration == NoClaim &&
		o.Executables == NoClaim &&
		o.FileSystem == NoClaim &&
		o.Hardware == NoClaim &&
		o.RuntimeOpaque == NoClaim &&
		o.StorageOpaque == NoClaim &&
		o.SourcedData == NoClaim
}
