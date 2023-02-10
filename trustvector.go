// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

// TrustVector is an implementation of the Trustworthiness Vector (and Claims)
// described in §2.3 of draft-ietf-rats-ar4si-03, using a JSON serialization.
type TrustVector struct {
	InstanceIdentity TrustClaim `json:"instance-identity,omitempty"`
	Configuration    TrustClaim `json:"configuration,omitempty"`
	Executables      TrustClaim `json:"executables,omitempty"`
	FileSystem       TrustClaim `json:"file-system,omitempty"`
	Hardware         TrustClaim `json:"hardware,omitempty"`
	RuntimeOpaque    TrustClaim `json:"runtime-opaque,omitempty"`
	StorageOpaque    TrustClaim `json:"storage-opaque,omitempty"`
	SourcedData      TrustClaim `json:"sourced-data,omitempty"`
}

// AsMap() returns a map[string]TrustClaim with claims names mapped onto
// corresponding TrustClaim values.
func (o TrustVector) AsMap() map[string]TrustClaim {
	return map[string]TrustClaim{
		"instance-identity": o.InstanceIdentity,
		"configuration":     o.Configuration,
		"executables":       o.Executables,
		"file-system":       o.FileSystem,
		"hardware":          o.Hardware,
		"runtime-opaque":    o.RuntimeOpaque,
		"storage-opaque":    o.StorageOpaque,
		"sourced-data":      o.SourcedData,
	}
}

func ToTrustVector(v interface{}) (*TrustVector, error) {
	var tv TrustVector

	err := populateStructFromInterface(
		&tv, v, "json",
		map[string]parser{}, // use defaultParser below for everything
		func(iface interface{}) (interface{}, error) {
			claim, err := ToTrustClaim(iface)
			return *claim, err
		})

	return &tv, err
}

// SetAll sets all vector elements to the specified claim. This is primarily
// useful with globally-applicable claims such as -1 (verifier malfunction), 0
// (no claim, in order to "reset" the vector), or 99 (cryptographic validation
// failed).
func (o *TrustVector) SetAll(c TrustClaim) {
	o.InstanceIdentity = c
	o.Configuration = c
	o.Executables = c
	o.FileSystem = c
	o.Hardware = c
	o.RuntimeOpaque = c
	o.StorageOpaque = c
	o.SourcedData = c
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
