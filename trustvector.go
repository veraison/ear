// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

// TrustVector is an implementation of the Trustworthiness Vector (and Claims)
// described in §2.3 of draft-ietf-rats-ar4si-03, using a JSON serialization.
type TrustVector struct {
	InstanceIdentity TClaim `json:"instance-identity"`
	Configuration    TClaim `json:"configuration"`
	Executables      TClaim `json:"executables"`
	FileSystem       TClaim `json:"file-system"`
	Hardware         TClaim `json:"hardware"`
	RuntimeOpaque    TClaim `json:"runtime-opaque"`
	StorageOpaque    TClaim `json:"storage-opaque"`
	SourcedData      TClaim `json:"sourced-data"`
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
