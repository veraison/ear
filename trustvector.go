// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"fmt"
	"strings"
)

// TrustVector is an implementation of the Trustworthiness Vector (and Claims)
// described in §2.3 of draft-ietf-rats-ar4si-03, using a JSON serialization.
type TrustVector struct {
	InstanceIdentity TrustClaim `json:"instance-identity"`
	Configuration    TrustClaim `json:"configuration"`
	Executables      TrustClaim `json:"executables"`
	FileSystem       TrustClaim `json:"file-system"`
	Hardware         TrustClaim `json:"hardware"`
	RuntimeOpaque    TrustClaim `json:"runtime-opaque"`
	StorageOpaque    TrustClaim `json:"storage-opaque"`
	SourcedData      TrustClaim `json:"sourced-data"`
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
	var (
		tv  TrustVector
		err error
	)

	switch t := v.(type) {
	case TrustVector:
		tv = t
	case *TrustVector:
		tv = *t
	case map[string]interface{}:
		tv, err = getTrustVectorFromMap(t)
	case map[string]string:
		m := make(map[string]interface{}, len(t))
		for k, v := range t {
			m[k] = v
		}
		tv, err = getTrustVectorFromMap(m)
	default:
		err = fmt.Errorf("invalid value for TrustVector: %v", t)
	}

	return &tv, err
}

func getTrustVectorFromMap(m map[string]interface{}) (TrustVector, error) {
	var vector TrustVector

	expected := []string{
		"instance-identity",
		"configuration",
		"executables",
		"file-system",
		"hardware",
		"runtime-opaque",
		"storage-opaque",
		"sourced-data",
	}

	extra := getExtraKeys(m, expected)
	if len(extra) > 0 {
		return vector, fmt.Errorf("found unexpected fields: %s", strings.Join(extra, ", "))
	}

	if err := populateClaimFromMap(m, "instance-identity", &vector.InstanceIdentity); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "configuration", &vector.Configuration); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "executables", &vector.Executables); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "file-system", &vector.FileSystem); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "hardware", &vector.Hardware); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "runtime-opaque", &vector.RuntimeOpaque); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "storage-opaque", &vector.StorageOpaque); err != nil {
		return vector, err
	}

	if err := populateClaimFromMap(m, "sourced-data", &vector.SourcedData); err != nil {
		return vector, err
	}

	return vector, nil
}

func populateClaimFromMap(m map[string]interface{}, key string, dest *TrustClaim) error {
	v, ok := m[key]
	if !ok {
		return nil
	}

	claim, err := ToTrustClaim(v)
	if err != nil {
		return fmt.Errorf("bad value for %q: %w", key, err)
	}

	*dest = *claim

	return err
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
