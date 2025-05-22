#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved. 
#
# Rego script that takes ITA token claims (from Azure/GCP) and converts them
# to reference values JSON (used in reference_values.sh).
#------------------------------------------------------------------------------
package intel.ita.tdi

import rego.v1

# Creates an MRTD reference value from Google TDX evidence and includes
# "value" metadata from evidence's tdx.attester_user_data.
mrtd := rv if {
    input.tdx.attester_runtime_data.bios_vendor == "Google"

    rv := {
        "key": input.tdx.tdx_mrtd,
        "value": {
            "cloud_provider": "gcp",
            "bios_release": input.tdx.attester_runtime_data.bios_release
        }
    }
}

# Creates an MRTD reference value from Azure TDX evidence and includes
# "value" metadata from evidence's tdx.attester_user_data.
mrtd := rv if {
    input.tdx.attester_user_data.bios_vendor == "Microsoft Corporation"

    rv := {
        "key": input.tdx.tdx_mrtd,
        "value": {
            "cloud_provider": "azure",
            "bios_release": input.tdx.attester_user_data.bios_release
        }
    }
}

# Creates a kernel digest reference value from azure evidence (tdx/vtpm 
# uefi event-logs).  Includes "value" metadata from evidence's 
# tdx.attester_user_data.
kernel_digest := rv if {
    input.tdx.attester_runtime_data.bios_vendor == "Google"

    evl := input.tdx.uefi_event_logs[_]
    evl.index == 3
    evl.type_name == "EV_IPL"

    # filter the events on details that start with '/vmlinuz'
    os := evl.details.string
    kernel_string(os)

    digests := evl.digests[_]
    digests.alg = "SHA-384"
    digest := digests.digest

    rv := {
        "key": digests.digest,
        "value": {
            "kernel_version": input.tdx.attester_runtime_data.kernel_version
        }
    }
}

# Creates a kernel digest reference value from Azure evidence (tdx/vtpm 
# uefi event-logs).  Includes "value" metadata from evidence's 
# tdx.attester_user_data.
kernel_digest := rv if {
    input.tdx.attester_user_data.bios_vendor == "Microsoft Corporation"

    evl := input.tpm.uefi_event_logs[_]
    evl.index == 4
    evl.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"

    # filter the events on details that start with '/vmlinuz'
    device_paths := evl.details.device_paths[_]
    contains(device_paths, "kernel")
    
    digests := evl.digests[_]
    digests.alg = "SHA-256"
    digest := digests.digest

    rv := {
        "key": digests.digest,
        "value": {
            "kernel_version": input.tdx.attester_user_data.kernel_version
        }
    }
}

kernel_string(str) if {
    startswith(str, "/vmlinuz") 
}

kernel_string(str) if {
    startswith(str, "/boot/vmlinuz") 
}