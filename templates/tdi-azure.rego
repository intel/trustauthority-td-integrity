#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#--------------------------------------------------------------------------------------------------
package tdi

# This rego template requires the file name to be passed in as "data"...
# REF_FILE=../reference_values/gcp/6.8.0-1021-gcp.json
# opa eval -f raw -i $REF_FILE -d <(echo "{\"ref_file\": \"${REF_FILE}\"}") -d tdi-gcp.rego "data.tdi.template" | jq

template := {
    "reference_values": [
        {
            "source": data.ref_file,
            "mrtd": mrtd,
            "tdx_debug": tdx_debug,
            "secure_boot": secure_boot,
            "kernel_digest": kernel_digest
        }
    ]
}

mrtd := rv {
    rv := {
        "description": "Require that the MRTD matches a known reference value for Azure TDX CVMs",
        "evidence_path": "tdx.tdx_mrtd",
        "expected_value": input.tdx.tdx_mrtd
    }
}

tdx_debug := rv {
    rv := {
        "description": "Require that the TDX is not in a debug state",
        "evidence_path": "tdx.tdx_td_attributes_debug",
        "expected_value": false
    }
}

# Find and include the SecureBoot efi variable in the event log
secure_boot := rv {
    evl := input.tpm.uefi_event_logs[_]
    evl.index == 7
    evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
    evl.details.unicode_name == "SecureBoot"
    evl.details.variable_data = "AQ==" # "1" or enabled

    rv := {
        "description": "Require that the vTPM event-logs contains a SecureBoot EFI variable with value 1 (or true/enabled)",
        "evidence_path": "tpm.uefi_event_logs",
        "expected_value": evl
    }
}

# Finds the kernel digest from azure evidence (tdx/rtmr uefi event-logs)
kernel_digest := rv {
    # find the kernel measurement
    evl := input.tpm.uefi_event_logs[_]
    evl.index == 4
    evl.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"

    # filter the events on details that start with '/vmlinuz'
    device_paths := evl.details.device_paths[_]
    contains(device_paths, "kernel")
    
    sp := split(device_paths, "\\")
    s := sp[count(sp)-1]
    os := replace(s, ")", "")

    digests := evl.digests[_]
    digests.alg = "SHA-256"
    digest := digests.digest

    rv := {
        "description":  sprintf("Verifies the kernel digest (%s) from the vTPM event-log entry in PCR 4", [os]),
        "evidence_path": "tpm.uefi_event_logs",
        "expected_value": evl
    }
}
