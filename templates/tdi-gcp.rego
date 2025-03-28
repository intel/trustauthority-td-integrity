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
        "description": "Require that the MRTD matches a known reference value for GCP TDX CVMs",
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

secure_boot := rv {
    rv := {
        "description": "Require that the RTMR event-logs contains a SecureBoot EFI variable with value 1 (or true/enabled)",
        "evidence_path": "tdx.uefi_event_logs",
        "expected_value": {
            "details": {
                "unicode_name": "SecureBoot",
                "unicode_name_length": 10,
                "variable_data": "AA==",
                "variable_data_length": 1,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
            },
            "digest_matches_event": true,
            "digests": [
                {
                    "alg": "SHA-384",
                    "digest": "cfa4e2c606f572627bf06d5669cc2ab1128358d27b45bc63ee9ea56ec109cfafb7194006f847a6a74b5eaed6b73332ec"
                }
            ],
            "event": "Yd/ki8qT0hGqDQDgmAMrjAoAAAAAAAAAAQAAAAAAAABTAGUAYwB1AHIAZQBCAG8AbwB0AAA=",
            "index": 1,
            "type": 2147483649,
            "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
        }
    }
}

# Finds the kernel digest from azure evidence (tdx/rtmr uefi event-logs)
kernel_digest := rv {
    # find the kernel measurement
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
        "description":  sprintf("Verifies the kernel digest (%s) from the RTMR event-log entry in index 3", [os]),
        "evidence_path": "tdx.uefi_event_logs",
        "expected_value": evl
    }
}

kernel_string(str) {
    startswith(str, "/vmlinuz") 
}

kernel_string(str) {
    startswith(str, "/boot/vmlinuz") 
}