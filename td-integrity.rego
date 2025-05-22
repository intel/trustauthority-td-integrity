#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# TD Integrity Policy:  This rego policy provides the 'appraisal_results' function that requires
# 'reference_values' as an input parameter.  When successful, it returns a JSON element that 
# describes the appraisal process performed by TD Integrity.
#
# INPUT:
# - input:  This rego policy exects rego 'input' from ITA attestation tokens with...
#   - 'tdx' evidence (required to validate mrtd reference values)
#   - 'event-logs' (required to evaluate 'secure_boot' and/or 'kernel'). This policy handles 
#     event-logs from "tpm" evidence or "ccel" (embedded in "tdx" evidence).
# - 'reference_values': Measurements must be provided via the JSON 'reference_values' parameter
#   in the following format...
#   {
#     "mrtds": []           // required array containing one or more mrtd key/value pairs
#     "kernel_digests": []  // optional array of kernel digest key/value pairs
#   } 
#
#   Each mrtds/kernel_digests array element must contain...
#   {
#     "key": "{{actual digest/measurement}},
#     "value": {
#       "field1": "value1"   // arbitrary fields that describe the measurement (ex. bios version)
#     }
#   }
#
# OUTPUT:
#  When successful, the 'appraisal_results' will return a JSON object in the following format...
#  {
#    "mrtd": {matching mrtd key/value reference object},
#    "kernel": {matching kernel_digest key/value reference object},
#    "secure_boot": "enabled" | "disabled" | "unknown"
#  }
#
# The expected results of 'apprasail_results' are...
#  - If the evidence tdx.tdx_mrtd value does not match one of the provided "mrtds" reference 
#    values, TDI's appraisal_result.mrtd object will be empty (i.e., "{}").  Otherwise, the 
#    appraisal_result.mrtd object will include the key/value pair from the matching "mrtds"  
#    reference value.
#  - If the evidence's event-log (CCEL or vTPM) does not match one of the provided "kernel_digests"
#    reference values, TDI's appraisal_result.kernel object will be empty (i.e., "{}").  Otherwise,
#    the appraisal_result.kernel object will include the key/value pair from the matching 
#    "kernel_digests" reference value.
#  - When the evidence does not contain CCEL/vTPM event-logs, the appraisal_result.secure_boot 
#    will be "unknown".  If the event-logs are present and the secure boot variable event cannot 
#    be found, the appraisal_result.secure_boot will be "unknown".  If the event-logs are present 
#    and the secure boot variable is "AQ==" (base64 for 1), appraisal_result.secure_boot will 
#    be "enabled".  If the event-logs are present and the secure boot variable is not "AQ==", 
#    appraisal_result.secure_boot will be "disabled".
#--------------------------------------------------------------------------------------------------
package intel.ita.tdi

import rego.v1

appraisal_results(reference_values) := result if {
  m := find_mrtd(reference_values.mrtds)
  k := find_kernel(reference_values.kernel_digests)
  sb := secure_boot

  result := {
   "mrtd": m,
   "secure_boot": sb,
   "kernel": k
  }
}

find_mrtd(mrtds) := found if {
  m := mrtds[_]
  m.key == input.tdx.tdx_mrtd
  found := m
} else = found if {
  found := {}
}

find_kernel(kernel_digests) := found if {
  evl := input.tpm.uefi_event_logs[_]
  evl.index == 4
  evl.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"

  digests := evl.digests[_]
  digests.alg = "SHA-256"
  digest := digests.digest

  k := kernel_digests[_]
  k.key == digest
  found := k
} else := found if {
  evl := input.tdx.uefi_event_logs[_]
  evl.index == 3
  evl.type_name == "EV_IPL"

  digests := evl.digests[_]
  digests.alg = "SHA-384"
  digest := digests.digest

  k := kernel_digests[_]
  k.key == digest
  found := k
} else := found if {
  found := {}
}

secure_boot := result if {
  evl := input.tpm.uefi_event_logs[_]
  evl.digest_matches_event == true
  evl.index == 7
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data == "AQ==" # base64 value of 1 (or true)
  result := "enabled"
} else := result if {
  evl := input.tpm.uefi_event_logs[_]
  evl.digest_matches_event == true
  evl.index == 7
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data != "AQ==" # ! base64 value of 1 (or true)
  result := "disabled"
} else := result if {
  evl := input.tdx.uefi_event_logs[_]
  evl.digest_matches_event == true
  evl.index == 1
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data == "AQ==" # base64 value of 1 (or true)
  result := "enabled"
} else := result if {
  evl := input.tdx.uefi_event_logs[_]
  evl.digest_matches_event == true
  evl.index == 1
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data != "AQ==" # ! base64 value of 1 (or true)
  result := "disabled"
} else := result if {
  result := "unknown"
}

