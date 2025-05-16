#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# TD Integrity Policy
#--------------------------------------------------------------------------------------------------
package intel.ita.tdi

appraisal_results(reference_values) := result {
  m := find_mrtd(reference_values.mrtds)
  k := find_kernel(reference_values.kernel_digests)
  sb := secure_boot

  result := {
   "mrtd": m,
   "secure_boot": sb,
   "kernel": k
  }
}

find_mrtd(mrtds) := found {
  m := mrtds[_]
  m.key == input.tdx.tdx_mrtd
  found := m
} else = found {
  found := {}
}

find_kernel(kernel_digests) := found {
  evl := input.tpm.uefi_event_logs[_]
  evl.index == 4
  evl.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"

  digests := evl.digests[_]
  digests.alg = "SHA-256"
  digest := digests.digest

  k := kernel_digests[_]
  k.key == digest
  found := k
} else := found {
  evl := input.tdx.uefi_event_logs[_]
  evl.index == 3
  evl.type_name == "EV_IPL"

  digests := evl.digests[_]
  digests.alg = "SHA-384"
  digest := digests.digest

  k := kernel_digests[_]
  k.key == digest
  found := k
} else := found {
  found := {}
}

secure_boot := result {
  evl := input.tpm.uefi_event_logs[_]
#  evl.digest_matches_event == true
  evl.index == 7
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data == "AQ==" # base64 value of 1 (or true)
  result := "enabled"
} else := result {
  evl := input.tpm.uefi_event_logs[_]
#  evl.digest_matches_event == true
  evl.index == 7
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data != "AQ==" # ! base64 value of 1 (or true)
  result := "disabled"
} else := result {
  evl := input.tdx.uefi_event_logs[_]
#  evl.digest_matches_event == true
  evl.index == 1
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data == "AQ==" # base64 value of 1 (or true)
  result := "enabled"
} else := result {
  evl := input.tdx.uefi_event_logs[_]
#  evl.digest_matches_event == true
  evl.index == 1
  evl.type_name == "EV_EFI_VARIABLE_DRIVER_CONFIG"
  evl.details.unicode_name == "SecureBoot"
  evl.details.variable_data != "AQ==" # ! base64 value of 1 (or true)
  result := "disabled"
} else {
  result := "unknown"
}

