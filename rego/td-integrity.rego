#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#--------------------------------------------------------------------------------------------------
# TD Integrity Policy
#
# Date:   [DATE]
# Branch: [BRANCH]
# Commit: [COMMIT]
#--------------------------------------------------------------------------------------------------
package tdi

# overall determination of TD Integrity (i.e., true or false)
default has_td_integrity := false
has_td_integrity = true {
  compare_mrtd.matches == true
  compare_tdx_debug.matches == true
  compare_secure_boot.matches == true
  compare_kernel_digest.matches == true
}

# export 'appraisal_results' to the attestation token's "policy_defined_claims"
export := {
  "appraisal_results": appraisal_results
}

# builds a json element of matched/unmatched rules
appraisal_results := result {
  mrtd := compare_mrtd
  tdx_debug := compare_tdx_debug
  secure_boot := compare_secure_boot
  kernel_digest := compare_kernel_digest

  result := [
    mrtd,
    tdx_debug,
    secure_boot,
    kernel_digest
  ]
}

#------------------------------------------------------------------------------
# compare_mrtd
#------------------------------------------------------------------------------
default compare_mrtd = {
  "name":  "TDX MRTD",
  "matches": false
}

compare_mrtd := result {
  # get the reference values from all sources
  ref_val := rvs[_]["mrtd"]

  # match the reference values against the input data
  m := matches(ref_val)

  # return a json element that is included in appraisal results
  result := {
    "name":  "TDX MRTD",
    "matches": m,
    "reference_value": ref_val
  }
}

#------------------------------------------------------------------------------
# compare_tdx_debug
#------------------------------------------------------------------------------
default compare_tdx_debug = {
  "name": "TDX Debug",
  "matches": false
}

compare_tdx_debug := result {
  # get the reference values from all sources
  ref_val := rvs[_]["tdx_debug"]

  # match the reference values against the input data
  m := matches(ref_val)

  # return a json element that is included in appraisal results
  result := {
    "name":  "TDX Debug",
    "matches": m,
    "reference_value": ref_val
  }
}

#------------------------------------------------------------------------------
# compare_secure_boot
#------------------------------------------------------------------------------
default compare_secure_boot = {
  "name":  "Secure Boot Enabled",
  "matches": false
}

compare_secure_boot := result {
  # get the reference values from all sources
  ref_val := rvs[_]["secure_boot"]

  # match the reference values against the input data
  m := matches(ref_val)

  # return a json element that is included in appraisal results
  result := {
    "name":  "Secure Boot Enabled",
    "matches": m,
    "reference_value": ref_val
  }
}

#------------------------------------------------------------------------------
# compare_kernel_digest
#------------------------------------------------------------------------------
default compare_kernel_digest = {
  "name":  "Kernel Digest",
  "matches": false
}

compare_kernel_digest := result {
  # get the reference values from all sources
  ref_val := rvs[_]["kernel_digest"]

  # match the reference values against the input data
  m := matches(ref_val)

  # return a json element that is included in appraisal results
  result := {
    "name": "Kernel Digest",
    "matches": m,
    "reference_value": ref_val
  }
}


#------------------------------------------------------------------------------
# utility rules
#------------------------------------------------------------------------------
matches(ref_val) {
  obj := object.get(input, split(ref_val.evidence_path, "."), null)
  not is_array(obj)
  obj == ref_val.expected_value
}

matches(ref_val) {
  obj := object.get(input, split(ref_val.evidence_path, "."), null)
  is_array(obj)
  obj[_] == ref_val.expected_value
}

# The following line is used for debugging rego by aliasing "refernce_values" that 
# are passed on the command line (via "reference_values.json")...
#
#   opa eval -f raw -i evidence.json -d td-integrity.rego -d reference-values.json "data.tdi.appraisal_results"
#
# Otherwise, the project build uses templates to generate reference values from 
# files in reference_values (that are appended to this file).
#
#rvs := data.reference_values

