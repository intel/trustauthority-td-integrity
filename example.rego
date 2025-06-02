#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# Example "tenant policy" that passes reference values to TD Integrity rego.
#--------------------------------------------------------------------------------------------------
package example # the 'package' statement must be removed before uploading to ITA

import rego.v1

# copy generated reference values here (empty is provided to avoid opa errors)
my_reference_values := {}

# pass the reference values to the TD Integrity catalog policy
results := data.intel.ita.tdi.appraisal_results(my_reference_values)

# compare the results from TD integrity to determine if the token's "policy_ids_matched" is true/false
default matches = false
matches = true if {
  results.mrtd != {}                # not empty indicates an MRTD matched
  results.kernel != {}              # not empty indicates a kernel digest matched
  results.secure_boot == "enabled"  # secure boot is enabled
}

# "export" the results to the token's "policy_defined_claims"
export := {
  "appraisal_results": results
}

