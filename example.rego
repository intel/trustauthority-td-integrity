#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# Example "tenant policy" that passes reference values to TD Integrity.
#--------------------------------------------------------------------------------------------------
package example

# This rego example can be run locally using the following opa commands...
# - Show appraisal_results JSON...
#   opa eval -f raw -i {{ITA Token Claims JSON}}} -d example.rego -d td-integrity.rego "data.example.results"
# - Show matching results (true/false)
#   opa eval -f raw -i {{ITA Token Claims JSON}}} -d example.rego -d td-integrity.rego "data.example.matches"

# pass the reference values to TD Integrity
results := data.intel.ita.tdi.appraisal_results(my_reference_values)

# determines if the token's "policy_ids_matched" is true/false..
default matches = false
matches = true {
  results.mrtd != {}                # not empty indicates an MRTD matched
  results.kernel != {}              # not empty indicates a kernel digest matched
  results.secure_boot == "enabled"  # secure boot is enabled
}

# "export" the results to the token's "policy_defined_claims"
export := {
  "appraisal_results": results
}

# copy generated reference values here (empty is provided to avoid opa errors)...
my_reference_values := {}

