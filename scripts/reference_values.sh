#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# This script uses rego to collect reference-values from the json files in the
# "refernce_values" directory and comine them into a single JSON object.
#------------------------------------------------------------------------------
#!/bin/bash

RV_FOLDER="reference_values"

# collect reference values from each json file in the reference_values folder
reference_values=()
for file in $(find "${RV_FOLDER}" -type f -name "*.json"); do
    # get the cloud provider from the file's parent folder
    cloud_provider="$(basename "$(dirname "$file")")"

    # use a cloud provider specific rego template to collect the reference values from the file
    reference_values+=$(opa eval -f raw -i "${file}" -d <(echo "{\"ref_file\": \"${file}\"}") -d templates/tdi-"${cloud_provider}".rego "data.tdi.template")
done

# combine all reference values into a single json object
jq -n '{ reference_values: [inputs | .reference_values] | add}' <<< "${reference_values[@]}"