#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# This script validates that the generated rego file successfully validates the
# reference-values from golden measurements files in the "refrence_values" 
# directory.
#------------------------------------------------------------------------------
#!/bin/bash

RV_FOLDER="reference_values"

for file in $(find "${RV_FOLDER}" -type f -name "*.json"); do
    echo Testing file $file

    result=$(opa eval -f raw -i "${file}" -d "out/td-integrity.rego" "data.tdi.has_td_integrity")
    if [ $? -ne 0 ]; then
        echo "Failed to evaluate policy"
        exit 1
    fi

    if [ "$result" != "true" ]; then
        echo "Policy evaluation failed"
        exit 1
    fi
done