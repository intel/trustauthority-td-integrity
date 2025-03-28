#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# This script combines reference values (created by reference_values.sh) into
# a single appraisal-policy (td-integrity.txt) that can be uploaded to ITA.
#------------------------------------------------------------------------------
#!/bin/bash

REGO_OUTPUT_FILE="out/td-integrity.rego"                    # unaltered rego policy
TEXT_OUTPUT_FILE="out/td-integrity.txt"                     # ITA friendly policy without "package"
RV_FILE="out/reference-values.json"                         # reference values in json (expected to be present)
DOCS_OUTPUT_FILE="out/td-integrity-reference-values.html"   # reference values in html

# generate reference files and write to out directory
RV_JSON=$(cat ${RV_FILE})

# strip the top level "refernce_values" element so that the appended rego
# object is an array
RV_ARRAY=$(jq -n '[input | .reference_values] | add' <<< "${RV_JSON}")

cp rego/td-integrity.rego ${REGO_OUTPUT_FILE}
sed -i "s/\[DATE\]/$(date +"%Y-%m-%dT%H:%M:%S%z")/g" ${REGO_OUTPUT_FILE}
sed -i "s/\[BRANCH\]/$(git branch --show-current)/g" ${REGO_OUTPUT_FILE}
sed -i "s/\[COMMIT\]/$(git log --pretty=tformat:"%h" -n1 .)/g" ${REGO_OUTPUT_FILE}
echo "#------------------------------------------------------------" >> ${REGO_OUTPUT_FILE}
echo "# Reference Values" >> ${REGO_OUTPUT_FILE}
echo "#------------------------------------------------------------" >> ${REGO_OUTPUT_FILE}
echo "rvs := ${RV_ARRAY}" >> ${REGO_OUTPUT_FILE}

# create a text file version withouth the package declaration suitable for
# upload to ITA.
cp ${REGO_OUTPUT_FILE} ${TEXT_OUTPUT_FILE}
sed -i 's/package tdi/#package tdi/g' ${TEXT_OUTPUT_FILE}
