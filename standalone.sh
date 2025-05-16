#!/bin/bash
#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# This script combines example.rego, td-integrity.rego, and the generated
# out/reference_values.json into a single text file (out/td-integrity.txt)
# that can be uploaded as a policy via the ITA portal (i.e. for testing/debugging
# purposes).
#------------------------------------------------------------------------------
OUT_DIR="out"
REFERENCE_VALUES_JSON="${OUT_DIR}/reference_values.json"
TD_INTEGRITY_REGO="td-integrity.rego"
EXAMPLE_REGO="example.rego"
OUTPUT_FILE="${OUT_DIR}/td-integrity.txt"

if [ ! -e ${REFERENCE_VALUES_JSON} ]; then
    echo "Error: ${REFERENCE_VALUES_JSON} does not exist"
    exit 1
fi

cp ${EXAMPLE_REGO} ${OUTPUT_FILE}
cat ${TD_INTEGRITY_REGO} >> ${OUTPUT_FILE}
sed -i '/^package/ s/^/#/' ${OUTPUT_FILE}   # comment out package statements
sed -i '/^my_reference_values/ s/^/#/' ${OUTPUT_FILE}   # comment out "my_reference_values" 
sed -i 's/\(:= *\)[a-zA-Z0-9_.]*\.\(appraisal_results(my_reference_values)\)/\1\2/' ${OUTPUT_FILE}

echo "#--------------------------------------------------------------------------------------------------" >> ${OUTPUT_FILE}
echo "# REFERENCE VALUES" >> ${OUTPUT_FILE}
echo "#--------------------------------------------------------------------------------------------------" >> ${OUTPUT_FILE}
echo "my_reference_values := $(cat ${REFERENCE_VALUES_JSON})" >> ${OUTPUT_FILE}