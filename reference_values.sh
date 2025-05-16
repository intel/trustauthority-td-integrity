#!/bin/bash
#------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# This script uses rego to build reference_values.json from ITA JWT tokens in
# the "evidence" directory.
#------------------------------------------------------------------------------
EVIDENCE_FOLDER="evidence"

mrtds=()
kernel_digests=()
for TOKEN_FILE in $(find "${EVIDENCE_FOLDER}" -type f -name "*.jwt"); do
    JSON_FILE="${TOKEN_FILE%.jwt}.json"
    
    # extract json from the token and save to file
    PAYLOAD=$(cat "$TOKEN_FILE" | cut -d '.' -f 2)
    CLAIMS=$(echo "$PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null)
    echo $CLAIMS | jq > "$JSON_FILE"

    mrtds+=($(opa eval -f raw -i $JSON_FILE -d template.rego "data.intel.ita.tdi.mrtd" | jq -c))
    kernel_digests+=($(opa eval -f raw -i $JSON_FILE -d template.rego "data.intel.ita.tdi.kernel_digest" | jq -c))
done

mkdir -p out

jq -n \
  --argjson mrtds "$(printf '%s\n' "${mrtds[@]}" | jq -s '.')" \
  --argjson kernel_digests "$(printf '%s\n' "${kernel_digests[@]}" | jq -s '.')" \
  '{mrtds: $mrtds, kernel_digests: $kernel_digests}' > out/reference_values.json
