#!/bin/bash
#--------------------------------------------------------------------------------------------------
# Copyright(C) 2025 Intel Corporation. All Rights Reserved.
#
# This script automates the collection of ITA tokens from GCP/Azure TDX CVMs to support the creation
# of TD Integrity reference values.  It includes "METADATA" from the host into the token so that
# "reference_values.sh" can include it into reference values.
#--------------------------------------------------------------------------------------------------
CLOUD_PROVIDER=${CLOUD_PROVIDER:-""}
ITA_API_URL=${ITA_API_URL:-"https://api.pilot.trustauthority.intel.com"}
ITA_API_KEY=${ITA_API_KEY:-""}
CONFIG_FILE=${CONFIG_FILE:-"config.json"}
TRUST_AUTHORITY_CLI="trustauthority-cli"
TOKEN_ARGS=""

# check env vars and dependencies
if [[ -z ${CLOUD_PROVIDER} ]]; then
  echo "Error: CLOUD_PROVIDER was not provided"
  exit 1
fi

if [[ -z ${ITA_API_KEY} ]]; then
  echo "Error: ITA_API_KEY  was not provided"
  exit 1
fi

ITA_VERSION=$(${TRUST_AUTHORITY_CLI} version)
if [ $? -ne 0 ]; then
  echo "Error: trustauthority-cli is not installed"
fi
echo "ITA CLI version: ${ITA_VERSION}"

# Build CSP specific config file and token args
if [[ ${CLOUD_PROVIDER} == "azure" ]]; then
cat <<EOF > ${CONFIG_FILE}
{
  "cloud_provider": "${CLOUD_PROVIDER}",
  "trustauthority_api_url": "${ITA_API_URL}",
  "trustauthority_api_key": "${ITA_API_KEY}",
  "tpm": {
    "ak_handle": "81000003"
  }
}
EOF

  # Azure specific token args
  TOKEN_ARGS="--tdx --tpm --evl"

elif [[ ${CLOUD_PROVIDER} == "gcp" ]]; then
cat <<EOF > ${CONFIG_FILE}
{
  "trustauthority_api_url": "${ITA_API_URL}",
  "trustauthority_api_key": "${ITA_API_KEY}"
}
EOF

  # GCP specific token args
  TOKEN_ARGS="--tdx --ccel"

else
  echo "Error: Unsupported cloud provided: ${CLOUD_PROVIDER}"
  exit 1
fi

# Collect metadata that will be included in the token
METADATA=$(cat <<EOF
{
  "cli_version": "$(${TRUST_AUTHORITY_CLI} version | sed -n 's/^Version: //p')",
  "bios_vendor": "$(cat /sys/class/dmi/id/bios_vendor)",
  "bios_release": "$(cat /sys/class/dmi/id/bios_release)",
  "kernel_version": "$(uname -r)"
}
EOF
)
MD64=$(echo "${METADATA}" | base64 -w 0)

# Run the token command, collect a token and save it to a file
TOKEN=$(eval "${TRUST_AUTHORITY_CLI} token -c ${CONFIG_FILE} ${TOKEN_ARGS} -u $MD64")
if [ $? -ne 0 ]; then
  echo "Error: failed to get token from ITA"
  exit 1
fi

FILE_NAME=${CLOUD_PROVIDER}.$(date +%s).jwt
echo $TOKEN > ${FILE_NAME}
echo "ITA token saved to ${FILE_NAME}"
