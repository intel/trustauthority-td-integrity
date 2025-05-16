# TD Integrity Reference Values
This repository contains scripts that collect reference values from Azure and GCP TDX confidential virtual machines (CVMs).
These reference values can be integrated into [Intel® Tiber™ Trust Authority's](http://www.intel.com/trustauthority) (ITA)
opa/rego appraisal process to support TD Integrity.  TD Integrity utilizes ITA's evidence collection and appraisal capabilitiesto verify a CVM's chain of trust (i.e., from its TDX hardware root of trust (HRoT) through the virtual bios and kernel).  For more information see [TD Integrity](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-td-integrity.html).

## Prerequisites
The following prerequisites are needed to collect TD Integrity reference values from an Azure/GCP CVM...
- A login/account to ITA and an ITA API Key.
- An Azure or GCP TDX CVM from which reference values will be collected (see CVM creation instructions for [Azure](https://docs.trustauthority.intel.com/main/articles/articles/ita/tutorial-tdx.html#creating-a-vm-with-intel-tdx-on-microsoft-azure) or [GCP](https://docs.trustauthority.intel.com/main/articles/articles/ita/tutorial-tdx.html#creating-a-cvm-with-intel-tdx-on-gcp)).
- A linux host that can run `reference_values.sh` to generate reference values JSON.  The script requires...
  - opa (see https://www.openpolicyagent.org/docs/latest/)
  - jq (see https://jqlang.org/)

## Instructions
- Start a shell to your TDX CVM and install the `trustauthority-cli` (see https://docs.trustauthority.intel.com/main/articles/articles/ita/integrate-go-tdx-cli.html#simplified-installation-linux).
- Copy `evidence.sh` to the CVM and ensure it is executable (i.e., `chmod +x evidence.sh`).
- Export the following environment variables to the CVM's shell...
    |Env Variable|Description|Example|
    |---|---|---|
    |ITA_API_URL|The instance of ITA used to create and verify reference values.|export ITA_API_URL=https://api.pilot.trustauthority.intel.com|
    |ITA_API_KEY|The API key used to authenticate with ITA.|export ITA_API_KEY={your api-key}|
    |CLOUD_PROVIDER|"gcp" or "azure" is needed.|export CLOUD_PROVIDER=azure|
- Run `sudo -E evidence.sh` to create an attestation token file.  `evidence.sh` will create a file named {CLOUD_PROVIDER}.{timestamp}.jwt (ex. "azure.1747062320.jwt").
- Copy the JWT file into the `evidence` directory (copying multiple JWT files to the evidence directory will result in multiple reference values that can span CSPs, CVM versions, etc.).
- Run `reference_values.sh` to generate `out/reference_values.json`.
- Integrate the generated reference values into ITA's appraisal process by copying the contents `out/reference_values.json` into your policy.  For example...
  ```
  # From out/reference_values.json...
  my_reference_values := {
    "mrtds": [
      {
        "key": "94c0df4d903245...233c6f103d003b14",
        "value": {
          "bios_release": "4.1",
          "cloud_provider": "azure"
        }
      }
    ]
  }

  # pass the reference values to TD Integrity 
  results := data.intel.ita.tdi.appraisal_results(my_reference_values)

  # determines if the token's "policy_ids_matched" is true/false...
  default matches = false
  matches = true {
    # not empty indicates that "input" evidence matched an element in "my_reference_values.mrtds"
    results.mrtd != {}
  }

  ```
- Follow the CSP specific instructions for verifying the TD Integrity appraisal process at [TD Integrity](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-td-integrity.html).
  