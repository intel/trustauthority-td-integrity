# TD Integrity Builds
To support the appraisal of different chains-of-trust (across cloud-providers) and measurements (across different versions of bios, os, etc.), this repository uses Linux scripts (make, bash, etc.) to generate an up-to-date `td-integrity.txt` policy.  The generated policy reflects the golden reference-values (mesaurements) contained in the JSON files in the "reference_values" directory.  This file provides an overview of the automation process that generates `td-integrity.txt`.

Prerequisites
- A Linux host that supports bash (the build scripts are known to work on Ubuntu 22).
- make
- Optional:  node.js for generating HTML refernce-value docs used by the `make doc` target.

The diagram below depicts the overall build process for generating the TD Integrity appraisal-policy.
![Builds](diagrams/builds.drawio.svg)

1. Golden measurements are collected (using trustauthority-cli) from CVMs running in different cloud-providers.  These JSON files have been checked into the `reference_values` directory.  For more information on how the golden measurements were collected, please see the CSP specific instructions in the Readme.md files in the `reference_values` directory.
2. The `make reference-values` target calls `scripts/reference_values.sh` to combine all of the golden measurement files into `out/reference_values.json`.  
3. The `make build` target combines `rego/td-integrity.rego` with `out/reference_values.json` to create `td-integrity.txt`.
4. The `make test` target performs positive validation by confirming the golden measurements are successfully evaluated (this is mainly used to test the logic in `rego/td-integrity.rego`).
5. Optional:  The `make doc` target will generate `out/td-integrity.html` for reference purposes.

*Note: As of v1.15, ITA will not accept policy files that are larger than 20k.  To mitigate that limitation, uneeded files can be removed from the `reference_values` folder.*  
