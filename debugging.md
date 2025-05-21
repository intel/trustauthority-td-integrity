# Debugging TD Integrity Rego
This file contains instructions on how to locally debug `td-integrity.rego` against ITA attestation token claims json.

1. Create an `input` file containing token claims in JSON format.  Generally, this can be done by getting an ITA attestation token (jwt) using the trustauthority-cli (see [Readme.md](Readme.md)) and extracting its JSON claims.  *Note: the creation of json such files is performed by `reference_values.sh` and are created in the `evidence` folder.*
2. Create reference values.  Follow the instructions in [Readme.md](Readme.md) to create `out/reference_values.json`.
3. Manually copy the JSON contents from `out/reference_values.json` to the `my_reference_values` variable in `example.rego`.  For example...
   ```
    my_reference_values := {
      "mrtds": [
        {
          "key": "a6c9a230bc8...5319096e6d7864f729",
          "value": {
            "bios_release": "4.1"
          }
        }
        ...other reference values
    }
   ```
4. Use opa to evaluate `input` (token claims) against `td-integrity.rego` and `example.rego`.
   1. View appraisal results JSON:  `opa eval -f raw -i {{token claims json file}}} -d example.rego -d td-integrity.rego "data.example.results"`
   2. View matching/unmatching results: `opa eval -f raw -i {{token claims json file}}} -d example.rego -d td-integrity.rego "data.example.matches"`