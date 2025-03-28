# GCP Reference Values
The files in this folder were collected from GCP TDX CVMs.

The TDX CVMs were created using the following command in Google Cloud Shell...
```
gcloud compute instances create my-gcp-tdx-cvm1 \
    --machine-type c3-standard-4 \
    --confidential-compute-type=TDX \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --zone us-central1-a \
    --maintenance-policy=TERMINATE" \
    --project my-project-name
```

The following trustauthority-cli (v1.9.0+) command was used to collect an attestation token...
`sudo trustauthority-cli token --tdx --ccel --no-verifier-nonce -c config.json`

The json claims were then extracted from the JWT token and included in this directory.