# Azure Reference Values
The files in this folder were collected from Azure TDX CVMs.

The TDX CVMs were created using the following command in Azure shell...
```
az vm create --name my-az-tdx-cvm1 \
    --resource-group my-resource-group \
    --size Standard_DC2es_v5 \
    --image Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest \
    --security-type ConfidentialVM \
    --enable-secure-boot true \
    --enable-vtpm true \
    --zone 2 \
    --location eastus2 \
    --nsg-rule NONE \
    --os-disk-security-encryption-type DiskWithVMGuestState \
    --os-disk-delete-option DELETE \
    --data-disk-delete-option DELETE \
    --nic-delete-option DELETE \
    --generate-ssh-keys
```

The following trustauthority-cli (v1.9.0+) command was used to collect an attestation token...
`sudo trustauthority-cli token --tdx --tpm --evl --no-verifier-nonce -c config.json`

The json claims were then extracted from the JWT token and included in this directory.