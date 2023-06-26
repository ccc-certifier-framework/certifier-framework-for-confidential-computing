# SEV SNP VCEK Certificate and Trust Chain

The SEV-SNP VCEK (Versioned Chip Endorsement Key) public key is need to
validate the attestation report signed by the hardware using the chip TCB
unique VCEK private key. The VCEK public key certificate can be obtained from
the AMD KDS service through a public standard API. For details about the API,
please refer to: https://www.amd.com/system/files/TechDocs/57230.pdf

This document will briefly examine the basics covered the document above.

The VCEK certificate is rooted through a certificate chain including the AMD
Root Key (ARK) and the AMD SEV Signing Key (ASK):

ARK (Self-signed) -> ASK -> VCEK

The ARK and ASK are product specific. They can be obtained with the following
REST API:

https://kdsintf.amd.com/vcek/v1/{Product_Name}/cert_chain

For instance, if we want to obtain the ASK and ARK for AMD Milan series of
processors, we could do the following:

https://kdsintf.amd.com/vcek/v1/Milan/cert_chain

Try doing this in a browser and you will be prompted to download the cert file.
This file will be in the PEM format and contains two certificates (ASK and ARK
in that order). You can split them into two PEM files for the certifier SEV-SNP
backend.

The VCEK certificate can be obtained similarly, but it requires Hardware ID and
parameters in addition to Product ID:

https://kdsintf.amd.com/vcek/v1/{product_name}/{hwID}?{parameters}

Alternatively, you can go to https://kdsintf.amd.com/vcek/ and use the UI. You
need to use the AMD guest tools to get the Hardware ID and the parameters
needed. Please refer to the AMD VCEK Certificate document linked above.

