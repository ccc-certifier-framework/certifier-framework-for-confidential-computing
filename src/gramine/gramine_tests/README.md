# Gramine tests for Attest/Verify, Seal/Unseal core APIs on SGX platform

The gramine_tests implement tests for the core APIs needed by Certifier. The tests demonstrate how to Attest/Verify an enclave and provide Seal/Unseal functionality for secrets management. The steps below describe the setup and work needed to run these tests.

1. Clone Gramine
```
git clone https://github.com/gramineproject/gramine.git
```

2. Clone Certifier
Clone certifier in the same parent directory as Gramine above.

```
git clone https://github.com/vmware-research/certifier-framework-for-confidential-computing.git certifier
```

3. Replace ra_tls.h and ra_tls_verify_dcap.c in Gramine
```
cd gramine
git checkout -b gramine-certifier
cp ../certifier/third_party/gramine/tools/sgx/ra-tls/ra_tls.h tools/sgx/ra-tls/
cp ../certifier/third_party/gramine/tools/sgx/ra-tls/ra_tls_verify_dcap.c tools/sgx/ra-tls/
git add tools/sgx/ra-tls
git commit -m "Gramine verification with DCAP needed by certifier"
```

4. Build Gramine
Follow instructions here to build Gramine: https://gramine.readthedocs.io/en/stable/devel/building.html

5. Build Gramine-Certifier tests
```
cd certifier/src/gramine/gramine_tests
make app dcap RA_TYPE=dcap
```

6. Run tests
```
gramine-sgx ./gramine_tests dcap
```

Tests should return successful results for Attest/Verify and Seal/Unseal.
