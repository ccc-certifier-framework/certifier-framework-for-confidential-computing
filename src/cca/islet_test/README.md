# ISLET tests for Attest/Verify, Seal/Unseal core APIs on Arm CCA platform
This sample app is towards Arm CCA with [ISLET SDK](https://github.com/Samsung/islet/tree/main/sdk)
Currently this is running on x86_64 to integrate easily.
The real app running on Arm CCA simulator (arm64) is coming soon.

## How to test
### Setup islet sdk
ISLET SDK is written in Rust but it also supports C/C++.
```sh
../../../third_party/islet/setup.sh
```

### Run tests (simulated version running on x86_64)
```sh
make test
```

## TODO
- [x] Import ISLET SDK and make the sample app (simulated version on x86_64)
- [ ] Integrate interface between `ceritifer` and `islet` (x86_64)
- [ ] Run sample app on Arm CCA simulator
