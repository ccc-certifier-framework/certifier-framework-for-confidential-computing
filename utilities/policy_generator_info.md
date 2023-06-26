# Building the Policy Generator:

You will need the json-schema-validator library which in turn depends on the
JSON for Modern C++ library. Follow these instructions to have them
built and installed on your system:

```shell
git clone https://github.com/nlohmann/json.git
cd json
mkdir build
cd build
cmake ..
make
make install

git clone https://github.com/pboettch/json-schema-validator.git
cd json-schema-validator
mkdir build
cd build
cmake .. -DBUILD_SHARED_LIBS=ON ..
make
make install
```

Both libraries should be installed under `/usr/local` by default. If this is not
the case, remember to update the JSON_VALIDATOR variable in
`policy_generator.mak` .

Add `/usr/local/lib` to `/etc/ld.so.conf` and run ldconfig if not already done.

The Policy Generator utility can then be built using:
```shell
make -f policy_generator.mak
```

You can then use the generator by invoking:

```shell
policy_generator.exe --policy_input=<your policy JSON>
```

By default, the generator is using `policy_schema.json` in the same directory as
schema input. If you want to use a custom schema, use the `--schema_input`
option. The default policy output is "policy.bin" in the invoking directory.
This can be overwritten using the `--policy_output` argument.

If the Certifier Utilitites are not in your path, you can specify `--util_path`.
The `--debug` argument will show more debug info.

The generator invokes Certifier utilities to generate the policy bundle by
default. If you want to do a dry-run or generate a bash script which can be
executed later, use the `--script` argument.

## Some example usages are:

```shell
policy_generator.exe --policy_input=sev_policy.json --schema_input=schema.json \
  --util_path=../utilities --policy_output=my_policy.bin --debug

policy_generator.exe --policy_input=sev_policy.json --script > script.sh
```

## Example JSON policy file

Given an example policy below:

{
  "policyKey" : "policy_key_file.bin",

  "platforms": [{
      "type": "amd-sev-snp",
      "props": [{
          "comparator": "eq",
          "type": "string",
          "name": "debug",
          "value": "no"
        },
        {
          "comparator": "eq",
          "type": "string",
          "name": "migrate",
          "value": "no"
        },
        {
          "comparator": "eq",
          "type": "string",
          "name": "key-share",
          "value": "no"
        },
        {
          "comparator": "ge",
          "type": "int",
          "name": "api-major",
          "value": "0"
        },
        {
          "comparator": "ge",
          "type": "int",
          "name": "api-minor",
          "value": "0"
        }
      ]
    }
  ],

  "measurements" : [
    "010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708"
  ],

  "claims" : [{
      "unaryClause" : {
        "keySubject" : "policy_ark_file.bin",
        "verb" : "is-trusted-for-attestation"
      },
      "verb" : "says",
      "keySubject" : "policy_key_file.bin"
    }
  ]
}

----

The following policy bundle can be generated:

```
3 blocks
1:
Signed claim
format: vse-clause

not before: 2023-03-04T23:40:45.00000Z
not after: 2024-03-14T23:40:45.00000Z
Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says platform[amd-sev-snp, no key, debug:  no, migrate:  no, key-share:  no, api-major:  = 0, api-minor:  = 0] has-trusted-platform-property
Serialized: ...

2:
Signed claim
format: vse-clause

not before: 2023-03-04T23:40:45.00000Z
not after: 2024-03-14T23:40:45.00000Z
Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]  is-trusted
Serialized: ...

3:
Signed claim
format: vse-clause

not before: 2023-03-04T23:40:45.00000Z
not after: 2024-03-14T23:40:45.00000Z
Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Key[rsa, ARKKey, cd107487f4238122ed5cbdb126aabee3e8456c20] is-trusted-for-attestation
Serialized: ...
```