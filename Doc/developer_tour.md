# Nuts and bolts of the Certifier Framework with a real example

A "Security Domain" is defined by a policy key by a domain owner, say ServiceCo,
to protect  some set of programs that enforce policy using Confidential Computing.


1. ServiceCo generates a policy key and a self signed cert.  Private key is used by
the Certifier Service.

2. The policy cert is conceptually embedded in an application.  In the ServiceCo case,
embedding the key in an application customized the application for ServiceCo.  Note
that the application plus key is the unforgeable "measurement" of the ServiceCo application
and is reflected in the "quote" or "attestation that comes from the program.

3. All the ServiceCos apps (with key) are measured.

4. ServiceCo generates (using utilities) the policy for the domain.


Here is an example of policy for an encrypted VM hosted by SEV:

```
Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says
  Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 
Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says
    Measurement[010203040506070...]  is-trusted 
Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says
    platform[amd-sev-snp, no key, debug:  no, migrate:  no, api-major:  >= 0, api-minor:  >= 0,
      key-share:  no, tcb-version:  >= 0] has-trusted-platform-property  
```

5. This policy is distributed and read into the Certifier Service.

```
00 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] is-trusted 
01 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says
    Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 
02 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] 
    says Measurement[0102030...] is-trusted 
03 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says
    platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0,
      key-share: no, tcb-version: >=0] has-trusted-platform-property 
```

6. Applications call the certifier framework to Attest to an per-instance application
authentication key.

## Example program code

Here is an example of such a program and its interactions with the Certifier API.

```
  #include "policy_key.cc"
  cc_trust_manager* trust_mgr = nullptr;

  // Declare hardware and policy store locationn
  string enclave_type("sev-enclave");
  string purpose("authentication");

  // FLAGS_policy_host is IP address of Certifier Service.
  // FLAGS_policy_port is port number for Certifier Service.
  // FLAGS_policy_store_file is the name of the store file.
  // FLAGS_data_dir is the directory for application files.
  // FLAGS_server_app_host is the IP address the app uses to provide services.
  // FLAGS_server_app_port is the port the app uses to provide services.
  // home_domain_name is the name of the security domain.

  trust_mgr = new cc_trust_manager(enclave_type, purpose, store_file);

  // init policy key from standard location
  trust_mgr->init_policy_key(initialized_cert_size, initialized_cert);

  int n = 0;
  // The following two lines are only needed if sev cannot retrieve standard parameters
  string * s = nullptr;
  get_sev_parameters(&s, &n).

  // Initialize enclave
  //  If n ==0, initialize_enclave gets the parameters automatically.
  trust_mgr->initialize_enclave(n, s)

  // Standard algorithms for the enclave
  string public_key_alg("rsa-2048");
  string symmetric_key_alg("aes-256-cbc-hmac-sha256");

  // Initialize keys
  trust_mgr->cold_init(public_key_alg, symmetric_key_alg,
          home_domain_name, FLAGS_policy_host, FLAGS_policy_port,
          FLAGS_server_app_host, FLAGS_server_app_port);

  // Get certified (Getting "Admissions certificate" naming your public key and measurement)
  trust_mgr->certify_me();


  // Open secure channel
  string my_role("client");  // or "server"
  secure_authenticated_channel channel(my_role);
  channel.init_client_ssl(FLAGS_server_app_host, FLAGS_server_app_port,
          trust_mgr->serialized_policy_cert_, trust_mgr->private_auth_key_,
          trust_mgr->serialized_primary_admissions_cert_);

  Now just read or write over channel.
```

The Certifier Service evaluates the evidence (including the attestation) against the
policy. If the evidence is security-domain compliant, it issues the
"Admission Certificate" naming the Application public key and the program measurement.


## Certifier Service - Request for Certification

Here is how the Certifier Service evaluates a request for certification using policy and
application evidence (including attestations).


After InitProved in the Certifier Service:

```
00 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] is-trusted 

01 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 

02 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
 is-trusted 

03 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0, key-share: no, tcb-version: >=0] has-trusted-platform-property 

04 Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] says Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 

05 Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] says Key[rsa, ASKKey, 94ae81c969a329f1f45e2e222868240d57d1f0f8] is-trusted-for-attestation 

06 Key[rsa, ASKKey, 94ae81c969a329f1f45e2e222868240d57d1f0f8] says Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] is-trusted-for-attestation 

07 Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] says environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-environment 

08 Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] says Key[rsa, auth-key, baf7c80055650283bd2ee59e0c531cd4bc87ac20] speaks-for environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
```

Statements 4-8 were deduced from the evidence provided by the certifier using the "certify_me()"
call and transmitted to the Certifier Service.


Here is the verified proof the Certifier Service generates and validates to determine domain policy compliance.

```
ValidateSevEvidence: Proof

 toProve: Key[rsa, auth-key, baf7c80055650283bd2ee59e0c531cd4bc87ac20] is-trusted-for-authentication 

Proof:
    Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] is-trusted 
     and
    Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
 is-trusted 
     imply via rule 3
    Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
 is-trusted 

    Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] is-trusted 
     and
    Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 
     imply via rule 3
    Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 

    Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] is-trusted-for-attestation 
     and
    Key[rsa, ARKKey, a9c223c6e8ee0be4609445347b2cae59e150f975] says Key[rsa, ASKKey, 94ae81c969a329f1f45e2e222868240d57d1f0f8] is-trusted-for-attestation 
     imply via rule 5
    Key[rsa, ASKKey, 94ae81c969a329f1f45e2e222868240d57d1f0f8] is-trusted-for-attestation 

    Key[rsa, ASKKey, 94ae81c969a329f1f45e2e222868240d57d1f0f8] is-trusted-for-attestation 
     and
    Key[rsa, ASKKey, 94ae81c969a329f1f45e2e222868240d57d1f0f8] says Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] is-trusted-for-attestation 
     imply via rule 5
    Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] is-trusted-for-attestation 

    Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] is-trusted-for-attestation 
     and
    Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] says environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-environment 
     imply via rule 6
    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-environment 

    Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] is-trusted 
     and
    Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0, key-share: no, tcb-version: >=0] has-trusted-platform-property 
     imply via rule 3
    platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0, key-share: no, tcb-version: >=0] has-trusted-platform-property 

    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-environment 
     and
    platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0, key-share: no, tcb-version: >=0] has-trusted-platform-property 
     imply via rule 8
    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] environment-platform-is-trusted 

    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-environment 
     and
    Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
 is-trusted 
     imply via rule 9
    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] environment-measurement-is-trusted 

    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] environment-measurement-is-trusted 
     and
    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] environment-platform-is-trusted 
     imply via rule 10
    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-trusted 

    Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] is-trusted-for-attestation 
     and
    Key[ecc-P-384, VCEKKey, 39622e5b1ab45112e6efc1eb6042d2fb173bc76c6dabf8cdb1800d2b988b288bdb249a6fa3b8de91311957ca1d8c65ef] says Key[rsa, auth-key, baf7c80055650283bd2ee59e0c531cd4bc87ac20] speaks-for environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
     imply via rule 6
    Key[rsa, auth-key, baf7c80055650283bd2ee59e0c531cd4bc87ac20] speaks-for environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]

    environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-trusted 
     and
    Key[rsa, auth-key, baf7c80055650283bd2ee59e0c531cd4bc87ac20] speaks-for environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0, api-minor: =0, tcb-version: =0], measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
     imply via rule 1
    Key[rsa, auth-key, baf7c80055650283bd2ee59e0c531cd4bc87ac20] is-trusted-for-authentication 
```


```
Artifact:
3082037830820260a0030201020208174a04b97945c9bd300d06092a864886f70d01010b050030293118301606035504030c0f706f6c696379417574686f72697479310d300b060355040a0c04726f6f74301e170d3233303330373033313833305a170d3234303330363033313833305a30818d31723070060355040a13694d656173757265642d303130323033303430353036303730383031303230333034303530363037303830313032303330343035303630373038303130323033303430353036303730383031303230333034303530363037303830313032303330343035303630373038311730150603550403130e436572746966696572557365727330820122300d06092a864886f70d01010105000382010f003082010a0282010100baf7c80055650283bd2ee59e0c531cd4bc87ac20524166e6adc9cd5c3a979459a9aae3e5ce00c1fb8ca784749570a4ccb9343c73d7eda6a5148b7a4865798100e50d13aebe37495717fdafec2f36817ae2376cc1eeba9f94baa2e64d49d02e1d92fa175a3c6e30a8065fca64a1a8ac327e397ddee5b4010040800b336e45fa1d636dfb40a21c099a2525f89f332018199ca1d1b96444f532fa90d582901123838b78838c6bf2f4bb11502baa53fa648824b29e365d5453bfc0a986697b5cdce9f0e5445dcaec2d46b499f7b26f60656945f6d001bdc74a2a3aaaed0081a9f02d058ca748cc82530a211b3bf0ea45236d04d964e97464318990a47f8cb15692410203010001a33f303d300e0603551d0f0101ff040403020284301d0603551d250416301406082b0601050507030206082b06010505070301300c0603551d130101ff04023000300d06092a864886f70d01010b05000382010100581417285f5e8e617747ad8667842720c23edad6ef803d902083e1c16ce6826f36d113746325232c7a58f3a67613784cb4c11fbf708cef5c44f3db2c36d4832bfe6c8ff6a0376762aa5dffb191aab46de3d623c81546e3d9244adaba72db7b52e6281a71d59f9a92ac5d116bf9bcd1b8d17a2792017392b0b238062a3822b87c5b80983ec4f985fe4f7a767da3eb2e0d408985f4a3a7166df754bdc9e1d0cb572931c0c88838c45015baad319c15febbd2b86d8a49956b08e24c192066cc6f5a8c5fc2e2c28884e46aad84fe4984562ff2547812f1169257c68c33c2ad722acb8775e6f91156d6830eae400d141f8d68fd0e11d38e3d91c24dc6ce691cfec431
```

This is a der-encoded X509 cert with subject the program measurement, signed by the policy key.


The program we showed you above has two instances.  One is an SSL server and one is an SSL client.

In the simple example, after the certification is done they open a mutually authenticated secure channel.

The Client sends the message "Hi from your secret client" over the secure channel.

```
  running as server
  Server peer id is Measured-010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708
  SSL server read: Hi from your secret client
```

The server responds with "Hi from your secret client"

```
  running as client
  Client peer id is Measured-010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708
  SSL client read: Hi from your secret server
```

