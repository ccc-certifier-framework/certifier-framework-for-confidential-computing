
# Privacy Preserving data analytics with Certifier Framework 

This sample application demonstrates how to conduct privacy preserving data analytics with 
the Certifier Framework on openenclave. It has the following properties: 
* Demonstrates how to securely use certifier framework  
   * configures custom trusted policy and security domain
   * conducts data analytics only on certified secure enclaves  
* Deploys an existing openenclave application with the certifier framework
* End-to-end privacy preserving data analytics 
   * protects the dataset sent to the enclave
   * protects the result returned from the enclave
   * secures the analytics computation done in the enclave

**Note:** 
The existing demostration has been tested with SGX hardware mode and simulation mode, but it 
does not leverage the openenclave's interface for getting and verifying the measurement.
Future release will fix this issue.  

### On Simulated Enclave 

#### Prerequisites 
The example is build on [Open Enclave](https://github.com/openenclave/openenclave). 
Please refer to the [link](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs#hardware-drivers)
 for instructions. The example also relies on the protobuf built specifically with 
 openenclave libc, which the instructions can be found [here](../../openenclave_test/instructions.txt)

To configure the environment variables for this project, first point `$CERTIFIER` to 
the top level of the certifier repository. such as 
```
export CERTIFIER=~/certifier-framework-for-confidential-computing
```
Then run 
```
export CERTIFIER_PROTOTYPE=$CERTIFIER
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/motion_planning
export PATH=$PATH:/usr/local/go/bin && export PATH=$PATH:$(go env GOPATH)/bin
source /opt/openenclave/share/openenclave/openenclaverc
```
`$CERTIFIER` is the top level directory for the certifier repository.

#### Build and Run

Step 1: Load the third party libraries 
```bash
cd $EXAMPLE_DIR/third_party
chmod +x ./load_dataframe.sh
./load_dataframe.sh
```
This will load and build the [Dataframe](https://github.com/hosseinmoein/DataFrame)
dependency of the project with openenclave SDK.

Step 1: Build the utilities
```bash
cd $CERTIFIER_PROTOTYPE
cd utilities
make -f cert_utility.mak
make -f policy_utilities.mak
```


Step 2: Generate the policy key and self-signed cert
```bash
mkdir $EXAMPLE_DIR/provisioning
cd $EXAMPLE_DIR/provisioning
$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe --operation=generate-policy-key-and-test-keys \
    --policy_key_output_file=policy_key_file.bin --policy_cert_output_file=policy_cert_file.bin \
    --platform_key_output_file=platform_key_file.bin --attest_key_output_file=attest_key_file.bin
```
This will also generate the attestation key and platform key for the these tests.

Step 3: Embed the policy key in example_app.
```bash
cd $EXAMPLE_DIR/provisioning
$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe --input=policy_cert_file.bin --output=../policy_key.cc
```

Step 4: Compile example_app with the embedded policy_key
```bash
cd $EXAMPLE_DIR
make
```

Step 6: Obtain the measurement of the trusted application for the security domain.
```bash
cd $EXAMPLE_DIR/provisioning
$CERTIFIER_PROTOTYPE/utilities/measurement_utility.exe --type=hash --input=../enclave/enclave.signed \
      --output=example_app.measurement
```

Step 7: Author the policy for the security domain and produce the signed claims the apps need.
```bash
cd $EXAMPLE_DIR/provisioning

# a. Construct statement "policy-key says example_app-measurement is-trusted"
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --key_subject="" \
   --measurement_subject=example_app.measurement --verb="is-trusted" \
   --output=ts1.bin
$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe --key_subject=policy_key_file.bin \
   --verb="says" --clause=ts1.bin --output=vse_policy1.bin

# b. Construct statement "policy-key says the platform-key is-trusted-for-attestation"
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --key_subject=platform_key_file.bin \
   --verb="is-trusted-for-attestation" --output=ts2.bin
$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe --key_subject=policy_key_file.bin \
   --verb="says" --clause=ts2.bin --output=vse_policy2.bin

# c. Produce the signed claims for each vse policy statement.
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe \
   --vse_file=vse_policy1.bin --duration=9000 \
   --private_key_file=policy_key_file.bin --output=signed_claim_1.bin
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe --vse_file=vse_policy2.bin \
   --duration=9000 --private_key_file=policy_key_file.bin --output=signed_claim_2.bin

# d. Combine signed policy statements for Certifier Service use.
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe --input=signed_claim_1.bin,signed_claim_2.bin\
   --output=policy.bin

# e. Construct statement "platform-key says attestation-key is-trusted-for-attestation" and sign it
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --key_subject=attest_key_file.bin \
   --verb="is-trusted-for-attestation" --output=tsc1.bin
$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe --key_subject=platform_key_file.bin \
   --verb="says" --clause=tsc1.bin --output=vse_policy3.bin
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe --vse_file=vse_policy3.bin \
   --duration=9000 --private_key_file=platform_key_file.bin \
   --output=platform_attest_endorsement.bin
```

Step 8: Provisioning data 
```bash
cd $EXAMPLE_DIR
mkdir app1_data app2_data service
cd $EXAMPLE_DIR/provisioning
cp ./* $EXAMPLE_DIR/app1_data
cp ./* $EXAMPLE_DIR/app2_data
cp policy_key_file.bin policy_cert_file.bin policy.bin $EXAMPLE_DIR/service
```

Step 9: Start the Certifier Service
  In a new terminal window:
```bash
cd $EXAMPLE_DIR/service
$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
--path=$EXAMPLE_DIR/service \
--policyFile=policy.bin --readPolicy=true
```

Step 10:  Run the apps and get admission certificates from Certifier Service
  Open two new terminals (one for the app as a client and one for the app as a server):
The `--simulate` flag is only required for running the application in SGX simulation mode.

On the client's terminal, run 
```bash
cd $EXAMPLE_DIR
./host/host ./enclave/enclave.signed cold-init $EXAMPLE_DIR/app1_data --simulate
./host/host ./enclave/enclave.signed get-certifier $EXAMPLE_DIR/app1_data --simulate
```

On the server's terminal, run 
```bash
cd $EXAMPLE_DIR
./host/host ./enclave/enclave.signed cold-init $EXAMPLE_DIR/app2_data --simulate
./host/host ./enclave/enclave.signed get-certifier $EXAMPLE_DIR/app2_data/ --simulate
```

Step 11:  Run the apps to test trusted services

Run the data analytics server as 
```bash
cd $EXAMPLE_DIR
./host/host ./enclave/enclave.signed run-app-as-server $EXAMPLE_DIR/app1_data --simulate
```
Run the data analytics client as 
```bash
cd $EXAMPLE_DIR
./host/host ./enclave/enclave.signed run-app-as-client $EXAMPLE_DIR/app1_data --simulate
```
You should be able to see the server process the dataset provided by the client. 

