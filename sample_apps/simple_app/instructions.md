# Simple App - Instructions

This document gives detailed instructions for building and running the sample
application and generating the policy for the Certifier Service using the policy
utilities.

This simple_app sample program provides an example of initializing
and provisioning the Certifier Service with utility-generated keys,
measurements and policy.

The sample program will still need to construct the statement "The attestation-key says the
enclave-key speaks-for the program".  This is the attestation.

Except for the ancillary files `attest_key_file.bin`, `example_app.measurement` and
`platform_attest_endorsement.bin` which are needed because of the simulated-enclave,
this example closely models the steps needed for a real (but simple) deployment. In addition,
this example embeds the policy key in the application using `embed_policy_key.exe`.

Read the [policy_key_notes.txt](policy_key_notes.txt) in the `simple_app` directory and
[policy_utilities_info.txt](../../utilities/policy_utilities_info.txt) as  a background.

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it, e.g., :

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a shell variable
is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app
```

## Workflow

Here is a pictorial depiction of the overall workflow you need to follow to build
and execute this simple app.

###  Build Workflow
```mermaid
%%{init: {'theme':'forest'}}%%
flowchart TB

  subgraph 1.3 Build Policy Generator
  direction TB
    id3(make -f policy_generator.mak) --> id31([policy_generator.exe])
  end

  subgraph 1.2 Build Policy Utilities
  direction LR
    id2(make -f policy_utilities.mak) --> id21([combine_properties.exe])
    id2(make -f policy_utilities.mak) --> id22([embed_policy_key.exe])
    id2(make -f policy_utilities.mak) --> id23([make_environment.exe])
    id2(make -f policy_utilities.mak) --> id24([make_indirect_vse_clause.exe.exe])
    id2(make -f policy_utilities.mak) --> id25([make_platform.exe.exe])
    id2(make -f policy_utilities.mak) --> id26([make_property.exe.exe])
    id2(make -f policy_utilities.mak) --> id27([make_signed_claim_from_vse_clause.exe.exe])
    id2(make -f policy_utilities.mak) --> id28([make_simple_vse_clause.exe.exe])
    id2(make -f policy_utilities.mak) --> id29([make_unary_vse_clause.exe.exe])
    id2(make -f policy_utilities.mak) --> id210([measurement_utility.exe.exe])
    id2(make -f policy_utilities.mak) --> id211([package_claims.exe])
    id2(make -f policy_utilities.mak) --> id212([print_packaged_claims.exe])
    id2(make -f policy_utilities.mak) --> id213([print_signed_claim.exe])
    id2(make -f policy_utilities.mak) --> id214([print_vse_clause.exe])
    id2(make -f policy_utilities.mak) --> id215([sample_sev_key_generation.exe])
    id2(make -f policy_utilities.mak) --> id216([simulated_sev_attest.exe])
    id2(make -f policy_utilities.mak) --> id217([simulated_sev_key_generation.exe])
  end

  subgraph 1.1 Build Certificate-related Utilities
  direction TB
    id1(make -f cert_utility.mak) --> id11([cert_utility.exe])
    id1(make -f cert_utility.mak) --> id12([measurement_init.exe])
    id1(make -f cert_utility.mak) --> id13([key_utility.exe])
  end

```

----

###  Policy & Certificate Generation Workflow
```mermaid
 flowchart TB
    subgraph sg3 [3. Generate the policy key and self-signed certificate]
      direction TB
      id12(cert_utility.exe) --> id31{{"--operation=generate-policy-key-and-test-keys"}}
      id31 -- "--policy_key_output_file"   --> id32(policy_key_file.bin)
      id31 -- "--policy_cert_output_file"  --> id33(policy_cert_file.bin)
      id31 -- "--platform_key_output_file" --> id34(platform_key_file.bin)
      id31 -- "--attest_key_output_file"   --> id35(attest_key_file.bin)
    end

    subgraph sg4 [4. Embed policy key]
      direction LR
      id33(policy_cert_file.bin) -- "--input" --> embed_policy_key.exe
      embed_policy_key.exe -- "--output" --> id41([../policy_key.cc, linked with example_app.cc])
    end

    subgraph sg5 [5. Compile example_app]
      direction LR
      id41([../policy_key.cc]) -- "#include" --> example_app.cc
      example_app.cc -- "make -f example.mak" --> example_app.exe
    end

    subgraph shg6 [6. Measure trusted application]
      direction LR
      example_app.exe -- "--input" --> id6.1[measurement_utility.exe --type=hash]
      id6.1 -- "--output" --> id6o(example_app.measurement)
    end

    subgraph shg7a1 [7a.1. Construct Policy Key]
      direction LR
      id34 --> id7a1_1(make_unary_vse_clause.exe)
      id7a1_1 -- "--key_subject=platform_key_file.bin\n-verb='is-trusted-for-attestation'\n--output=" --> 7a1_o(ts1.bin)
    end

    subgraph shg7a2 [7a.2. Construct Policy Key\n]
      direction LR
      id32 --> id7a2_exe(make_indirect_vse_clause.exe)
      7a1_o -- "--clause=ts1.bin" --> id7a2_exe
      id7a2_exe -- "--key_subject=policy_key_file.bin\n--clause=ts1.bin\n--verb='says'\n--output=" --> id7a2_o(vse_policy1.bin)
    end

    subgraph shg7b1 [7b.1. Construct Policy Key\n]
      direction LR
      id6o --> id7b1_exe(make_indirect_vse_clause.exe)
      id7b1_exe -- "--measurement_subject=example_app.measurement\n--verb='is_trusted'\n--output=" --> id7b1_o(ts2.bin)
    end

    subgraph shg7b2 [7b.2. Construct Policy Key\n]
      direction LR
      id7b1_o --> id7b2_exe(make_indirect_vse_clause.exe)
      id32 --> id7b2_exe
      id7b2_exe -- "--key_subject=policy_key_file.bin\n--verb='says'\n--clause='ts2.bin'\n--output=" --> id7b2_o(vse_policy2.bin)

    end

  subgraph sg7c1 [7c.1 Produce signed claims: For each VSE policy statement]
    direction LR
    id7a2_o --> id7c1_exe(make_signed_claim_from_vse_clause.exe)
    id32    --> id7c1_exe
    id7c1_exe -- "--duration=9000\n--vse_file=vse_policy1.bin\n--private_key_file=policy_key_file.bin\n--output=" --> id7c1_o1(signed_claim_1.bin)

    id7b2_o --> id7c1_exe
    id7c1_exe -- "--duration=9000\n--vse_file=vse_policy2.bin\n--private_key_file=policy_key_file.bin\n--output=" --> id7c1_o2(signed_claim_2.bin)
  end

  subgraph sg7d [7d. Combine signed claims]
    direction LR
    id7c1_o1 --> id7d_exe(package_claims.exe)
    id7c1_o2 --> id7d_exe
    id7d_exe -- "--input=signed_claim(s)\n--output=" --> id7d_o(policy.bin)
  end

  subgraph sg7e [7e. Print the policy]
    id7d_o --> id7d_exe2(print_packaged_claims.exe)
    id7d_exe2 -- "--input=policy.bin" --> id7e_op>Policy print output]
  end

  subgraph sg7f1 [7f.1 Construct statement and sign it]
    direction LR
    id35      --> id7f1_exe(make_unary_vse_clause.exe)
    id7f1_exe -- "--key_subject=attest_key_file.bin\n--verb='is-trusted-for-attestation'\n--output=" --> id7f1_o(tsc1.bin)
  end

  subgraph sg7f2 [7f.2 Construct statement and sign it]
    direction LR
    id34 --> id7f2_exe(make_indirect_vse_clause.exe)
    id7f1_o --> id7f2_exe
    id7f2_exe -- "--key_subject=platform_key_file.bin\n--verb='says'\n--clause=tsc1.bin\n--output=" --> id7f2_o(vse_policy3.bin)
  end

  subgraph sg7f3 [7f.3 Construct statement and sign it]
    direction LR
    id7f2_o --> id7f3_exe(make_signed_claim_from_vse_clause.exe)
    id34 --> id7f3_exe
    id7f3_exe -- "--duration=9000\n--vse_file=vse_policy3.bin\n--private_key_file=platform_key_file.bin\n--output=" --> id7f3_o(platform_attest_endorsement.bin)
  end

  subgraph sg7g [7g. Print platform endorsement]
    direction LR
    id7f3_o --> id7g_exe(print_signed_claim.exe)
    id7g_exe -- "--input=platform_attest_endorsement.bin" --> id7g_op>Platform attestation output]
  end

```

----

### Run the apps and get admission certificates from Certifier Service
``` mermaid
  %%{init: { 'sequence': {'mirrorActors':false} } }%%
sequenceDiagram
  autonumber
  actor client as example_app-as-a-client
  actor CS as Certifier Service
  actor server as example_app-as-a-server

  client -->> CS : cold_init<br/>--measurement_file="example_app.measurement"
  client -->> CS : get_certified<br/>--measurement_file="example_app.measurement"

  server -->> CS : cold_init<br/>--measurement_file="example_app.measurement"
  server -->> CS : get_certified<br/>--measurement_file="example_app.measurement"

```

----

###  Connect the client/server apps (without Certifier Service)
``` mermaid
sequenceDiagram
  autonumber
  actor client as example_app-as-a-client
  actor server as example_app-as-a-server

  client -->> server : open-secure-channel
  client -->> server : "Hi from your secret client"
  server -->> client : "Hi from your secret server"

```

----
## Step 1: Build the utilities

```shell
cd $CERTIFIER_PROTOTYPE/utilities
make -f cert_utility.mak
make -f policy_utilities.mak
```

## Step 2:  Create a directory for provisioning the files
```shell
mkdir $EXAMPLE_DIR/provisioning
```


## Step 3: Generate the policy key and self-signed certificate

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe          \
      --operation=generate-policy-key-and-test-keys      \
      --policy_key_output_file=policy_key_file.bin       \
      --policy_cert_output_file=policy_cert_file.bin     \
      --platform_key_output_file=platform_key_file.bin   \
      --attest_key_output_file=attest_key_file.bin
  ```

This will also generate the attestation key and platform key for these tests.

## Step 4: Embed the policy key in example_app
```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe      \
      --input=policy_cert_file.bin                       \
      --output=../policy_key.cc
```

## Step 5: Compile example_app with the embedded policy_key

```shell
cd $EXAMPLE_DIR

make -f example_app.mak
```

## Step 6: Obtain the measurement of the trusted application for this security domain.
```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/measurement_utility.exe      \
        --type=hash                                         \
        --input=../example_app.exe                          \
        --output=example_app.measurement
```

## Step 7: Author the policy for the security domain and produce the signed claims the apps need

```shell
cd $EXAMPLE_DIR/provisioning
```

### a. Construct policyKey says platformKey is-trusted-for-attestation

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
      --key_subject=platform_key_file.bin                   \
      --verb="is-trusted-for-attestation"                   \
      --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe    \
      --key_subject=policy_key_file.bin                        \
      --verb="says"                                            \
      --clause=ts1.bin                                         \
      --output=vse_policy1.bin
```

### b. Construct  policy key says measurement is-trusted

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
      --key_subject=""                                      \
      --measurement_subject=example_app.measurement         \
      --verb="is-trusted"                                   \
      --output=ts2.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe    \
      --key_subject=policy_key_file.bin                        \
      --verb="says"                                            \
      --clause=ts2.bin                                         \
      --output=vse_policy2.bin
```

### c. Produce the signed claims for each vse policy statement.
```shell
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file=vse_policy1.bin                                        \
      --duration=9000                                                   \
      --private_key_file=policy_key_file.bin                            \
      --output=signed_claim_1.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file=vse_policy2.bin                                        \
      --duration=9000                                                   \
      --private_key_file=policy_key_file.bin                            \
      --output=signed_claim_2.bin
```

### d. Combine signed policy statements for Certifier Service use

```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe     \
      --input=signed_claim_1.bin,signed_claim_2.bin   \
      --output=policy.bin
```

### e. [optional] Print the policy

```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```

### f. Construct statement "platform-key says attestation-key is-trusted-for-attestation" and sign it

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
      --key_subject=attest_key_file.bin                     \
      --verb="is-trusted-for-attestation"                   \
      --output=tsc1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe    \
      --key_subject=platform_key_file.bin                      \
      --verb="says"                                            \
      --clause=tsc1.bin                                        \
      --output=vse_policy3.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file=vse_policy3.bin                                        \
      --duration=9000                                                   \
      --private_key_file=platform_key_file.bin                          \
      --output=platform_attest_endorsement.bin
```

### g. [optional] Print it

```shell
$CERTIFIER_PROTOTYPE/utilities/print_signed_claim.exe --input=platform_attest_endorsement.bin
```


## Step 8: Build SimpleServer

You should have gotten the protobuf compiler (protoc) for Go when you got Go.
If not, do:

```shell
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```
Compile the protobuf

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/certprotos

protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
```
  Compile the oelib for OE host verification

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/oelib

make
```

  If you do not have OE SDK installed or do not want to enable OE:
```shell
make dummy
```

  Compile the teelib for running the certifier service inside a TEE
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/teelib

make
```

This should produce a Go file for the certifier protobufs called certifier.pb.go in certprotos.
Now build simpleserver:

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service

go build simpleserver.go
```

## Step 9: Create directories for app data

```shell
cd $EXAMPLE_DIR

mkdir app1_data app2_data
```

## Step 10: Create a directory for service data

```shell
mkdir $EXAMPLE_DIR/service
```

## Step 11: Provision the app files

Note: These files are required for the "simulated-enclave" which cannot measure
the example app and needs a provisioned attestation key and platform certificate.
On real hardware, these are not needed.

```shell
cd $EXAMPLE_DIR/provisioning

cp -p ./* $EXAMPLE_DIR/app1_data
cp -p ./* $EXAMPLE_DIR/app2_data
```


## Step 12: Provision the service files
```shell
cd $EXAMPLE_DIR/provisioning

cp -p policy_key_file.bin policy_cert_file.bin policy.bin $EXAMPLE_DIR/service
```

## Step 13: Start the Certifier Service

In a new terminal window:

```shell
cd $EXAMPLE_DIR/service

$CERTIFIER_PROTOTYPE/certifier_service/simpleserver   \
      --policyFile=policy.bin                         \
      --readPolicy=true
```

## Step 14:  Run the apps and get admission certificates from Certifier Service
Open two new terminals (one for the example app running as a client and one for the
same example app running as a server):

In the app-as-a-client terminal run the following:

```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/example_app.exe                       \
      --data_dir=./app1_data/                      \
      --operation=cold-init                        \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store
      --print_all=true

$EXAMPLE_DIR/example_app.exe                       \
      --data_dir=./app1_data/                      \
      --operation=get-certified                    \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store             \
      --print_all=true
```

In the app-as-a-server terminal run the following:

```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/example_app.exe                       \
      --data_dir=./app2_data/                      \
      --operation=cold-init                        \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store
      --print_all=true

$EXAMPLE_DIR/example_app.exe                       \
      --data_dir=./app2_data/                      \
      --operation=get-certified                    \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store             \
      --print_all=true
```

At this point, both versions of the app have their admission certificates.  You can look at
the output of the terminal running simpleserver for output.  Now all we have to do is have
the apps connect to each other for the final test.  **The Certifier Service is no longer needed
at this point.**


## Step 15:  Run the apps to test trusted services

### a. In the app-as-a-server terminal run the following:

```shell

cd $EXAMPLE_DIR

$EXAMPLE_DIR/example_app.exe           \
      --data_dir=./app2_data/          \
      --operation=run-app-as-server    \
      --policy_store_file=policy_store \
      --print_all=true
```

### b. In the app-as-a-client terminal run the following:

```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/example_app.exe           \
      --data_dir=./app1_data/          \
      --operation=run-app-as-client    \
      --policy_store_file=policy_store \
      --print_all=true
```

You should see the message "Hi from your secret server" in the client terminal window and
"Hi from your secret client".

If so, **Congratulations! Your first Confidential Computing program worked!**

-------
## Notes on real deployment and measurements

simpleserver is complete enough to serve as a server for a security domain.  In practice,
unlike this example, there will be multiple trusted measurements and possibly multiple
approved platform keys.  To accomodate these, you will have to repeat steps 7(a) and 7(b)
for these, putting them in unique files and including them in the 7(c).

### There is also **support for logging**.

To enable it add the following calls to the simplserver invocation.

```shell
    --enableLog=true
    --logDir="<dir-name>"       # the directory name where you want your log files
    --logFile="<log-file-name>" # the log file name for the log
```

You can change the starting log file sequence number using: ```--loggingSequenceNumber=3141 ```

### Platform-specific tools

As part of program measurement, each platform has a tool that takes an application
and produces a measurement which is used to construct the policy.

* The utility `measurement_utility.exe` does this in step 6 above for the simulated enclave.
* For SEV, you can obtain the corresponding tool from https://github.com/AMDESE/sev-tool.
* When Open Enclaves is used for SGX development, the oesign tool should be used.  This
can be obtained from https://github.com/openenclave/openenclave/tree/master/tools/oesign.
* These tools both produce a file containing the binary measurement which should
be used in step 7(a), above.

* For the Intel tool, see
https://github.com/intel/linux-sgx/blob/master/sdk/sign_tool/SignTool/sign_tool.cpp


-----
## Below are commands for general testing:

Other commands that can be run in the app-as-a-client terminal.

The operations are: _cold-init_, _get-certified_ and _run-app-as-client_.

**NOTE: --data_dir=./app1_data/** in these examples.

```shell
./example_app.exe                               \
      --data_dir=./app1_data/                   \
      --operation=cold-init                     \
      --policy_cert_file=policy_cert_file.bin   \
      --policy_store_file=policy_store          \
      --print_all=true

./example_app.exe                               \
      --data_dir=./app1_data/                   \
      --operation=get-certified                 \
      --policy_cert_file=policy_cert_file.bin   \
      --policy_store_file=policy_store          \
      --print_all=true

./example_app.exe                               \
      --data_dir=./app1_data/                   \
      --operation=run-app-as-client             \
      --policy_cert_file=policy_cert_file.bin   \
      --policy_store_file=policy_store          \
      --print_all=true
```
Similar sequence of commands can be run in the app-as-a-server terminal, with the final command being _run-app-as-server_ in this case:

**NOTE: --data_dir=./app2_data/** in these examples.

```shell
./```

### b. Produce the signed claims for each vse policy statement.
```shell

example_app.exe                                 \
      --data_dir=./app2_data/                   \
      --operation=cold-init                     \
      --policy_cert_file=policy_cert_file.bin   \
      --policy_store_file=policy_store          \
      --print_all=true

./example_app.exe                               \
      --data_dir=./app2_data/                   \
      --operation=get-certified                 \
      --policy_cert_file=policy_cert_file.bin   \
      --policy_store_file=policy_store          \
      --print_all=true

./example_app.exe                               \
      --data_dir=./app2_data/                   \
      --operation=run-app-as-server             \
      --policy_cert_file=policy_cert_file.bin   \
      --policy_store_file=policy_store          \
      --print_all=true
```

## Go setup

```shell
export GOPATH=$HOME
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
export GO111MODULE=off
go mod init
go mod tidy
go mod init certifier.pb.go
```

