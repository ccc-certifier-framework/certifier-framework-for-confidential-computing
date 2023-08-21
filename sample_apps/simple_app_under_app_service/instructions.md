# Simple App Under Application Service - Instructions

This document gives detailed instructions for building and running the sample
application under the Application Service.

The example app shows all the major steps in a Confidential Computing Program,
running under an Application Service.

This uses a nearly identical version of the [simple_app](../simple_app/)
application but running under the Application Service.

These steps are made much simpler by the Certifier API as shown below.

As with the simple_app, the instructions are detailed
and generally similar except for the Application-Service features.  These
include starting the application by sending a mesage to the Application
Service to start the program and actually running such a service.  This
is demonstrated in the [application_service](../../application_service/)
directory where the application_service is built. This message can come
from any program including a utility program called `send_request` in the
Application Service directory.

There are **almost no changes** for the simple_example program to work with
the Application Service. Basically the only difference is a call to a
different initialization function at program startup.  As a result, the
application code is nearly identical with that of the simple_example.

Service calls are made between a parent (the Application Service in SEV-VM
level enclave, for example) and the application via pipes. However, the
Certifier Framework handles all this without program changes.

This example runs under the simulated-enclave right now but we'll port it
to running under SEV-SNP.  For this example, we let the policy key for the
Application Service be the same as the policy key for the application.  This
will often, but not always, be the case.

## Multi-step process

This sample program requires setting up the Application Service, starting the
Certifier, followed by setting up the sample application.

The [run_example.sh](../run_example.sh) script packages these multiple steps
into simple interfaces, as below:

- Build-and-setup the Certifier and Application Service

  ```shell
  ./run_example.sh rm_non_git_files

  ./run_example.sh application_service setup
  ```

- Build-and-setup the sample application

  ```shell
  ./run_example.sh simple_app_under_app_service setup
  ```

- Start the required services

  In one terminal, start the Certifier Service, which is started as a background
  process. Tail the log file to see its activity:

  ```shell
  ./run_example.sh --no-cleanup application_service start_certifier_service
  ```

  Record the OS-pid of the Certifier Service started above.

  In another terminal, start the Application Service, which is also run as a background
  process:

  ```shell
  ./run_example.sh application_service start_application_service
  ```

   Once the Application Service has been certified, you can kill the Certifier Service
   started previously. The `--no-cleanup` flag prevents cleanup of the active
   Application Service process, which is needed by the sample app.

- Run the sample application

  ```shell
  ./run_example.sh simple_app_under_app_service run_test
  ```

  This `run_test` step packages these sub-steps:

  - Start a new Certifier Service for the sample app
  - Run app as a server and get certified by Certifier Service
  - Run app as a client and get certified by Certifier Service
  - Run app as a server offers trusted service
  - Run app as a client makes trusted request to app-as-a-server without contacting the Certifier Service

As in the simple_example, you should see the message "Hi from your secret server"
in the client terminal window and "Hi from your secret client".

If so, **Congratulations! Your first Confidential Computing program under the Application Service worked!**

To cleanup after a test run, do: `$ sudo ./cleanup.sh`

This will ensure that all active services and running processes are cleanly terminated.

----

# Detailed Instructions

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it, e.g., :

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

$SERVICE_EXAMPLE_DIR is this directory containing the example application.
Again, a shell variable is useful.

```shell
export SERVICE_EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_app_service
```

$APP_SERVICE_DIR is the Application Service

```shell
export APP_SERVICE_DIR=$CERTIFIER_PROTOTYPE/application_service
```

----
## Step 1: Build the utilities

```shell
cd $CERTIFIER_PROTOTYPE/utilities

make -f cert_utility.mak
make -f policy_utilities.mak
```


## Step 2:  Create a directory for the provisioning files
```shell
mkdir $SERVICE_EXAMPLE_DIR/provisioning
```


## Step 3: Generate the policy key and self-signed certificate
```shell
cd $SERVICE_EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe             \
        --operation=generate-policy-key-and-test-keys       \
        --policy_key_output_file=policy_key_file.bin        \
        --policy_cert_output_file=policy_cert_file.bin      \
        --platform_key_output_file=platform_key_file.bin    \
        --attest_key_output_file=attest_key_file.bin
```

## Step 4: Embed the policy key in example_app
```shell
cd $SERVICE_EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe     \
        --input=policy_cert_file.bin                    \
        --output=../policy_key.cc
```

## Step 5: Compile example_app with the embedded policy_key
```shell
cd $SERVICE_EXAMPLE_DIR

make -f example_app.mak
```


## Step 6: Obtain the measurement of the trusted application for this security domain

```shell
cd $SERVICE_EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/measurement_utility.exe  \
        --type=hash                                     \
        --input=../example_app.exe                      \
        --output=example_app.measurement
```


## Step 7: Author the policy for the security domain and produce the signed claims the apps need

```shell
cd $SERVICE_EXAMPLE_DIR/provisioning

```

### a. Construct statement "policy-key says the policy-key is-trusted-for-attestation"

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=policy_key_file.bin                   \
        --verb="is-trusted-for-attestation"                 \
        --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts1.bin                                        \
        --output=vse_policy1.bin
```

### b. Construct statement "policy-key says example_app-measurement is-trusted"

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=""                                    \
        --measurement_subject=example_app.measurement       \
        --verb="is-trusted"                                 \
        --output=ts2.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts2.bin                                        \
        --output=vse_policy2.bin
```

### c. Produce the signed claims for each vse policy statement.
```shell
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy1.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_1.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy2.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_2.bin
```

### d. Combine signed policy statements for Certifier Service use.
```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe       \
        --input=signed_claim_1.bin,signed_claim_2.bin   \
        --output=policy.bin
```

### e. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```

### f. This is just an example. This rule will be supplied by the Application Service

Construct statement "platform-key says attestation-key is-trusted-for-attestation" and sign it

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=attest_key_file.bin                   \
        --verb="is-trusted-for-attestation"                 \
        --output=tsc1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=platform_key_file.bin                     \
        --verb="says"                                           \
        --clause=tsc1.bin                                       \
        --output=vse_policy3.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy3.bin                                      \
        --duration=9000                                                 \
        --private_key_file=platform_key_file.bin                        \
        --output=platform_attest_endorsement.bin
```

### g. [optional] Print it
```shell
$CERTIFIER_PROTOTYPE/utilities/print_signed_claim.exe --input=platform_attest_endorsement.bin
```

Step (a) may seem redundant but first, it allows us to use the same Validation
as for simple_app and preserves the option that there will be an intermediate
key that signs the Application Service's delegation rule.


## Step 8: Build SimpleServer

You should have gotten the protobuf compiler (protoc) for Go when you got Go.
If not:
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
cd $CERTIFIER_PROTOTYPE/oelib

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

Now build simpeserver:

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service

go build simpleserver.go
```


## Step  9: Create directories for app data
```shell
cd $SERVICE_EXAMPLE_DIR

mkdir app1_data app2_data
```


## Step 10: Create a directory for service data
```shell
mkdir $SERVICE_EXAMPLE_DIR/service
```


## Step 11: Provision the app files for the app

Note: These files are required for the "simulated-enclave" which cannot measure the
example app and needs a provisioned attestation key and platform certificate.
On real hardware, these are not needed.

```shell
cd $SERVICE_EXAMPLE_DIR/provisioning

cp -p ./* $SERVICE_EXAMPLE_DIR/app1_data
cp -p ./* $SERVICE_EXAMPLE_DIR/app2_data
```


## Step 12: Provision the service files
```shell
cd $SERVICE_EXAMPLE_DIR/provisioning

cp -p policy_key_file.bin policy_cert_file.bin policy.bin $SERVICE_EXAMPLE_DIR/service
```


## Step 13: Build the Application Service and provision the service data for it
```shell
cd $APP_SERVICE_DIR
```

Follow the build and provisioning instructions in
[$APP_SERVICE_DIR/instructions.md](../../application_service/instructions.md) steps 4-9.


## Step 14: Start the Certifier Service for the Application Service built

In a new terminal window:

```shell
cd $APP_SERVICE_DIR/service

$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
        --policyFile=policy.bin                     \
        --readPolicy=true
```

## Step 15: In a new window, run the Application Service

Under the simulated enclave, run:

```shell
cd $APP_SERVICE_DIR/service

$APP_SERVICE_DIR/app_service.exe                                        \
      --policy_cert_file="policy_cert_file.bin"                         \
      --service_dir="./service/"                                        \
      --service_policy_store="policy_store"                             \
      --host_enclave_type="simulated-enclave"                           \
      --platform_file_name="platform_file.bin"                          \
      --platform_attest_endorsement="platform_attest_endorsement.bin"   \
      --attest_key_file="attest_key_file.bin"                           \
      --measurement_file="app_service.measurement"                      \
      --cold_init_service=true                                          \
      --guest_login_name="guest"
```

Under the SEV-SNP enclave, run:

```shell
cd $APP_SERVICE_DIR/service

$APP_SERVICE_DIR/app_service.exe                    \
      --policy_cert_file="policy_cert_file.bin"     \
      --service_dir="./service/"                    \
      --service_policy_store="policy_store"         \
      --host_enclave_type="sev-enclave"             \
      --cold_init_service=true                      \
      --guest_login_name="guest"
```

## Step 16: In a new window, run the Certifier Service for simple_app_under_app_service
```shell
cd $SERVICE_EXAMPLE_DIR/service

$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
        --policyFile=policy.bin                     \
        --readPolicy=true
```

## Step 17: Run simple_app_under_app_service for cold boot

In a new window, run simple_app_under_app_service for cold boot provisioning.
You need to do this through the start_program utility.

**Note:** As demonstrated in the `script`, you should use the full path name for files
and directories referenced by `start_program.exe` since they will run under a
directory that is different from the one you start `start_program.exe` in.

**Note:**
- If the parent enclave is the simulated enclave, add
  `--parent_enclave="simulated-enclave"`, to the commands below.
- If the parent enclave is the SEV-SNP, add `--parent_enclave="sev-enclave"`,
  to the commands below.  For that enclave, you can also remove
  `--measurement_file="example_app.measurement"`.

```shell
cd $SERVICE_EXAMPLE_DIR

$SERVICE_EXAMPLE_DIR/start_program.exe                              \
        --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe   \
        --args="--print_all=true,--operation=cold-init,--data_dir=./app1_data/,--measurement_file=example_app.measurement,--policy_store_file=policy_store"

$SERVICE_EXAMPLE_DIR/start_program.exe                              \
        --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe   \
        --args="--print_all=true,--operation=get-certified,--data_dir=./app1_data/,--measurement_file=example_app.measurement,--policy_store_file=policy_store"

$SERVICE_EXAMPLE_DIR/start_program.exe                              \
        --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe   \
        --args="--print_all=true,--operation=cold-init,--data_dir=./app2_data/,--measurement_file=example_app.measurement,--policy_store_file=policy_store"

$SERVICE_EXAMPLE_DIR/start_program.exe                              \
        --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe   \
        --args="--print_all=true,--operation=get-certified,--data_dir=./app2_data/,--measurement_file=example_app.measurement,--policy_store_file=policy_store"
```


At this point, both versions of the app have their admission certificates.  You can look at
the output of the terminal running simpleserver for output.  Now all we have to do is have
the apps connect to each other for the final test.  The Certifier Service is no longer needed
at this point.


## Step 18:  Run the apps to test trusted services
-----------------------------------------------

In the app-as-a-server terminal run the following:

```shell
cd $SERVICE_EXAMPLE_DIR

$SERVICE_EXAMPLE_DIR/start_program.exe                              \
        --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe   \
        --args="--print_all=true,--operation=run-app-as-server,--data_dir=./app2_data/,--policy_cert_file=policy_cert_file.bin,--policy_store_file=policy_store"
```

In the app-as-a-client terminal run the following:

```shell
cd $SERVICE_EXAMPLE_DIR

$SERVICE_EXAMPLE_DIR/start_program.exe                              \
        --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe   \
        --args="--print_all=true,--operation=run-app-as-client,--data_dir=./app1_data/,--policy_cert_file=policy_cert_file.bin,--policy_store_file=policy_store"
```


As in simple_example, you should see the message "Hi from your secret server"
in the client terminal window and "Hi from your secret client".

If so, **Congratulations! Your first Confidential Computing program under the Application Service worked!**

