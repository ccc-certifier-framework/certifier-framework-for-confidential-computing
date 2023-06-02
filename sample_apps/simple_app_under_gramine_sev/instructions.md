# Simple App between AMD Secure Encrypted Virtualization (SEV) and Gramine SGX

This document gives [detailed instructions](#Steps-to-generate-policies-for-both-applications) for
building and running the sample applications communicating with each other on
different hardware platforms (i.e., between AMD-SEV and Gramine SGX).

The work instructions in this document assume that you have enabled both the
[simple_app_under_sev](../simple_app_under_sev/sev_example_app.cc) and the
[simple_app_under_gramine](../simple_app_under_gramine/gramine_example_app.cc).
If not, follow the detailed instructions in those directories first to verify
that both applications are running correctly on your SEV-SNP and SGX platforms.

-------------------------------------------------------------------------
# Steps to generate policies for both applications

To allow an SEV-SNP application to talk to a Gramine application, they need to
be in the same policy domain. Do do this, we need to unify the policy key
generation and policy authoring steps of the two applications.

Set $CERTIFIER_PROTOTYPE and $EXAMPLE_DIR environment variables:

```shell
export CERTIFIER_PROTOTYPE=~/certifier-framework-for-confidential-computing
```

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_gramine_sev
```

## Step 1: Create a directory for the provisioning files
``` shell
mkdir $EXAMPLE_DIR/provisioning
```

## Step 2: Copy all the platform certificates

Collect AMD-SEV and Intel SGX platform certificates you retrieved by following the individual examples:
``` shell
cd $EXAMPLE_DIR/provisioning
cp ../../simple_app_under_gramine/provisioning/sgx.cert.der .
cp ../../simple_app_under_sev/provisioning/ark_cert.der .
cp ../../simple_app_under_sev/provisioning/ask_cert.der .
cp ../../simple_app_under_sev/provisioning/vcek_cert.der .
```

## Step 3: Generate the policy key and self-signed certificate

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe     \
    --operation=generate-policy-key                 \
    --policy_key_output_file=policy_key_file.bin    \
    --policy_cert_output_file=policy_cert_file.bin  \
```

This will also generate the attestation key and platform key for these tests.

## Step 4: Embed the policy key in example_app.

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe \
      --input=policy_cert_file.bin                  \
      --output=../policy_key.cc
```

## Step 5: Compile both example applications and obtain measurements

Follow the AMD-SEV and Gramine example application instructions to compile the
example applications. However, instead of using their own policy_key.cc, replace
it with the one generated in Step 4.

After the applications are compiled, follow the instructions to retrieve the
measurement of each application.

## Step 6: Author the policy for the security domain and produce the signed claims the apps need.

Edit $EXAMPLE_DIR/policy.json and put both applications' measurements in the
measurement list. Run the Policy Generator to generate the policy:

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/policy_generator.exe                         \
        --policy_input=../policy.json                                       \
        --schema_input=$CERTIFIER_PROTOTYPE/utilities/policy_schema.json    \
        --util_path=$CERTIFIER_PROTOTYPE/utilities
```

## Step 7: Create directories for app data and service data
```shell
cd $EXAMPLE_DIR
mkdir app1_data app2_data service
```

## Step 8: Provision the app files

Note: These files are required for the "simulated-enclave" which cannot measure the
example app and needs a provisioned attestation key and platform certificate.  On real
hardware, these are not needed.

```shell
cd $EXAMPLE_DIR/provisioning
cp -p ./* $EXAMPLE_DIR/app1_data
cp -p ./* $EXAMPLE_DIR/app2_data
```


## Step 9: Provision the service files
```shell
cd $EXAMPLE_DIR/provisioning
cp -p policy_key_file.bin policy_cert_file.bin policy.bin $EXAMPLE_DIR/service
cp -p *.der $EXAMPLE_DIR/service
```

## Step 10: Start the Certifier Service
  In a new terminal window:
```shell
cd $EXAMPLE_DIR/service
$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
      --policyFile=policy.bin                       \
      --readPolicy=true                             \
      --host=<CERTIFIER_SERVICE_HOST_IP>
```

## Step 11:  Run the apps to test trusted services

Use the sev_example_app.exe and gramine_example_app you built following their
corresponding instructions. However, use the app files provisioned in Step 8
instead. In this example, we will use the Gramine application as the client and
the AMD-SEV application as the server:

In app-as-a-server terminal run the following:
```shell
cd $EXAMPLE_DIR

$SEV_EXAMPLE_DIR/sev_example_app.exe        \
        --data_dir=./app2_data/             \
        --operation=cold-init               \
        --policy_store_file=policy_store    \
        --print_all=true

$SEV_EXAMPLE_DIR/sev_example_app.exe        \
        --data_dir=./app2_data/             \
        --operation=get-certifier           \
        --policy_store_file=policy_store    \
        --print_all=true                    \
        --policy_host=<CERTIFIER_SERVICE_HOST_IP>

$SEV_EXAMPLE_DIR/sev_example_app.exe        \
        --data_dir=./app2_data/             \
        --operation=run-app-as-server       \
        --policy_store_file=policy_store    \
        --print_all=true                    \
        --server_app_host=<SEV_HOST_IP>
```

In app-as-a-client terminal run the following:
```shell
cd $EXAMPLE_DIR

gramine-sgx gramine_example_app         \
    --data_dir=./app1_data/             \
    --operation=cold-init               \
    --policy_store_file=policy_store    \
    --print_all=true

gramine-sgx gramine_example_app         \
    --data_dir=./app1_data/             \
    --operation=get-certifier           \
    --policy_store_file=policy_store    \
    --print_all=true                    \
    --policy_host=<CERTIFIER_SERVICE_HOST_IP>

gramine-sgx gramine_example_app         \
    --data_dir=./app1_data/             \
    --operation=run-app-as-client       \
    --policy_store_file=policy_store    \
    --print_all=true                    \
    --server_app_host=<SEV_HOST_IP>
```

You should see the message "Hi from your secret server" in the client terminal
window and "Hi from your secret client".

