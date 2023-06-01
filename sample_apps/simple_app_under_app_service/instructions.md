Instructions for building and running the sample application under the
                        application service
======================================================================


This uses the same application as in .../sample_app but running under the
application service.  The app itself is almost identical with the original.
This example runs under the simulated-enclave right now but we'll port it
to running under sev-snp.  For this example, we let the policy key for the
application service be the same as the policy key for the application.  This
will often, but not always, be the case.


Set up some name shortcuts 

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.  On my
computer, it is in =~/src/github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing.
It is helpful to have a shell variable for it:
export CERTIFIER_PROTOTYPE=~/src/github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing

$SERVICE_EXAMPLE_DIR is this directory containing the example application.  Again, a shell variable
is useful.
export SERVICE_EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_app_service

$APP_SERVICE_DIR is the application service
export APP_SERVICE_DIR=$CERTIFIER_PROTOTYPE/application_service

Much of this is the same as the original simple_app


Step 1: Build the utilities.

    cd $CERTIFIER_PROTOTYPE
    cd utilities
    make -f cert_utility.mak
    make -f policy_utilities.mak


Step 2:  Create a directory for the provisioning files
    mkdir $SERVICE_EXAMPLE_DIR/provisioning


Step 3: Generate the policy key and self-signed cert
    cd $SERVICE_EXAMPLE_DIR/provisioning
    $CERTIFIER_PROTOTYPE/utilities/cert_utility.exe --operation=generate-policy-key-and-test-keys \
    --policy_key_output_file=policy_key_file.bin --policy_cert_output_file=policy_cert_file.bin \
    --platform_key_output_file=platform_key_file.bin --attest_key_output_file=attest_key_file.bin


Step 4: Embed the policy key in example_app.
    cd $SERVICE_EXAMPLE_DIR/provisioning
    $CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe --input=policy_cert_file.bin --output=../policy_key.cc


Step 5: Compile example_app with the embedded policy_key
    cd $SERVICE_EXAMPLE_DIR
    make -f example_app.mak


Step 6: Obtain the measurement of the trusted application for ths security domain.
    cd $SERVICE_EXAMPLE_DIR/provisioning
    $CERTIFIER_PROTOTYPE/utilities/measurement_utility.exe --type=hash --input=../example_app.exe \
      --output=example_app.measurement


Step 7: Author the policy for the security domain and produce the signed claims the apps need.
    cd $SERVICE_EXAMPLE_DIR/provisioning

    a. Construct statement "policy-key says the policy-key is-trusted-for-attestation"
       $CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --key_subject=policy_key_file.bin \
          --verb="is-trusted-for-attestation" --output=ts1.bin
       $CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe --key_subject=policy_key_file.bin \
          --verb="says" --clause=ts1.bin --output=vse_policy1.bin

    b. Construct statement "policy-key says example_app-measurement is-trusted"
       $CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --key_subject="" \
          --measurement_subject=example_app.measurement --verb="is-trusted" \
          --output=ts2.bin
       $CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe --key_subject=policy_key_file.bin \
          --verb="says" --clause=ts2.bin --output=vse_policy2.bin

    c. Produce the signed claims for each vse policy statement.
       $CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe \
          --vse_file=vse_policy1.bin --duration=9000 \
          --private_key_file=policy_key_file.bin --output=signed_claim_1.bin
       $CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe --vse_file=vse_policy1.bin \
          --duration=9000 --private_key_file=policy_key_file.bin --output=signed_claim_1.bin

    d. Combine signed policy statements for Certifier Service use.
       $CERTIFIER_PROTOTYPE/utilities/package_claims.exe --input=signed_claim_1.bin,signed_claim_2.bin\
          --output=policy.bin

    e. [optional] Print the policy
       $CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin

    f. This is just an example.  This rule will be supplied by the application_service.
       Construct statement "platform-key says attestation-key is-trusted-for-attestation" and sign it
       $CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --key_subject=attest_key_file.bin \
          --verb="is-trusted-for-attestation" --output=tsc1.bin
       $CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe --key_subject=platform_key_file.bin \
          --verb="says" --clause=tsc1.bin --output=vse_policy3.bin
       $CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe --vse_file=vse_policy3.bin \
          --duration=9000 --private_key_file=platform_key_file.bin \
          --output=platform_attest_endorsement.bin

    g. [optional] Print it
       $CERTIFIER_PROTOTYPE/utilities/print_signed_claim.exe --input=platform_attest_endorsement.bin

Step a may seem redundant but first, it allows us to use the same Validation as for simple_app and
preserves the option that there will be an intermediate key that signs the application service's
delegation rule.


Step 8: Build SimpleServer:
  You should have gotten the protobuf compiler (protoc) for go when you got go.
  If not:
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
  Compile the protobuf
    cd $CERTIFIER_PROTOTYPE
    cd certifier_service/certprotos
    protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
  Compile the oelib for OE host verification
    cd $CERTIFIER_PROTOTYPE
    cd certifier_service/oelib
    make
  If you do not have OE SDK installed or do not want to enable OE:
    make dummy

  This should produce a go file for the certifier protobufs called certifier.pb.go in certprotos.
  Now build simpeserver:
    cd $CERTIFIER_PROTOTYPE/certifier_service
    go build simpleserver.go


Step  9: Create directories for app data
    cd $SERVICE_EXAMPLE_DIR
    mkdir app1_data app2_data


Step 10: Create a directory for service data
    mkdir $SERVICE_EXAMPLE_DIR/service


Step 11: Provision the app files for the app
    Note: These files are required for the "simulated-enclave" which cannot measure the
    example app and needs a provisioned attestation key and platform cert.  On real
    hardware, these are not needed.

    cd $SERVICE_EXAMPLE_DIR/provisioning
    cp ./* $SERVICE_EXAMPLE_DIR/app1_data
    cp ./* $SERVICE_EXAMPLE_DIR/app2_data


Step 12: Provision the service files
    cd $SERVICE_EXAMPLE_DIR/provisioning
    cp policy_key_file.bin policy_cert_file.bin policy.bin $SERVICE_EXAMPLE_DIR/service


Step 13: Build the Application Service and provision the service data for it
    cd $APP_SERVICE_DIR
    Follow the build and provisioning instructions in
    $APP_SERVICE_DIR/instructions.txt steps 4-9.


Step 14: Start the Certifier Service for the built application service
  In a new terminal window:
    cd $APP_SERVICE_DIR/service
    $CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
      --policyFile=policy.bin --readPolicy=true


Step 15: In a new window, run the application service

Under the simulated enclave:
    cd $APP_SERVICE_DIR/service
    $APP_SERVICE_DIR/app_service.exe \
      --policy_cert_file="policy_cert_file.bin" \
      --service_dir="./service/" \
      --service_policy_store="policy_store" \
      --host_enclave_type="simulated-enclave" \
      --platform_file_name="platform_file.bin" \
      --platform_attest_endorsement="platform_attest_endorsement.bin" \
      --attest_key_file="attest_key_file.bin" \
      --measurement_file="app_service.measurement" \
      --cold_init_service=true \
      --guest_login_name="guest"

Under the sev enclave:
    cd $APP_SERVICE_DIR/service
    $APP_SERVICE_DIR/app_service.exe \
      --policy_cert_file="policy_cert_file.bin" \
      --service_dir="./service/" \
      --service_policy_store="policy_store" \
      --host_enclave_type="sev-enclave" \
      --cold_init_service=true \
      --guest_login_name="guest"


Step 16: In a new window, run the Certifier Service for simple_app_under_app_service
    cd $SERVICE_EXAMPLE_DIR/service
    $CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
      --policyFile=policy.bin --readPolicy=true


Step 17: In a new window, run simple_app_under_app_service for cold boot
         provisioning, you need to do this through the start_program utility.  Note:
         as demonstrated in the script, you should use the full path name for files
         and directories referenced by start_program.exe since they will run under a
         directory that is differenc from the one you start start_program.exe in.

Note:
  If the parent enclave is the simulated enclave, add --parent_enclave="simulated-enclave", to the commands below.
  If the parent enclave is the sev, add --parent_enclave="sev-enclave", to the commands below.  For that
  enclave, you can also remove --measurement_file="service_example_app.measurement".

    cd $SERVICE_EXAMPLE_DIR
    $SERVICE_EXAMPLE_DIR/start_program.exe --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe \
      --args= "--print_all=true,--operation=cold-init,--data_dir=./app1_data/,--measurement_file="service_example_app.measurement", --policy_store_file=policy_store"

    $SERVICE_EXAMPLE_DIR/start_program.exe --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe \
      --args= "--print_all=true,--operation=get-certifier,--data_dir=./app1_data/,--measurement_file="service_example_app.measurement", --policy_store_file=policy_store"

    $SERVICE_EXAMPLE_DIR/start_program.exe --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe \
      --args= "--print_all=true,--operation=cold-init,--data_dir=./app2_data/,--measurement_file="service_example_app.measurement", --policy_store_file=policy_store"

    $SERVICE_EXAMPLE_DIR/start_program.exe --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe \
      --args= "--print_all=true,--operation=get-certifier,--data_dir=./app2_data/,--measurement_file="service_example_app.measurement", --policy_store_file=policy_store"


At this point, both versions of the app have their admission certificates.  You can look at
the output of the terminal running simpleserver for output.  Now all we have to do is have
the apps connect to each other for the final test.  The Certifier Service is no longer needed
at this point.


Step 18:  Run the apps to test trusted services
-----------------------------------------------

In app as a server terminal run the following:
    cd $SERVICE_EXAMPLE_DIR
    $SERVICE_EXAMPLE_DIR/start_program.exe --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe \
    --args="--print_all=true,--operation=run-app-as-server,--data_dir=./app2_data/,--policy_cert_file=policy_cert_file.bin,--policy_store_file=policy_store"

In app as a client terminal run the following:
    cd $SERVICE_EXAMPLE_DIR
    $SERVICE_EXAMPLE_DIR/start_program.exe --executable=$SERVICE_EXAMPLE_DIR/service_example_app.exe \
    --args="--print_all=true,--operation=run-app-as-client,--data_dir=./app1_data/,--policy_cert_file=policy_cert_file.bin,--policy_store_file=policy_store"


As in simple_example, you should see the message "Hi from your secret server"
in the client terminal window and "Hi from your secret client".
If so, your first Confidential Computing program under the application service worked!

