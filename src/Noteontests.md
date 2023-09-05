In order for the sev certifier tests to work, you must first follow the instructions
in sec-snp-simulator which includes insmoding the simulated sev device.
You must also copy some test file into test_data including a policy key,
valid sev certificates and two files, ec-secp384r1-priv-key.pem and ec-secp384r1-pub-key.pem
into src.  See instructions.txt in sev-snp-simulator for building the simulated
sev environment.  You must also run the tests as root.  Finally, you must also
initialize platform policy that is cognizant of the attestation values initialized
in sec-snp-simulator.  This is done in the shell script: sev_policy_script.sh.

To run the full tests including the sev platform policy tests, use the command:
  ./certifier_tests.exe --policy_file_name=./test_data/policy.bin \
  --policy_key_file_name=./test_data/policy_key_file.bin \
  --ark_key_file_name=./test_data/policy_ark_file.bin \
  --ask_key_file_name=./test_data/policy_ask_file.bin \
  --vcek_key_file_name=./test_data/policy_vcek_file.bin \
  --ark_cert_file_name=./test_data/ark.der \
  --ask_cert_file_name=./test_data/ask.der \
  --vcek_cert_file_name=./test_data/vcek.der --print_all=true
If these variables are not set, it will skip some sev tests.  The sev tests only
work on Linux.

We've added an additional test for secure channel called test_channel.exe.  To use it,
you should init some keys in the test_data subdirectory just as in simple_apps.
Either change the calls below or rename:
  1. the policy cert file policy_cert_file.bin
  2. the policy_key file policy_key_file.bin
  3. the attestation key file auth_key_file.bin


In one window, type

  ./test_channel.exe --data_dir=./test_dir/ --operation=server --policy_cert_file=policy_cert_file.bin \
    --policy_key_file=policy_key_file.bin --auth_key_file=auth_key_file.bin

in another

  ./test_channel.exe --data_dir=./test_dir/ --operation=client --policy_cert_file=policy_cert_file.bin \
    --policy_key_file=policy_key_file.bin --auth_key_file=auth_key_file.bin

You should see the familiar "Hi from your secret client" and "Hi from your secret server."
Using the support tested, you no longer need to understand TLS and talking to a "trusted"
enclave involves only a couple of initialization calls.


