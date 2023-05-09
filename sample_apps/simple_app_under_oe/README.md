# simple_app_under_oe/ - Simple App under Open Enclave - README

You can use the [sample_apps/run_example.sh](../run_example.sh) to build
and run the simple application under OE as follows:

- Build and test the simple app under OE:

```shell
cd certifier-framework-for-confidential-computing/sample_apps
./run_example.sh simple_app_under_oe
```
The build process requires access to Open-SSL libraries. The default path specified in
this driver script is `/usr/local/lib`. To override this, when executing this script,
specify the location in your installation for these libraries. E.g.,
```shell
LOCAL_LIB=/usr/local/lib64 ./run_example.sh simple_app_under_oe
```

You can also build-and-setup the simple app using different ways to generate the policy.
Then, run the test multiple times.

- Setup the simple app using Manual policy generation. Run the test multiple times:

```shell
./run_example.sh simple_app_under_oe setup
./run_example.sh simple_app_under_oe run_test
./run_example.sh simple_app_under_oe run_test
```

- Setup the simple app by editing the policy JSON file and use policy generator:
  For this interface, you will need to install the `jq` utility for editing
  the JSON file. `$ sudo apt-get install -y jq`

```shell
./run_example.sh simple_app_under_oe setup_with_auto_policy_generation_for_OE
./run_example.sh simple_app_under_oe run_test
./run_example.sh simple_app_under_oe run_test
```
