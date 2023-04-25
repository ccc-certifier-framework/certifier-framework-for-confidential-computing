# run_example.sh - Setup and run test for simple_app program

This document is a user's guide to the run_example.sh script that you can use
to setup and run the simple_app sample app.

The simple_app sample program provides an example of initializing
and provisioning the Certifier Service with utility generated keys,
measurements and policy.

This script packages the steps documented in
[instructions.md](./instructions.md) in a self-contained script to execute
the simple_app program.

```shell
$ ./run_example.sh --help
You can use this script to Build and run example program simple_app.

   - Setup and execute the example program.
   - List the individual steps needed to setup the example program.
   - Run individual step in sequence.

Usage: run_example.sh [--help | --list]
  To run the example program          : ./run_example.sh
  To setup the example program        : ./run_example.sh setup
  To run and test the example program : ./run_example.sh run_test
  To list the individual steps        : ./run_example.sh --list
  To run an individual step           : ./run_example.sh <step name>
```

- To setup and run the simple_app: `$ run_example.sh`
- In case there is any cleanup needed, issue: `$ cleanup.sh`
- You can perform the setup once, and execute the test multiple times as follows:

```shell
$ run_example.sh setup
$ run_example.sh run_test
$ run_example.sh run_test
```
- List the individual steps of the setup / text: `$ run_example.sh --list`
- Execute each step in the order listed. E.g., `$ run_example.sh  get_measurement_of_trusted_app`