# Tests README

This directory contains a collection of setup-type scripts required by tests
run as part of CI. 

A collection of Python pytests live in the [./pytests](.pytests/) directory.

The tests executed as part of CI can be executed in your development
environmnet stand-alone using the [./test.sh](../CI/scripts/test.sh) script.

### Usage

```
Usage: test.sh [--help | --list] [ --from-test <test-function-name> ] [test_all]
```

- List the tests that can be run: `$ test.sh --list`

  This option will list the names of functions, i.e., test targets, driving a
  specific test execution. 

- Run all the tests: `$ test.sh`
- Run a specific test: `$ test.sh <test-name>`

     E.g., `$ test.sh test-run_example-simple_app`

    This command will perform the build-and-setup for the simple_app and will
    execute the simple_app.

- To resume execution from a failed test: `$ test.sh --from-test <test-name>`

    E.g., `$ test.sh --from-test test-build-and-install-sev-snp-simulator`

    This will resume test execution from the `test-build-and-install-sev-snp-simulator`
    test to run the remaining tests in the order reported by the `--list` argument.

- The execution of Python pytests is distributed across these test targets:

    - test-cert_framework-pytests

    - test-mtls-ssl-client-server-comm-pytest

    - test-run_example-simple_app
