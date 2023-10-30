# Tests README

This directory contains a collection of setup-type scripts required by tests
that are run as part of CI.

A collection of Python pytests live in the [./pytests](.pytests/) directory.

The tests executed as part of CI can be executed stand-alone in your
development environment using the [./test.sh](../CI/scripts/test.sh) script.

## Usage

```
Usage: test.sh [--help | --list] [ --from-test <test-function-name> ] [test_all]
```

- List the tests that can be run: `$ test.sh --list`

  This option will list the names of functions, i.e., test targets, driving
  the execution of a specific test scenario.

- Run all the tests: `$ test.sh`
- Run a specific test: `$ test.sh <test-name>`

     E.g., `$ test.sh test-run_example-simple_app`

    This command will perform the build-and-setup for the simple_app and will
    execute the simple_app.

- To resume execution from a failed test: `$ test.sh --from-test <test-name>`

    E.g., `$ test.sh --from-test test-build-and-install-sev-snp-simulator`

    This will resume test execution from the `test-build-and-install-sev-snp-simulator`
    test to run the remaining tests in the order reported by the `--list` argument.

## Executing test targets: `--list` output

Execution of some tests / test-cases needs multiple steps that need to be
executed in a sequence. One of the goals of `test.sh` is to encapsulate this
workflow [of steps] in a single test-execution target, found in the output
of the `--list` command.

Here are some examples:

- The execution of Python pytests is distributed across these test targets:

    - test-cert_framework-pytests

    - test-mtls-ssl-client-server-comm-pytest

    - test-run_example-simple_app

  Each of these can be run using a named test-target. For example:

    ```
    $ ./test.sh test-cert_framework-pytests

    $ ./test.sh test-mtls-ssl-client-server-comm-pytest

    $ ./test.sh test-run_example-simple_app
    ```

- Executing simple_app under Application Service needs a multi-step
  workflow. These are enacpsulated under a single test-target,
  executed as:

  ```
  $ ./test.sh test-build-and-setup-App-Service-and-simple_app_under_app_service
  ```
