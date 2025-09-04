# Multi-Domain Simple App - Instructions

This document gives detailed instructions for building and running the sample
application and generating the policy for the Certifier Service using the policy
utilities.

This version is like the simple_app except that the client and the server
are in two different policy domains. Each certifies to their home domain's certifier
but they also certify to another Certifier Service. The initialization up to and
including the initial certification (performed by `certify_me()`) is identical
to the simple_app example but then the client and the server certify to another
domain by first recording its data using

-----------------------------------------------------------------------------


## Build overview

As usual, it's convenient to have the following variables defined:

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it:
```shell
export CERTIFIER_PROTOTYPE=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.
```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/multidomain_simple_app
```
Now that the pattern is set, to save time, we just supply the two shell
scripts prepare-test.sh and run-test.sh rather than detailed instructions.
The shell script prepare-test.sh builds
the program and support files.  The shell script run-test.sh runs the test.
There is still benefit in carrying out the steps in run-test by copying and
pasting since you can see all the output and preserve the running servers.

The shell scripts assume you have all the right software installed including
the go programs and libraries mentioned below.

The shell scripts use the new API.

To prepare the test files, type:

  prepare-test.sh fresh [domain-name]
      - This clears out all old files
then
  prepare-test.sh all [domain-name]
      - This builds the files corresponding to steps 1-9 below.
then
  run-test.sh fresh [domain-name]
      - This removes old application files (policy store and cryptstore)
      - and runs the tests, corresponding to steps 9 and 10 below.

prepare-test.sh all runs the following subcommands in order:
  prepare-test.sh compile-utilities [domain-name]
      - This performs steps 1-2 below.
  prepare-test.sh make-keys [domain-name]
      - This performs step 3 below.
  prepare-test.sh compile-program [domain-name]
      - This performs step 4 to 5 below.
  prepare-test.sh make-policy [domain-name]
      - This performs steps 6 and 7 below.
  prepare-test.sh compile-certifier [domain-name]
      - This performs step 8 below.
  prepare-test.sh copy-files [domain-name]
      - This performs steps 9 to 12 below.

Each of these subcommands is runable from prepare-test.sh, for example,
you could run,
   prepare-test.sh make-policy [domain-name]
to remake the policy.

After you run "prepare-test.sh all", you can rerun the tests without
invoking prepare-test.sh.  After you run "prepare-test.sh all",

To run the tests
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
     -- This clears previous operational files.  The first assumes the
        default domain name ("datica-test").
  echo "  ./run-test.sh run (se | sev)"
  echo "  ./run-test.sh run domain_name (se | sev)"
     -- This runs the test.  The first assumes the default domain
         name ("datica-test").
you need only run subcommands that cause a change in the files;
for example, if you change the policy, you need only run
"prepare-test.sh make-policy" before running the tests.


------------------------------------------------------------------------------------
