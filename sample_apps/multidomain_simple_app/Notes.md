# Writing a CC app with the Certifier Framework


The example app shows all the major steps in a Confidential Computing program.
These steps are made much simpler by the Certifier API as indicated in
[instructions.md](./instructions.md).  multidomain-simpe_app adds certifying
in two different domains.

## For the Certifier Service
  1. Generate all the keys and the self-signed policy certificate:
     - This is done by the cert_utility.exe.
     - The cert utility also generates support keys for the simulated-enclave.
  2. Measure the app:  This is done by measurement_utility.exe.
  3. Author the policy: See step 7 in instructions.md.
  4. Build the service: See step 8 in instructions.md.
  5. Create and provision the service data: Steps 9-13 in instructions.md.
  6. Run the service: Step 13 instructions.md.

## For the Application

  1. Embed the policy key: This is done by the `embed_policy_key.exe` using
     the self-signed policy certificate from the Certifier Service.
  2. Isolate and measure the program: This is done by the platform.

  Subsequent steps are simplified using the cc_trust_data class in [cc_helpers.cc](../../src/cc_helpers.cc).

  3. Generate application keys and store them: This is done by `cold_init()`.
  4. Get certified and store the certificate:  This is done by a call to `certify_me(const string& host_name, int port)`.
  5. Recover Data: This is done in `warm_restart()`.
  6. Open a secure channel to send data.
      - The socket and SSL routines in cc_helpers.cc help set up the mutually
        authenticated secure channel.
      - The channel management is done in the application.
      - `run_me_as_server()` in the example shows how to do this when the app acts as a
        server. The actual (quite simple) transaction is done in `server_application()`.
      - `run_me_as_client()` in the example, shows how to do the client side of the
        channel.  The actual (quite simple) transaction is done in `client_application()`.
