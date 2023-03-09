Writing an applicaation service based  CC app with the Certifier Framework
==========================================================================

The example app shows all the major steps in a Confidential Computing Program,
running under an application-service which allows.

These steps are made much simpler by the Certifier API as indicated in
instructions.txt. As with the simple_app, the instructions are detailed
and generally similar except for the application-service features.  These
include starting the application by sending a meesage to the application
service to start the program and actually running such a service.  This
is demonstrated in the application_service directory where application_service
is built.  This message can come from any program including a utility called
send_request in the application service directory.

There are almost no changes for the simple_example program to work with the
application service, basically the only difference is a call to a different
initialization function at program startup.  As a result, the application
code is nearly identical with simple_example.

Service calls are made between a parent (the application service in sev VM
level enclave, for example) and the application via pipes; however, the
certifier framework handles all this without program changes.

