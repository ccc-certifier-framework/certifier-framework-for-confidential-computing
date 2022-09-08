Instructions for building and running the systemd attestation service
=====================================================================

Before you begin, make sure you followed the instructions to build the
Certifier. Update the Makefile to point CERTIFIER_LIB and CERTIFIER_INCLUDE to
your Certifier root and include directories. Additionally, make sure you have
the Certifier utilities built:

    cd $CERTIFIER_PROTOTYPE
    cd utilities
    make -f cert_utility.mak
    make -f policy_utilities.mak

Put the utilities directory to your PATH so they are accessible.

================================================================
!!! If you decide to try out the service with the simulator. !!!
================================================================

Make sure you follow the instructions in
$CERTIFIER_PROTOTYPE/sample_apps/simple_app for the provisioning process. Copy
all the files in provision directory and the policy_key.cc to the attestation
systemd service directory. Otherwise a new policy_key and the other files will
be generated automatically.

Add '#define USE_SIMULATED_ENCLAVE' to the beginning of attsvc.cc. Or add -D
USE_SIMULATED_ENCLAVE to CFLAGS in the Makefile.

The simulator mode for the systemd service is FOR DEMONSTRATION ONLY. It
essentially treat the service daemon as the client (app1) in the simple_app
example and use the server (app2) as the notification agent.

Finally, make sure you have the Go Certifier service server and the example_app
server (app2) running before you install and start the systemd service.

================================================================
!!! End of simulator. !!!
================================================================

Step 1: Build the service

    cd $EXAMPLE_DIR
    make

Step 2: Service installation

    sudo ./install.sh install
    (Use 'sudo ./install.sh install simulator' if simulator is used)

This is an interactive installation script. You will be prompted to configure
the service as follows:

    user@ubuntu:sudo ./install.sh install simulator
    Installing attestation service...
    Certifier Service IP: localhost
    Certifier Service Port: 8123
    Notification Client IP: localhost
    Notification Client Port: 8124
    Require Disk Encryption? no
    ● attservice.service - VMware Confidential Computing Attestation Service.
         Loaded: loaded (/etc/systemd/system/attservice.service; disabled; vendor preset: enabled)
         Active: active (running) since Thu 2022-09-08 15:46:22 EDT; 11ms ago
       Main PID: 284013 (attsvc)
          Tasks: 1 (limit: 9461)
         Memory: 796.0K
         CGroup: /system.slice/attservice.service
                 └─284013 /usr/bin/attsvc

    Sep 08 15:46:22 ubuntu systemd[1]: Started VMware Confidential Computing Attestation Service..
    Sep 08 15:46:22 ubuntu attsvc[284013]: VMware Attestation Service[284013]: Performing cold initialization...

Fill in the correct Certifier service and notification agent (client) IP and
port. Answer 'yes' if you want to enforce disk encryption.

The installer will create the service configuration directory at /etc/attsvc/.
A human readable configuration file called config and other supporting files
will be created there. You can manually change the configuration by editing
/etc/attsvc/config. The service will log its output to /var/log/syslog.

If you are using the simulator and both the certifier service and the server
app is running, you should see something like this:

    cat /var/log/syslog | grep VMware
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]: Performing cold initialization...
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]: Attestation Service Configuration:
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]:   Certifier host: localhost:8123
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]:   Notification client: localhost:8124
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]:   Require Disk Encryption? : No
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]: Performing certification...
    Sep  8 15:46:22 ubuntu-vse-test VMware Attestation Service[284013]: Virtual appliance is certified!
    Sep  8 15:46:23 ubuntu-vse-test VMware Attestation Service[284013]: Agent says: Hi from your secret server#012

And the server app should print a SUCCESS:

    running as server
    CA names to offer
     policyAuthority
    at accept
    Accepted ssl connection using TLS_AES_256_GCM_SHA384
    Server: No peer cert presented in nego
    client_auth_server succeeds
    Server peer id is CertifierUsers
    SSL server read: SUCCESS

