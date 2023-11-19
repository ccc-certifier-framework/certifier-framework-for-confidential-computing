# Enhancements and Feature Requests

 1. Finish Nvidia support
 2. Finish Python interface providing way to get keys and certs from store and using them in secure_channel  -- almost done
 3. thread safety for policy store (easy)
 4. Clean up leaks in channel
 5. Implement platform features using Ye's interface for Gramine apps --- Done
 6. Integration with Confidential Containers from IBM et al
 7. Update Docs
 8. Perf tests, Fuzz testing, valgrind for memory leaks
 9. Check enclave to enclave certification (without certifier service)
10. Write/read/open/close_encrypted (DoD request)
11. Nitro
12. TDX
    Build store with key-value, key is measurement and platform id, value is sealing key.
    Retrieve them and send (over encrypted channel) in response to a proper attestation.  You
    Can use the key provisioning in Certifier in a Tee code as a guide.
13. Token issuing serevice example
14. Add service API bindings instructions for secure channels. See https://krpc.github.io/krpc/communication-protocols/tcpip.html.
15. Sample ACL implementation for access over API's using program measurment as principle name.
16. Encrypted code loading
 5. Switch to smphost tools (https://virtee.io/) --- Ye
As available:  Islet simulator and final verify, Keystone simulator and final verify
