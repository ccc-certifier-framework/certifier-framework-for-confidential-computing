public class SimulatedTest {
    static {
        System.loadLibrary("simulated_enclave");
    }

    public static void main(String[] args) {
        StringBuilder attestation = new StringBuilder();
        StringBuilder platformCert = new StringBuilder();
        StringBuilder measurement = new StringBuilder();

        boolean initStatus = simulated_enclave.simulated_init();
        System.out.println("Init successful: " + initStatus);

        if (simulated_enclave.simulated_attest(attestation)) {
            System.out.println("Attestation: " + attestation.toString());
        }

        if (simulated_enclave.simulated_get_platform_cert(platformCert)) {
            System.out.println("Platform Cert: " + platformCert.toString());
        }

        if (simulated_enclave.simulated_get_measurement(measurement)) {
            System.out.println("Measurement: " + measurement.toString());
        }
    }
}
