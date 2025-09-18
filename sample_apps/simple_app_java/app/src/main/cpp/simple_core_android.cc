#include <string>
#include <sstream>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "CertifierJNI", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "CertifierJNI", __VA_ARGS__)

// Later: #include "certifier/..." and call TrustManager, channels, etc.
std::string run_certifier_simple(const std::string& workDir,
                                 const std::string& mode,
                                 const std::string& host,
                                 int port) {
    LOGI("run_certifier_simple(workDir=%s, mode=%s, host=%s, port=%d)",
         workDir.c_str(), mode.c_str(), host.c_str(), port);

    // TODO: read policy/keys from workDir, init trust manager, eval policy,
    // and (optionally) connect to host:port.
    std::ostringstream out;
    out << "Certifier native OK\n"
        << "mode=" << mode << " host=" << host << " port=" << port << "\n"
        << "workDir=" << workDir;
    return out.str();
}
