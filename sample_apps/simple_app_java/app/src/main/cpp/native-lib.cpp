#include <jni.h>
#include <string>

std::string run_certifier_simple(const std::string& workDir,
                                 const std::string& mode,
                                 const std::string& host,
                                 int port);

extern "C"
JNIEXPORT jstring JNICALL
Java_org_certifier_examples_SimpleApp_runCertifierNative(
        JNIEnv* env, jclass /*clazz*/,
        jstring jWorkDir, jstring jMode, jstring jHost, jint jPort) {

    const char* w = env->GetStringUTFChars(jWorkDir, nullptr);
    const char* m = env->GetStringUTFChars(jMode,    nullptr);
    const char* h = env->GetStringUTFChars(jHost,    nullptr);

    std::string work = w ? w : "";
    std::string mode = m ? m : "";
    std::string host = h ? h : "";
    int port = static_cast<int>(jPort);

    if (w) env->ReleaseStringUTFChars(jWorkDir, w);
    if (m) env->ReleaseStringUTFChars(jMode,    m);
    if (h) env->ReleaseStringUTFChars(jHost,    h);

    std::string result = run_certifier_simple(work, mode, host, port);
    return env->NewStringUTF(result.c_str());
}
