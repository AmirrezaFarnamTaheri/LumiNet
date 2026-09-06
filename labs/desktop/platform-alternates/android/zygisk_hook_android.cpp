// Zygisk C++ libc getifaddrs Interface Masker Module
// Intercepts getifaddrs calls inside sandboxed target applications to hide TUN/WireGuard interfaces.

#include <jni.h>
#include <ifaddrs.h>
#include <string.h>
#include <android/log.h>

#define LOG_TAG "LumiNetZygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static int (*orig_getifaddrs)(struct ifaddrs** ifap) = nullptr;

extern "C" int getifaddrs(struct ifaddrs** ifap) {
    if (!orig_getifaddrs) {
        return -1;
    }

    int ret = orig_getifaddrs(ifap);
    if (ret != 0 || !ifap || !*ifap) {
        return ret;
    }

    struct ifaddrs* prev = nullptr;
    struct ifaddrs* curr = *ifap;

    while (curr) {
        // Mask tun0 and wg0 interfaces from process visibility
        if (curr->ifa_name && (strcmp(curr->ifa_name, "tun0") == 0 || strcmp(curr->ifa_name, "wg0") == 0)) {
            LOGI("Zygisk getifaddrs: masking virtual interface %s", curr->ifa_name);
            struct ifaddrs* next = curr->ifa_next;
            if (prev) {
                prev->ifa_next = next;
            } else {
                *ifap = next;
            }
            curr = next;
        } else {
            prev = curr;
            curr = curr->ifa_next;
        }
    }

    return 0;
}
