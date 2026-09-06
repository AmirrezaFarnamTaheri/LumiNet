// Ported from: WhiteDNS
// Target path: desktop/android/whitedns_manager.kt

package com.luminet.android

import android.content.Context
import android.content.SharedPreferences

/**
 * WhiteDNSManager controls the Android-side DNSCrypt, DoH, and custom DNS profiles storage
 * and onboarding preferences utilizing SharedPreferences.
 */
class WhiteDNSManager(private val context: Context) {

    private val sharedPrefs: SharedPreferences = context.getSharedPreferences("WhiteDNS_Prefs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_PRIMARY_DNS = "primary_dns"
        private const val KEY_FALLBACK_DNS = "fallback_dns"
        private const val KEY_ENABLE_DOH = "enable_doh"
        private const val KEY_DOH_ENDPOINT = "doh_endpoint"
        private const val KEY_ENABLE_DNSCRYPT = "enable_dnscrypt"
    }

    /**
     * Persists customized DNS configuration profiles.
     */
    fun saveDNSProfile(primary: String, fallback: String, enableDoH: Boolean, dohUrl: String, enableDNSCrypt: Boolean) {
        sharedPrefs.edit().apply {
            putString(KEY_PRIMARY_DNS, primary)
            putString(KEY_FALLBACK_DNS, fallback)
            putBoolean(KEY_ENABLE_DOH, enableDoH)
            putString(KEY_DOH_ENDPOINT, dohUrl)
            putBoolean(KEY_ENABLE_DNSCRYPT, enableDNSCrypt)
            apply()
        }
    }

    /**
     * Retrieves primary DNS resolver IP.
     */
    fun getPrimaryDNS(): String {
        return sharedPrefs.getString(KEY_PRIMARY_DNS, "1.1.1.1") ?: "1.1.1.1"
    }

    /**
     * Retrieves fallback DNS resolver IP.
     */
    fun getFallbackDNS(): String {
        return sharedPrefs.getString(KEY_FALLBACK_DNS, "8.8.8.8") ?: "8.8.8.8"
    }

    /**
     * Checks if DNS-over-HTTPS (DoH) is enabled.
     */
    fun isDoHEnabled(): Boolean {
        return sharedPrefs.getBoolean(KEY_ENABLE_DOH, true)
    }

    /**
     * Retrieves custom DNS-over-HTTPS server endpoint.
     */
    fun getDoHEndpoint(): String {
        return sharedPrefs.getString(KEY_DOH_ENDPOINT, "https://cloudflare-dns.com/dns-query") ?: "https://cloudflare-dns.com/dns-query"
    }

    /**
     * Checks if DNSCrypt proxy is enabled.
     */
    fun isDNSCryptEnabled(): Boolean {
        return sharedPrefs.getBoolean(KEY_ENABLE_DNSCRYPT, false)
    }

    /**
     * Diagnostically resets all stored configurations to standard safe defaults.
     */
    fun setup() {
        saveDNSProfile("1.1.1.1", "8.8.8.8", true, "https://cloudflare-dns.com/dns-query", false)
    }
}
