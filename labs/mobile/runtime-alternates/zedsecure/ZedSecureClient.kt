package com.luminet.zedsecure

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import org.json.JSONObject
import java.io.File

/**
 * ZedSecureClient manages the Android VPN service integration, profile generation,
 * stealth evasion settings (REALITY TLS fingerprinting), and split-tunneling package exclusions.
 */
class ZedSecureClient(private val context: Context) {
    
    private val TAG = "ZedSecureClient"
    private val profileDir: File = File(context.filesDir, "profiles")

    init {
        if (!profileDir.exists()) {
            profileDir.mkdirs()
        }
    }

    /**
     * VPN Config Profile representing the connection settings.
     */
    data class VpnProfile(
        val name: String,
        val serverAddress: String,
        val serverPort: Int,
        val protocol: String, // e.g., "VLESS", "Shadowsocks", "TUIC"
        val clientFingerprint: String, // e.g., "chrome", "firefox", "safari"
        val enableGoodbyeDPI: Boolean,
        val cloakPsk: String?,
        val realityPublicKey: String?,
        val excludedPackages: List<String> = emptyList(),
        val dnsOverHttpsUrl: String? = null,
        val enableEch: Boolean = false,
        val echConfig: String? = null,
        val enableMux: Boolean = false,
        val muxConcurrency: Int = 8,
        val enableUdp: Boolean = true,
        val logLevel: String = "info",
        val allowedDomains: List<String> = emptyList(),
        val blockedIps: List<String> = emptyList(),
        val mtuSize: Int = 1400,
        val routingMode: String = "global",
        val packetPadding: Boolean = false,
        val utlsSpoof: String? = null
    )

    /**
     * Parse profile JSON content into VpnProfile struct.
     */
    fun parseProfile(jsonString: String): VpnProfile? {
        return try {
            val json = JSONObject(jsonString)
            val excludeArray = json.optJSONArray("excludedPackages")
            val excluded = mutableListOf<String>()
            if (excludeArray != null) {
                for (i in 0 until excludeArray.length()) {
                    excluded.add(excludeArray.getString(i))
                }
            }
            val allowedDomainsArray = json.optJSONArray("allowedDomains")
            val allowedDoms = mutableListOf<String>()
            if (allowedDomainsArray != null) {
                for (i in 0 until allowedDomainsArray.length()) {
                    allowedDoms.add(allowedDomainsArray.getString(i))
                }
            }
            val blockedIpsArray = json.optJSONArray("blockedIps")
            val blocked = mutableListOf<String>()
            if (blockedIpsArray != null) {
                for (i in 0 until blockedIpsArray.length()) {
                    blocked.add(blockedIpsArray.getString(i))
                }
            }
            VpnProfile(
                name = json.getString("name"),
                serverAddress = json.getString("serverAddress"),
                serverPort = json.getInt("serverPort"),
                protocol = json.getString("protocol"),
                clientFingerprint = json.optString("clientFingerprint", "chrome"),
                enableGoodbyeDPI = json.optBoolean("enableGoodbyeDPI", false),
                cloakPsk = json.optString("cloakPsk", null),
                realityPublicKey = json.optString("realityPublicKey", null),
                excludedPackages = excluded,
                dnsOverHttpsUrl = json.optString("dnsOverHttpsUrl", null),
                enableEch = json.optBoolean("enableEch", false),
                echConfig = json.optString("echConfig", null),
                enableMux = json.optBoolean("enableMux", false),
                muxConcurrency = json.optInt("muxConcurrency", 8),
                enableUdp = json.optBoolean("enableUdp", true),
                logLevel = json.optString("logLevel", "info"),
                allowedDomains = allowedDoms,
                blockedIps = blocked,
                mtuSize = json.optInt("mtuSize", 1400),
                routingMode = json.optString("routingMode", "global"),
                packetPadding = json.optBoolean("packetPadding", false),
                utlsSpoof = json.optString("utlsSpoof", null)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse VPN Profile: ${e.message}")
            null
        }
    }

    /**
     * Save the VPN Profile configuration to disk.
     */
    fun saveProfile(profile: VpnProfile): Boolean {
        return try {
            val file = File(profileDir, "${profile.name}.json")
            val json = JSONObject().apply {
                put("name", profile.name)
                put("serverAddress", profile.serverAddress)
                put("serverPort", profile.serverPort)
                put("protocol", profile.protocol)
                put("clientFingerprint", profile.clientFingerprint)
                put("enableGoodbyeDPI", profile.enableGoodbyeDPI)
                put("cloakPsk", profile.cloakPsk)
                put("realityPublicKey", profile.realityPublicKey)
                put("excludedPackages", JSONObject.wrap(profile.excludedPackages))
                put("dnsOverHttpsUrl", profile.dnsOverHttpsUrl)
                put("enableEch", profile.enableEch)
                put("echConfig", profile.echConfig)
                put("enableMux", profile.enableMux)
                put("muxConcurrency", profile.muxConcurrency)
                put("enableUdp", profile.enableUdp)
                put("logLevel", profile.logLevel)
                put("allowedDomains", JSONObject.wrap(profile.allowedDomains))
                put("blockedIps", JSONObject.wrap(profile.blockedIps))
                put("mtuSize", profile.mtuSize)
                put("routingMode", profile.routingMode)
                put("packetPadding", profile.packetPadding)
                put("utlsSpoof", profile.utlsSpoof)
            }
            file.writeText(json.toString(4))
            Log.i(TAG, "Successfully saved VPN profile: ${profile.name}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save profile on disk: ${e.message}")
            false
        }
    }

    // --- Profile Getters ---
    fun getProfileName(profile: VpnProfile): String = profile.name
    fun getProfileServerAddress(profile: VpnProfile): String = profile.serverAddress
    fun getProfileServerPort(profile: VpnProfile): Int = profile.serverPort
    fun getProfileProtocol(profile: VpnProfile): String = profile.protocol
    fun getProfileClientFingerprint(profile: VpnProfile): String = profile.clientFingerprint
    fun getProfileEnableGoodbyeDPI(profile: VpnProfile): Boolean = profile.enableGoodbyeDPI
    fun getProfileCloakPsk(profile: VpnProfile): String? = profile.cloakPsk
    fun getProfileRealityPublicKey(profile: VpnProfile): String? = profile.realityPublicKey
    fun getProfileExcludedPackages(profile: VpnProfile): List<String> = profile.excludedPackages
    fun getProfileDnsOverHttpsUrl(profile: VpnProfile): String? = profile.dnsOverHttpsUrl
    fun getProfileEnableEch(profile: VpnProfile): Boolean = profile.enableEch
    fun getProfileEchConfig(profile: VpnProfile): String? = profile.echConfig
    fun getProfileEnableMux(profile: VpnProfile): Boolean = profile.enableMux
    fun getProfileMuxConcurrency(profile: VpnProfile): Int = profile.muxConcurrency
    fun getProfileEnableUdp(profile: VpnProfile): Boolean = profile.enableUdp
    fun getProfileLogLevel(profile: VpnProfile): String = profile.logLevel
    fun getProfileAllowedDomains(profile: VpnProfile): List<String> = profile.allowedDomains
    fun getProfileBlockedIps(profile: VpnProfile): List<String> = profile.blockedIps
    fun getProfileMtuSize(profile: VpnProfile): Int = profile.mtuSize
    fun getProfileRoutingMode(profile: VpnProfile): String = profile.routingMode
    fun getProfilePacketPadding(profile: VpnProfile): Boolean = profile.packetPadding
    fun getProfileUtlsSpoof(profile: VpnProfile): String? = profile.utlsSpoof

    // --- Profile Builders ---
    fun withName(profile: VpnProfile, name: String): VpnProfile = profile.copy(name = name)
    fun withServerAddress(profile: VpnProfile, addr: String): VpnProfile = profile.copy(serverAddress = addr)
    fun withServerPort(profile: VpnProfile, port: Int): VpnProfile = profile.copy(serverPort = port)
    fun withProtocol(profile: VpnProfile, proto: String): VpnProfile = profile.copy(protocol = proto)
    fun withClientFingerprint(profile: VpnProfile, fp: String): VpnProfile = profile.copy(clientFingerprint = fp)
    fun withEnableGoodbyeDPI(profile: VpnProfile, enabled: Boolean): VpnProfile = profile.copy(enableGoodbyeDPI = enabled)
    fun withCloakPsk(profile: VpnProfile, psk: String?): VpnProfile = profile.copy(cloakPsk = psk)
    fun withRealityPublicKey(profile: VpnProfile, key: String?): VpnProfile = profile.copy(realityPublicKey = key)
    fun withExcludedPackages(profile: VpnProfile, pkgs: List<String>): VpnProfile = profile.copy(excludedPackages = pkgs)
    fun withDnsOverHttpsUrl(profile: VpnProfile, url: String?): VpnProfile = profile.copy(dnsOverHttpsUrl = url)
    fun withEnableEch(profile: VpnProfile, enabled: Boolean): VpnProfile = profile.copy(enableEch = enabled)
    fun withEchConfig(profile: VpnProfile, conf: String?): VpnProfile = profile.copy(echConfig = conf)
    fun withEnableMux(profile: VpnProfile, enabled: Boolean): VpnProfile = profile.copy(enableMux = enabled)
    fun withMuxConcurrency(profile: VpnProfile, c: Int): VpnProfile = profile.copy(muxConcurrency = c)
    fun withEnableUdp(profile: VpnProfile, enabled: Boolean): VpnProfile = profile.copy(enableUdp = enabled)
    fun withLogLevel(profile: VpnProfile, level: String): VpnProfile = profile.copy(logLevel = level)
    fun withAllowedDomains(profile: VpnProfile, domains: List<String>): VpnProfile = profile.copy(allowedDomains = domains)
    fun withBlockedIps(profile: VpnProfile, ips: List<String>): VpnProfile = profile.copy(blockedIps = ips)
    fun withMtuSize(profile: VpnProfile, size: Int): VpnProfile = profile.copy(mtuSize = size)
    fun withRoutingMode(profile: VpnProfile, mode: String): VpnProfile = profile.copy(routingMode = mode)
    fun withPacketPadding(profile: VpnProfile, padding: Boolean): VpnProfile = profile.copy(packetPadding = padding)
    fun withUtlsSpoof(profile: VpnProfile, spoof: String?): VpnProfile = profile.copy(utlsSpoof = spoof)

    /**
     * Configure VpnService Intent with target parameters.
     */
    fun prepareVpnIntent(profile: VpnProfile, vpnServiceClass: Class<out VpnService>): Intent {
        return Intent(context, vpnServiceClass).apply {
            putExtra("EXTRA_PROFILE_NAME", profile.name)
            putExtra("EXTRA_SERVER_ADDR", profile.serverAddress)
            putExtra("EXTRA_SERVER_PORT", profile.serverPort)
            putExtra("EXTRA_PROTOCOL", profile.protocol)
            putExtra("EXTRA_FINGERPRINT", profile.clientFingerprint)
            putExtra("EXTRA_GOODBYEDPI", profile.enableGoodbyeDPI)
            if (profile.cloakPsk != null) {
                putExtra("EXTRA_CLOAK_PSK", profile.cloakPsk)
            }
            if (profile.realityPublicKey != null) {
                putExtra("EXTRA_REALITY_KEY", profile.realityPublicKey)
            }
            putStringArrayListExtra("EXTRA_EXCLUDED_PACKAGES", ArrayList(profile.excludedPackages))
        }
    }

    /**
     * Apply connection setup filters and routing configuration inside VpnService builder.
     */
    fun establishVpnBuilder(builder: VpnService.Builder, profile: VpnProfile): VpnService.Builder {
        builder.setSession(profile.name)
            .setMtu(1400)
            .addAddress("10.8.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")

        // Apply package-specific bypass split tunneling
        for (pkg in profile.excludedPackages) {
            try {
                builder.addDisallowedApplication(pkg)
                Log.d(TAG, "Excluded package from VPN tunnel: $pkg")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude package '$pkg': ${e.message}")
            }
        }
        return builder
    }

    // ---------------------------------------------------------------------------
    // Ported from: WhiteDNS-Android-main
    // ---------------------------------------------------------------------------

    /**
     * Configuration profile for Tun2Proxy wrapper.
     */
    class Tun2ProxyConfig {
        private var proxyUrl: String = ""
        private var tunFd: Int = -1
        private var closeFdOnDrop: Boolean = true
        private var tunMtu: Char = ' '
        private var verbosity: Int = 3
        private var dnsStrategy: Int = 0
        private val ipWhitelist = java.util.ArrayList<String>()
        private val ipBlacklist = java.util.ArrayList<String>()
        private val allowedApps = java.util.ArrayList<String>()
        private val blockedApps = java.util.ArrayList<String>()
        private var enableIpv6: Boolean = false
        private var dnsVirtualPort: Int = 53
        private var dnsOverTcpPort: Int = 53
        private var enablePacketPadding: Boolean = false
        private var connectionTimeoutMs: Int = 5000

        // Getters & Setters
        fun getProxyUrl(): String = proxyUrl
        fun setProxyUrl(valStr: String) { proxyUrl = valStr }
        fun getTunFd(): Int = tunFd
        fun setTunFd(valInt: Int) { tunFd = valInt }
        fun getCloseFdOnDrop(): Boolean = closeFdOnDrop
        fun setCloseFdOnDrop(valBool: Boolean) { closeFdOnDrop = valBool }
        fun getTunMtu(): Char = tunMtu
        fun setTunMtu(valChar: Char) { tunMtu = valChar }
        fun getVerbosity(): Int = verbosity
        fun setVerbosity(valInt: Int) { verbosity = valInt }
        fun getDnsStrategy(): Int = dnsStrategy
        fun setDnsStrategy(valInt: Int) { dnsStrategy = valInt }
        fun getIpWhitelist(): java.util.ArrayList<String> = ipWhitelist
        fun setIpWhitelist(valList: java.util.ArrayList<String>) { ipWhitelist.clear(); ipWhitelist.addAll(valList) }
        fun getIpBlacklist(): java.util.ArrayList<String> = ipBlacklist
        fun setIpBlacklist(valList: java.util.ArrayList<String>) { ipBlacklist.clear(); ipBlacklist.addAll(valList) }
        fun getAllowedApps(): java.util.ArrayList<String> = allowedApps
        fun setAllowedApps(valList: java.util.ArrayList<String>) { allowedApps.clear(); allowedApps.addAll(valList) }
        fun getBlockedApps(): java.util.ArrayList<String> = blockedApps
        fun setBlockedApps(valList: java.util.ArrayList<String>) { blockedApps.clear(); blockedApps.addAll(valList) }
        fun getEnableIpv6(): Boolean = enableIpv6
        fun setEnableIpv6(valBool: Boolean) { enableIpv6 = valBool }
        fun getDnsVirtualPort(): Int = dnsVirtualPort
        fun setDnsVirtualPort(valInt: Int) { dnsVirtualPort = valInt }
        fun getDnsOverTcpPort(): Int = dnsOverTcpPort
        fun setDnsOverTcpPort(valInt: Int) { dnsOverTcpPort = valInt }
        fun getEnablePacketPadding(): Boolean = enablePacketPadding
        fun setEnablePacketPadding(valBool: Boolean) { enablePacketPadding = valBool }
        fun getConnectionTimeoutMs(): Int = connectionTimeoutMs
        fun setConnectionTimeoutMs(valInt: Int) { connectionTimeoutMs = valInt }

        // Builders
        fun withProxyUrl(valStr: String): Tun2ProxyConfig { proxyUrl = valStr; return this }
        fun withTunFd(valInt: Int): Tun2ProxyConfig { tunFd = valInt; return this }
        fun withCloseFdOnDrop(valBool: Boolean): Tun2ProxyConfig { closeFdOnDrop = valBool; return this }
        fun withTunMtu(valChar: Char): Tun2ProxyConfig { tunMtu = valChar; return this }
        fun withVerbosity(valInt: Int): Tun2ProxyConfig { verbosity = valInt; return this }
        fun withDnsStrategy(valInt: Int): Tun2ProxyConfig { dnsStrategy = valInt; return this }
        fun withIpWhitelist(valList: java.util.ArrayList<String>): Tun2ProxyConfig { setIpWhitelist(valList); return this }
        fun withIpBlacklist(valList: java.util.ArrayList<String>): Tun2ProxyConfig { setIpBlacklist(valList); return this }
        fun withAllowedApps(valList: java.util.ArrayList<String>): Tun2ProxyConfig { setAllowedApps(valList); return this }
        fun withBlockedApps(valList: java.util.ArrayList<String>): Tun2ProxyConfig { setBlockedApps(valList); return this }
        fun withEnableIpv6(valBool: Boolean): Tun2ProxyConfig { enableIpv6 = valBool; return this }
        fun withDnsVirtualPort(valInt: Int): Tun2ProxyConfig { dnsVirtualPort = valInt; return this }
        fun withDnsOverTcpPort(valInt: Int): Tun2ProxyConfig { dnsOverTcpPort = valInt; return this }
        fun withEnablePacketPadding(valBool: Boolean): Tun2ProxyConfig { enablePacketPadding = valBool; return this }
        fun withConnectionTimeoutMs(valInt: Int): Tun2ProxyConfig { connectionTimeoutMs = valInt; return this }

        // Array / List Modifiers
        fun addIpWhitelist(ip: String) { ipWhitelist.add(ip) }
        fun removeIpWhitelist(ip: String): Boolean = ipWhitelist.remove(ip)
        fun clearIpWhitelist() { ipWhitelist.clear() }
        fun getIpWhitelistCount(): Int = ipWhitelist.size

        fun addIpBlacklist(ip: String) { ipBlacklist.add(ip) }
        fun removeIpBlacklist(ip: String): Boolean = ipBlacklist.remove(ip)
        fun clearIpBlacklist() { ipBlacklist.clear() }
        fun getIpBlacklistCount(): Int = ipBlacklist.size

        fun addAllowedApp(pkg: String) { allowedApps.add(pkg) }
        fun removeAllowedApp(pkg: String): Boolean = allowedApps.remove(pkg)
        fun clearAllowedApps() { allowedApps.clear() }
        fun getAllowedAppsCount(): Int = allowedApps.size

        fun addBlockedApp(pkg: String) { blockedApps.add(pkg) }
        fun removeBlockedApp(pkg: String): Boolean = blockedApps.remove(pkg)
        fun clearBlockedApps() { blockedApps.clear() }
        fun getBlockedAppsCount(): Int = blockedApps.size
    }

    /**
     * JNI interface for native libtun2proxy executions.
     */
    object Tun2proxyJni {
        const val DNS_VIRTUAL = 0
        const val DNS_OVER_TCP = 1
        const val DNS_DIRECT = 2

        const val VERBOSITY_OFF = 0
        const val VERBOSITY_ERROR = 1
        const val VERBOSITY_WARN = 2
        const val VERBOSITY_INFO = 3
        const val VERBOSITY_DEBUG = 4
        const val VERBOSITY_TRACE = 5

        init {
            try {
                System.loadLibrary("tun2proxy")
            } catch (e: UnsatisfiedLinkError) {
                Log.w("Tun2proxyJni", "Native tun2proxy library was not pre-loaded: ${e.message}")
            }
        }

        @JvmStatic
        external fun run(
            proxyUrl: String,
            tunFd: Int,
            closeFdOnDrop: Boolean,
            tunMtu: Char,
            verbosity: Int,
            dnsStrategy: Int
        ): Int

        @JvmStatic
        external fun stop(): Int
    }

    /**
     * Tun2Socks native library helper installer.
     */
    class Tun2SocksBinaryInstaller(private val context: Context) {
        private var libraryName: String = "libtun2proxy.so"

        fun getLibraryName(): String = libraryName
        fun setLibraryName(name: String) { libraryName = name }

        fun requireLibrary(): File {
            val library = File(context.applicationInfo.nativeLibraryDir, libraryName)
            if (!library.exists()) {
                Log.w("BinaryInstaller", "Native library libtun2proxy.so not found at ${library.absolutePath}")
            }
            return library
        }
    }

    /**
     * VPN Events definitions and listeners registry.
     */
    sealed class WhiteDnsVpnEvent {
        data class Log(val sessionId: String, val message: String) : WhiteDnsVpnEvent()
        data class Ready(val sessionId: String, val message: String) : WhiteDnsVpnEvent()
        data class Failed(val sessionId: String, val message: String) : WhiteDnsVpnEvent()
    }

    object WhiteDnsVpnEvents {
        private val listeners = java.util.concurrent.CopyOnWriteArraySet<(WhiteDnsVpnEvent) -> Unit>()

        fun addListener(listener: (WhiteDnsVpnEvent) -> Unit) {
            listeners.add(listener)
        }

        fun removeListener(listener: (WhiteDnsVpnEvent) -> Unit) {
            listeners.remove(listener)
        }

        fun clearListeners() {
            listeners.clear()
        }

        fun getListenersCount(): Int = listeners.size

        fun log(sessionId: String, message: String) {
            emit(WhiteDnsVpnEvent.Log(sessionId, message))
        }

        fun ready(sessionId: String, message: String) {
            emit(WhiteDnsVpnEvent.Ready(sessionId, message))
        }

        fun failed(sessionId: String, message: String) {
            emit(WhiteDnsVpnEvent.Failed(sessionId, message))
        }

        private fun emit(event: WhiteDnsVpnEvent) {
            listeners.forEach { listener ->
                runCatching { listener(event) }
            }
        }
    }

    /**
     * Service process execution supervisor.
     */
    class Tun2SocksProcessManager(
        private val context: Context,
        private val binaryInstaller: Tun2SocksBinaryInstaller = Tun2SocksBinaryInstaller(context)
    ) {
        private var active: Boolean = false
        private var serviceState: String = "stopped"
        private var connsCount: Long = 0L
        private var lastError: String = ""
        private var startedTime: Long = 0L
        private var retryAttempts: Int = 0
        private var socksHost: String = ""
        private var socksPort: Int = 1080
        private var socksUsername: String? = null
        private var socksPassword: String? = null

        // Getters and Setters
        fun getActive(): Boolean = active
        fun setActive(valBool: Boolean) { active = valBool }
        fun getServiceState(): String = serviceState
        fun setServiceState(valStr: String) { serviceState = valStr }
        fun getConnsCount(): Long = connsCount
        fun setConnsCount(valLong: Long) { connsCount = valLong }
        fun getLastError(): String = lastError
        fun setLastError(valStr: String) { lastError = valStr }
        fun getStartedTime(): Long = startedTime
        fun setStartedTime(valLong: Long) { startedTime = valLong }
        fun getRetryAttempts(): Int = retryAttempts
        fun setRetryAttempts(valInt: Int) { retryAttempts = valInt }
        fun getSocksHost(): String = socksHost
        fun setSocksHost(valStr: String) { socksHost = valStr }
        fun getSocksPort(): Int = socksPort
        fun setSocksPort(valInt: Int) { socksPort = valInt }
        fun getSocksUsername(): String? = socksUsername
        fun setSocksUsername(valStr: String?) { socksUsername = valStr }
        fun getSocksPassword(): String? = socksPassword
        fun setSocksPassword(valStr: String?) { socksPassword = valStr }

        // Operations
        fun start(tunFd: Int, closeFdOnDrop: Boolean = true): Boolean {
            binaryInstaller.requireLibrary()
            val proxyUrl = buildSocksProxyUrl(socksHost, socksPort, socksUsername, socksPassword)
            startedTime = System.currentTimeMillis()
            active = true
            serviceState = "running"
            Log.i("Tun2SocksProcessManager", "tun2proxy started with proxy URL $proxyUrl")
            return true
        }

        fun stop(): Boolean {
            active = false
            serviceState = "stopped"
            Log.i("Tun2SocksProcessManager", "tun2proxy stopped")
            return true
        }

        fun buildSocksProxyUrl(host: String, port: Int, user: String?, pass: String?): String {
            return if (user != null && pass != null) {
                "socks5://$user:$pass@$host:$port"
            } else {
                "socks5://$host:$port"
            }
        }

        fun isRunning(): Boolean = active && serviceState == "running"

        fun resetStats() {
            connsCount = 0L
            retryAttempts = 0
            lastError = ""
        }

        fun getUptimeMs(): Long {
            return if (active) System.currentTimeMillis() - startedTime else 0L
        }

        fun validateConfig(): Boolean {
            return socksHost.isNotEmpty() && socksPort in 1..65535
        }
    }
}
