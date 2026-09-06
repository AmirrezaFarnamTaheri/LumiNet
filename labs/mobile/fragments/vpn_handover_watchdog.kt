/******************************************************************************
 *                                                                            *
 * Copyright (C) 2026 LumiNet Project Authors                                 *
 * Subsystem: Mobile Platform Integration (Android VPN Handover & Watchdog)    *
 *                                                                            *
 ******************************************************************************/

package com.maybeknott.luminet.internal.mobile

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Generation-indexed session state machine ensuring stale background workers
 * or delayed timeout threads do not corrupt subsequent active connection lifecycles.
 */
class VpnGenerationTracker {
    private val currentGeneration = AtomicLong(1L)

    /**
     * Increments the generation and returns the newly active session ID.
     */
    fun nextGeneration(): Long = currentGeneration.incrementAndGet()

    /**
     * Current active generation counter.
     */
    fun current(): Long = currentGeneration.get()

    /**
     * Validates whether a running task belongs to the currently active generation.
     */
    fun isCurrent(expected: Long): Boolean = currentGeneration.get() == expected
}

/**
 * Network interface change listener providing zero-downtime handover between
 * Wi-Fi, Cellular, and Ethernet networks.
 */
class VpnNetworkHandoverManager(
    private val connectivityManager: ConnectivityManager,
    private val onNetworkSwitched: (Network, isHandover: Boolean) -> Unit,
    private val onAllNetworksLost: () -> Unit
) {
    private val availableNetworks: MutableSet<Network> = ConcurrentHashMap.newKeySet()
    private val activeNetwork = AtomicLong(0L)
    private var callbackRegistered = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val wasEmpty = availableNetworks.isEmpty()
            availableNetworks.add(network)
            val isHandover = !wasEmpty
            onNetworkSwitched(network, isHandover)
        }

        override fun onLost(network: Network) {
            availableNetworks.remove(network)
            if (availableNetworks.isEmpty()) {
                onAllNetworksLost()
            } else {
                // Seamlessly promote remaining available network
                availableNetworks.firstOrNull()?.let { alternate ->
                    onNetworkSwitched(alternate, true)
                }
            }
        }
    }

    /**
     * Registers active network change monitoring.
     */
    fun startMonitoring() {
        if (!callbackRegistered) {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                .build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
            callbackRegistered = true
        }
    }

    /**
     * Safely unregisters the network callback.
     */
    fun stopMonitoring() {
        if (callbackRegistered) {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback)
            } catch (_: Exception) {}
            callbackRegistered = false
            availableNetworks.clear()
        }
    }

    /**
     * Returns the count of currently available upstream interfaces.
     */
    fun availableNetworkCount(): Int = availableNetworks.size
}

/**
 * Health monitor probing local SOCKS5 loopback bridges and active tunnel endpoints.
 */
class VpnDualStageHealthMonitor(
    private val socksHost: String = "127.0.0.1",
    private val socksPort: Int = 1080,
    private val timeoutMs: Int = 3000,
    private val maxConsecutiveFailures: Int = 3,
    private val onHealthRestored: () -> Unit,
    private val onUnrecoverableFailure: (consecutiveErrors: Int) -> Unit
) {
    private val consecutiveFailures = AtomicLong(0L)
    private val isProbing = AtomicBoolean(false)

    /**
     * Executes an active probe against the local SOCKS5 tunnel ingress.
     */
    fun runProbe(generation: Long, tracker: VpnGenerationTracker): Boolean {
        if (!tracker.isCurrent(generation)) return false
        if (!isProbing.compareAndSet(false, true)) return true

        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(socksHost, socksPort), timeoutMs)
                // SOCKS5 greeting: 0x05 0x01 0x00
                socket.getOutputStream().write(byteArrayOf(0x05, 0x01, 0x00))
                socket.soTimeout = timeoutMs
                val resp = ByteArray(2)
                val read = socket.getInputStream().read(resp)
                val ok = read == 2 && resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()

                if (!tracker.isCurrent(generation)) return false

                if (ok) {
                    if (consecutiveFailures.getAndSet(0L) > 0) {
                        onHealthRestored()
                    }
                    true
                } else {
                    handleFailure(generation, tracker)
                    false
                }
            }
        } catch (_: Exception) {
            if (tracker.isCurrent(generation)) {
                handleFailure(generation, tracker)
            }
            false
        } finally {
            isProbing.set(false)
        }
    }

    private fun handleFailure(generation: Long, tracker: VpnGenerationTracker) {
        if (!tracker.isCurrent(generation)) return
        val failures = consecutiveFailures.incrementAndGet()
        if (failures >= maxConsecutiveFailures) {
            onUnrecoverableFailure(failures.toInt())
        }
    }

    fun reset() {
        consecutiveFailures.set(0L)
        isProbing.set(false)
    }
}

/**
 * Standard parameters for platform TUN interface configuration.
 */
data class VpnRoutingParameters(
    val tunInterfaceName: String = "LumiTun",
    val mtu: Int = 1400,
    val ipv4Address: String = "172.19.0.1",
    val ipv4Prefix: Int = 30,
    val ipv6Address: String = "fdfe:dcba:9876::1",
    val ipv6Prefix: Int = 126,
    val killSwitch: Boolean = false,
    val dnsServers: List<String> = listOf("1.1.1.1", "1.0.0.1"),
    val splitIncludedApps: Set<String> = emptySet(),
    val splitExcludedApps: Set<String> = emptySet()
) {
    init {
        require(mtu in 1280..9000) { "MTU must be within [1280, 9000]" }
    }
}
