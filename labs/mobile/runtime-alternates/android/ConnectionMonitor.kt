// Ported from: IPRadar2ForLinux-main / ipscan-master
// Target path: desktop/android/ConnectionMonitor.kt

package com.luminet.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Build
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.abs

/**
 * Real-time network connection monitor for LumiNet Android.
 *
 * Monitors:
 *  - Network type changes (WiFi / mobile / VPN / none).
 *  - Round-trip latency to a configurable target host.
 *  - Upload/download byte counters via [TrafficStats].
 *  - IP Scanner integration: sweeps a /24 subnet for live hosts via TCP SYN.
 *
 * Ported from IPRadar2ForLinux-main and ipscan-master connectivity probing logic.
 */
class ConnectionMonitor(private val context: Context) {

    companion object {
        private const val TAG = "ConnectionMonitor"
        private const val PROBE_INTERVAL_MS = 5_000L
        private const val TCP_PROBE_TIMEOUT_MS = 2_000
        private const val DEFAULT_PROBE_HOST = "cloudflare.com"
        private const val DEFAULT_PROBE_PORT = 443
        private const val JITTER_WINDOW_SIZE = 10
    }

    // ── Network State ─────────────────────────────────────────────────────────

    /** Current network type observed by the [ConnectivityManager]. */
    enum class NetworkType { NONE, WIFI, MOBILE, VPN, ETHERNET, UNKNOWN }

    data class NetworkSnapshot(
        val type: NetworkType,
        val latencyMs: Long,
        val jitterMs: Long,
        val rxBytes: Long,
        val txBytes: Long,
        val isVpnActive: Boolean,
    )

    private val _networkState = MutableStateFlow(NetworkSnapshot(
        type = NetworkType.NONE,
        latencyMs = -1,
        jitterMs = 0,
        rxBytes = 0,
        txBytes = 0,
        isVpnActive = false,
    ))
    val networkState: StateFlow<NetworkSnapshot> get() = _networkState

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val monitoring = AtomicBoolean(false)
    private val latencyHistory = ArrayDeque<Long>(JITTER_WINDOW_SIZE)
    private var baselineRx = AtomicLong(0)
    private var baselineTx = AtomicLong(0)

    // ── Network Callback ──────────────────────────────────────────────────────

    private val connectivityManager: ConnectivityManager
        get() = context.getSystemService(ConnectivityManager::class.java)

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d(TAG, "Network available: ${network.networkHandle}")
            updateNetworkType()
        }

        override fun onLost(network: Network) {
            Log.d(TAG, "Network lost: ${network.networkHandle}")
            emit(networkType = NetworkType.NONE, latencyMs = -1, jitterMs = 0)
        }

        override fun onCapabilitiesChanged(network: Network, nc: NetworkCapabilities) {
            updateNetworkType()
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /** Starts the connection monitor and background probing. */
    fun start() {
        if (!monitoring.compareAndSet(false, true)) return

        baselineRx.set(TrafficStats.getTotalRxBytes())
        baselineTx.set(TrafficStats.getTotalTxBytes())

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, networkCallback)

        scope.launch { probingLoop() }
        Log.i(TAG, "ConnectionMonitor started")
    }

    /** Stops monitoring and releases resources. */
    fun stop() {
        monitoring.set(false)
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {}
        scope.cancel()
        Log.i(TAG, "ConnectionMonitor stopped")
    }

    // ── Probing ───────────────────────────────────────────────────────────────

    private suspend fun probingLoop() {
        while (monitoring.get() && isActive) {
            val (latency, success) = measureLatency(DEFAULT_PROBE_HOST, DEFAULT_PROBE_PORT)
            val jitter = if (success) computeJitter(latency) else 0L
            val rx = TrafficStats.getTotalRxBytes() - baselineRx.get()
            val tx = TrafficStats.getTotalTxBytes() - baselineTx.get()
            val type = currentNetworkType()
            val vpnActive = isVpnConnected()

            _networkState.value = NetworkSnapshot(
                type = type,
                latencyMs = if (success) latency else -1L,
                jitterMs = jitter,
                rxBytes = rx.coerceAtLeast(0),
                txBytes = tx.coerceAtLeast(0),
                isVpnActive = vpnActive,
            )

            delay(PROBE_INTERVAL_MS)
        }
    }

    /**
     * Measures TCP connection latency to [host]:[port].
     *
     * Returns `(latencyMs, success)`.
     */
    fun measureLatency(host: String, port: Int): Pair<Long, Boolean> {
        return try {
            val start = System.nanoTime()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), TCP_PROBE_TIMEOUT_MS)
            }
            val elapsed = (System.nanoTime() - start) / 1_000_000
            Pair(elapsed, true)
        } catch (ex: Exception) {
            Log.d(TAG, "Probe failed to $host:$port — ${ex.message}")
            Pair(-1L, false)
        }
    }

    /**
     * Computes jitter as the mean absolute deviation of [JITTER_WINDOW_SIZE]
     * recent latency measurements.
     */
    private fun computeJitter(latencyMs: Long): Long {
        synchronized(latencyHistory) {
            if (latencyHistory.size >= JITTER_WINDOW_SIZE) {
                latencyHistory.removeFirst()
            }
            latencyHistory.addLast(latencyMs)
            if (latencyHistory.size < 2) return 0L
            val mean = latencyHistory.average()
            return (latencyHistory.sumOf { abs(it - mean.toLong()) } / latencyHistory.size)
        }
    }

    // ── IP Scanner ────────────────────────────────────────────────────────────

    /**
     * Scans a /24 subnet for reachable hosts by attempting TCP connections
     * on [port] with a short timeout.
     *
     * @param subnetPrefix e.g. `"192.168.1"` — scans `192.168.1.1`–`192.168.1.254`.
     * @param port TCP port to probe (default 80).
     * @return List of live host IPs found.
     */
    suspend fun scanSubnet(subnetPrefix: String, port: Int = 80): List<String> {
        val live = mutableListOf<String>()
        val jobs = (1..254).map { i ->
            scope.async {
                val ip = "$subnetPrefix.$i"
                val (_, ok) = measureLatency(ip, port)
                if (ok) ip else null
            }
        }
        jobs.awaitAll().filterNotNullTo(live)
        return live.sorted()
    }

    // ── Network Type Helpers ──────────────────────────────────────────────────

    private fun currentNetworkType(): NetworkType {
        val cm = connectivityManager
        val active = cm.activeNetwork ?: return NetworkType.NONE
        val caps = cm.getNetworkCapabilities(active) ?: return NetworkType.NONE
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> NetworkType.VPN
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.MOBILE
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            else -> NetworkType.UNKNOWN
        }
    }

    private fun isVpnConnected(): Boolean {
        val cm = connectivityManager
        val active = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(active) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun updateNetworkType() {
        val type = currentNetworkType()
        val vpnActive = isVpnConnected()
        val current = _networkState.value
        _networkState.value = current.copy(type = type, isVpnActive = vpnActive)
    }

    private fun emit(networkType: NetworkType, latencyMs: Long, jitterMs: Long) {
        _networkState.value = _networkState.value.copy(
            type = networkType,
            latencyMs = latencyMs,
            jitterMs = jitterMs,
        )
    }
}
