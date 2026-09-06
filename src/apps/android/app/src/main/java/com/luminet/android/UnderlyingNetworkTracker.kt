package com.luminet.android

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService

/**
 * Passive physical-network tracker for the Android VPN.
 *
 * Socket protection remains the authority for keeping LumiNet's outbound sockets
 * outside its own VPN. This helper only tells Android which non-VPN network
 * currently underlies the tunnel so interface/capability accounting stays
 * truthful across Wi-Fi/cellular hand-offs. It deliberately uses a passive
 * callback rather than requestNetwork(), which could keep a radio active.
 */
internal class UnderlyingNetworkTracker(
    private val vpnService: VpnService,
    private val connectivity: ConnectivityManager =
        vpnService.getSystemService(ConnectivityManager::class.java),
) {
    private val lock = Any()
    private val candidates = mutableMapOf<Network, NetworkCapabilities>()
    private var started = false
    private var appliedHandle = UNAPPLIED_HANDLE

    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            refresh(network)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            updateCandidate(network, capabilities)
        }

        override fun onLost(network: Network) {
            synchronized(lock) {
                candidates.remove(network)
            }
            applyBestCandidate()
        }
    }

    /**
     * Starts passive observation. Failure is intentionally non-fatal because
     * VpnService.protect() remains the routing-safety owner.
     */
    fun start(): Boolean {
        synchronized(lock) {
            if (started) return true
        }

        val registered = runCatching {
            connectivity.registerNetworkCallback(request, callback)
        }.isSuccess
        if (!registered) return false

        synchronized(lock) {
            started = true
        }

        // Seed state after registration so an event racing with this snapshot is
        // still followed by a callback and converges to the latest capabilities.
        runCatching { connectivity.allNetworks.toList() }
            .getOrDefault(emptyList())
            .forEach(::refresh)
        applyBestCandidate()
        return true
    }

    fun stop() {
        val shouldUnregister = synchronized(lock) {
            if (!started) {
                false
            } else {
                started = false
                candidates.clear()
                appliedHandle = UNAPPLIED_HANDLE
                true
            }
        }
        if (shouldUnregister) {
            runCatching { connectivity.unregisterNetworkCallback(callback) }
        }
        // null means that LumiNet no longer asserts an underlying network.
        runCatching { vpnService.setUnderlyingNetworks(null) }
    }

    private fun refresh(network: Network) {
        val capabilities = runCatching { connectivity.getNetworkCapabilities(network) }.getOrNull()
        if (capabilities == null) {
            synchronized(lock) {
                candidates.remove(network)
            }
            applyBestCandidate()
            return
        }
        updateCandidate(network, capabilities)
    }

    private fun updateCandidate(network: Network, capabilities: NetworkCapabilities) {
        synchronized(lock) {
            if (!started) return
            if (isPhysicalInternet(capabilities)) {
                candidates[network] = NetworkCapabilities(capabilities)
            } else {
                candidates.remove(network)
            }
        }
        applyBestCandidate()
    }

    private fun applyBestCandidate() {
        val selected = synchronized(lock) {
            if (!started) return
            chooseBestCandidate(candidates, runCatching { connectivity.activeNetwork }.getOrNull())
        }
        val selectedHandle = selected?.networkHandle ?: NO_NETWORK_HANDLE

        val changed = synchronized(lock) {
            started && appliedHandle != selectedHandle
        }
        if (!changed) return

        val applied = runCatching {
            if (selected == null) {
                vpnService.setUnderlyingNetworks(null)
            } else {
                vpnService.setUnderlyingNetworks(arrayOf(selected))
            }
        }.isSuccess
        if (applied) {
            synchronized(lock) {
                if (started) appliedHandle = selectedHandle
            }
        }
    }

    companion object {
        private const val UNAPPLIED_HANDLE = Long.MIN_VALUE
        private const val NO_NETWORK_HANDLE = Long.MIN_VALUE + 1

        private fun isPhysicalInternet(capabilities: NetworkCapabilities): Boolean =
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

        /**
         * Prefer the system-active physical network when it is still visible;
         * otherwise prefer validated, non-suspended connectivity. The stable
         * network handle is only a deterministic tie-breaker, never a quality
         * claim.
         */
        private fun chooseBestCandidate(
            candidates: Map<Network, NetworkCapabilities>,
            activeNetwork: Network?,
        ): Network? {
            if (activeNetwork != null && activeNetwork in candidates) return activeNetwork

            return candidates.entries
                .sortedWith(
                    compareByDescending<Map.Entry<Network, NetworkCapabilities>> {
                        it.value.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    }.thenByDescending {
                        it.value.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
                    }.thenByDescending {
                        it.value.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                    }.thenBy { it.key.networkHandle },
                )
                .firstOrNull()
                ?.key
        }
    }
}
