/******************************************************************************
 *                                                                            *
 * Copyright (C) 2026 LumiNet Project Authors                                 *
 * Ported from: Exclave-dev/app/src/main/java/io/nekohasekai/sagernet/utils  *
 *                                                                            *
 ******************************************************************************/

package com.maybeknott.luminet.internal.mobile

import android.annotation.TargetApi
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.channels.actor
import kotlinx.coroutines.runBlocking
import java.net.UnknownHostException

object DefaultNetworkListener {
    private sealed class NetworkMessage {
        class Start(val key: Any, val listener: (Network?) -> Unit) : NetworkMessage()
        class Get : NetworkMessage() {
            val response = CompletableDeferred<Network>()
        }
        class Stop(val key: Any) : NetworkMessage()
        class Put(val network: Network) : NetworkMessage()
        class Update(val network: Network) : NetworkMessage()
        class Lost(val network: Network) : NetworkMessage()
    }

    private lateinit var connectivityManager: ConnectivityManager

    fun initialize(manager: ConnectivityManager) {
        connectivityManager = manager
    }

    private val networkActor = GlobalScope.actor<NetworkMessage>(Dispatchers.Unconfined) {
        val listeners = mutableMapOf<Any, (Network?) -> Unit>()
        var network: Network? = null
        val pendingRequests = arrayListOf<NetworkMessage.Get>()
        for (message in channel) when (message) {
            is NetworkMessage.Start -> {
                if (listeners.isEmpty()) register()
                listeners[message.key] = message.listener
                if (network != null) message.listener(network)
            }
            is NetworkMessage.Get -> {
                check(listeners.isNotEmpty()) { "Getting network without any listeners is not supported" }
                if (network == null) pendingRequests += message else message.response.complete(
                    network
                )
            }
            is NetworkMessage.Stop -> if (listeners.isNotEmpty() &&
                listeners.remove(message.key) != null && listeners.isEmpty()
            ) {
                network = null
                unregister()
            }
            is NetworkMessage.Put -> {
                network = message.network
                pendingRequests.forEach { it.response.complete(message.network) }
                pendingRequests.clear()
                listeners.values.forEach { it(network) }
            }
            is NetworkMessage.Update -> if (network == message.network) listeners.values.forEach {
                it(network)
            }
            is NetworkMessage.Lost -> if (network == message.network) {
                network = null
                listeners.values.forEach { it(null) }
            }
        }
    }

    suspend fun start(key: Any, listener: (Network?) -> Unit) =
        networkActor.send(NetworkMessage.Start(key, listener))

    suspend fun get() = if (fallback) @TargetApi(23) {
        connectivityManager.activeNetwork ?: throw UnknownHostException()
    } else NetworkMessage.Get().run {
        networkActor.send(this)
        response.await()
    }

    suspend fun stop(key: Any) = networkActor.send(NetworkMessage.Stop(key))

    var ssid: String? = null

    private val Callback: ConnectivityManager.NetworkCallback = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        object: ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
            override fun onAvailable(network: Network) =
                runBlocking { networkActor.send(NetworkMessage.Put(network)) }

            override fun onCapabilitiesChanged(
                network: Network, networkCapabilities: NetworkCapabilities
            ) {
                if (networkCapabilities.transportInfo is WifiInfo) {
                    val wifiInfo = networkCapabilities.transportInfo as WifiInfo
                    ssid = wifiInfo.ssid
                }
                runBlocking { networkActor.send(NetworkMessage.Update(network)) }
            }

            override fun onLost(network: Network) =
                runBlocking { networkActor.send(NetworkMessage.Lost(network)) }
        }
    } else {
        object: ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) =
                runBlocking { networkActor.send(NetworkMessage.Put(network)) }

            override fun onCapabilitiesChanged(
                network: Network, networkCapabilities: NetworkCapabilities
            ) {
                runBlocking { networkActor.send(NetworkMessage.Update(network)) }
            }

            override fun onLost(network: Network) =
                runBlocking { networkActor.send(NetworkMessage.Lost(network)) }
        }
    }

    private var fallback = false
    private val request = NetworkRequest.Builder().apply {
        addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        if (Build.VERSION.SDK_INT == 23) {
            removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            removeCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
        }
    }.build()
    private val mainHandler = Handler(Looper.getMainLooper())

    private fun register() {
        try {
            fallback = false
            when (Build.VERSION.SDK_INT) {
                in 31..Int.MAX_VALUE -> @TargetApi(31) {
                    connectivityManager.registerBestMatchingNetworkCallback(
                        request, Callback, mainHandler
                    )
                }
                in 28 until 31 -> @TargetApi(28) {
                    connectivityManager.requestNetwork(request, Callback, mainHandler)
                }
                in 26 until 28 -> @TargetApi(26) {
                    connectivityManager.registerDefaultNetworkCallback(Callback, mainHandler)
                }
                in 24 until 26 -> @TargetApi(24) {
                    connectivityManager.registerDefaultNetworkCallback(Callback)
                }
                else -> {
                    connectivityManager.requestNetwork(request, Callback)
                }
            }
        } catch (e: Exception) {
            fallback = true
        }
    }

    private fun unregister() = connectivityManager.unregisterNetworkCallback(Callback)
}
