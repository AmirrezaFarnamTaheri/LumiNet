package com.luminet.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import com.luminet.mobilebind.Mobilebind
import com.luminet.mobilebind.SocketProtector
import com.luminet.mobilebind.VPNEngine
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Canonical LumiNet Android VPN lifecycle.
 *
 * Android owns the TUN only until [android.os.ParcelFileDescriptor.detachFd]
 * succeeds. The detached descriptor is then transferred exactly once to the
 * generated gomobile [VPNEngine], whose Go runtime owns both the proxy core and
 * userspace TUN adapter until startup fails or [stopVpn] completes.
 */
class VpnEngineService : VpnService() {

    private val running = AtomicBoolean(false)
    private var engine: VPNEngine? = null
    private var underlyingNetworkTracker: UnderlyingNetworkTracker? = null
    private val socketProtector = object : SocketProtector {
        override fun protect(fd: Long): Boolean = this@VpnEngineService.protect(fd.toInt())
    }
    private var socketProtectorRegistered = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        if (running.get()) {
            _runtimeState.update { VpnRuntimeState(VpnRuntimeStage.CONNECTED) }
            return START_STICKY
        }

        _runtimeState.update { VpnRuntimeState(VpnRuntimeStage.STARTING) }
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.vpn_notification_starting)))
        return if (startVpnTunnel()) START_STICKY else START_NOT_STICKY
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn(preserveError = runtimeState.value.stage == VpnRuntimeStage.ERROR)
        super.onDestroy()
    }

    private fun startVpnTunnel(): Boolean {
        val candidate = VPNEngine()
        try {
            val builder = Builder()
                .setSession("LumiNet")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, VPN_ADDRESS_PREFIX)
                .addRoute(VPN_ROUTE, VPN_ROUTE_PREFIX)
                .addDnsServer(InetAddress.getByName(VPN_DNS))
                .setBlocking(true)

            // Per-app policy is mobile-local authority because only Android's
            // VpnService.Builder can enforce package selection. Validation is
            // complete before Builder mutation, and platform errors fail tunnel
            // startup closed instead of silently applying a partial package set.
            PerAppVpnPolicyStore.load(this).applyTo(builder, packageName)

            val pfd = builder.establish()
                ?: throw IllegalStateException("VPN tunnel establishment failed")

            // Ownership transfers to Go here. Do not close this raw descriptor
            // from Kotlin after detachFd(), even if Start throws: StartLoop owns
            // and closes every transferred descriptor on all failure paths.
            val tunFd = pfd.detachFd()
            registerSocketProtector()
            underlyingNetworkTracker = UnderlyingNetworkTracker(this).also { it.start() }
            candidate.start(tunFd, "")

            engine = candidate
            running.set(true)
            _runtimeState.update { VpnRuntimeState(VpnRuntimeStage.CONNECTED) }
            updateNotification(getString(R.string.vpn_notification_active))
            return true
        } catch (ex: Exception) {
            runCatching { candidate.stop() }
            stopUnderlyingNetworkTracker()
            unregisterSocketProtector()
            running.set(false)
            _runtimeState.update {
                VpnRuntimeState(
                    stage = VpnRuntimeStage.ERROR,
                    failureCode = classifyFailureCode(ex),
                )
            }
            updateNotification(getString(R.string.vpn_notification_failed))
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return false
        }
    }

    private fun stopVpn(preserveError: Boolean = false) {
        if (!running.get() && engine == null) {
            if (!preserveError) {
                _runtimeState.update { VpnRuntimeState(VpnRuntimeStage.IDLE) }
            }
            return
        }
        if (!preserveError) {
            _runtimeState.update { VpnRuntimeState(VpnRuntimeStage.STOPPING) }
        }
        running.set(false)
        val current = engine
        engine = null
        if (current != null) {
            runCatching { current.stop() }
        }
        stopUnderlyingNetworkTracker()
        unregisterSocketProtector()
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (!preserveError) {
            _runtimeState.update { VpnRuntimeState(VpnRuntimeStage.IDLE) }
        }
        stopSelf()
    }

    private fun classifyFailureCode(ex: Exception): String = when (ex) {
        is SecurityException -> "permission_or_policy"
        is IllegalArgumentException -> "invalid_configuration"
        is IllegalStateException -> "tunnel_establishment_failed"
        else -> "engine_start_failed"
    }

    private fun stopUnderlyingNetworkTracker() {
        underlyingNetworkTracker?.stop()
        underlyingNetworkTracker = null
    }

    private fun registerSocketProtector() {
        if (socketProtectorRegistered) return
        Mobilebind.registerSocketProtector(socketProtector)
        socketProtectorRegistered = true
    }

    private fun unregisterSocketProtector() {
        if (!socketProtectorRegistered) return
        Mobilebind.registerSocketProtector(null)
        socketProtectorRegistered = false
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.vpn_notification_channel_description)
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, VpnEngineService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.vpn_notification_stop), stopIntent)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            ?.notify(NOTIFICATION_ID, buildNotification(text))
    }


    companion object {
        const val ACTION_STOP = "com.luminet.android.STOP_VPN"
        private const val CHANNEL_ID = "luminet_vpn_channel"
        private const val NOTIFICATION_ID = 1001
        private const val VPN_DNS = "1.1.1.1"
        private const val VPN_ADDRESS = "10.88.0.2"
        private const val VPN_ADDRESS_PREFIX = 30
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_ROUTE_PREFIX = 0
        private const val VPN_MTU = 1500

        private val _runtimeState = MutableStateFlow(VpnRuntimeState())
        val runtimeState: StateFlow<VpnRuntimeState> = _runtimeState.asStateFlow()

    }
}
