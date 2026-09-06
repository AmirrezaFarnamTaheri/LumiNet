package com.maybeknott.luminet.internal.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.luminet.android.R
import java.io.IOException

/**
 * Coordinates the WhiteDNS foreground VPN tunnel.
 *
 * The Android 14+ foreground-service type matches the manifest's `specialUse`
 * declaration instead of requesting the restricted `systemExempted` type.
 */
class WhiteDnsVpnService : VpnService() {

    companion object {
        private const val TAG = "WhiteDnsVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "whitedns-vpn"
        private const val NOTIFICATION_ID = 9911

        fun startService(context: Context) {
            val intent = Intent(context, WhiteDnsVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopService(context: Context) {
            context.stopService(Intent(context, WhiteDnsVpnService::class.java))
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        Log.i(TAG, "WhiteDnsVpnService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_luminet_status)
            .setContentTitle("LumiNet Safe DNS Protection")
            .setContentText("DNS routing and VPN tunnel active")
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        if (!establishTunnel()) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        return START_STICKY
    }

    private fun establishTunnel(): Boolean {
        return try {
            vpnInterface?.close()
            vpnInterface = Builder()
                .setSession("LumiNet WhiteDNS Tunnel")
                .addAddress("10.10.10.1", 30)
                .addDnsServer("127.0.0.1")
                .addRoute("0.0.0.0", 0)
                .establish()

            val established = vpnInterface
            if (established == null) {
                Log.e(TAG, "VPN builder returned no tunnel interface")
                false
            } else {
                Log.i(TAG, "VPN tunnel interface established: ${established.fileDescriptor}")
                true
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN interface", e)
            false
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "LumiNet VPN Channel",
                NotificationManager.IMPORTANCE_LOW,
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Failed to close WhiteDNS tunnel", e)
        } finally {
            vpnInterface = null
        }
        Log.i(TAG, "WhiteDnsVpnService stopped")
        super.onDestroy()
    }
}
