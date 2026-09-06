/******************************************************************************
 *                                                                            *
 * Copyright (C) 2026 LumiNet Project Authors                                 *
 * Ported from: outline-go-tun2socks-demo/app/src/main/java/app/hankdev...     *
 *                                                                            *
 ******************************************************************************/

package com.maybeknott.luminet.internal.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.content.ContextCompat
import com.luminet.android.R
import java.io.IOException

class OutlineVpnService : VpnService() {
    companion object {
        private const val TAG = "OutlineVpnService"
        const val ACTION_START = "action.start"
        const val ACTION_STOP = "action.stop"

        private const val NOTIFICATION_CHANNEL_ID = "outline-vpn"
        private const val NOTIFICATION_COLOR = 0x00BFA5
        private const val NOTIFICATION_SERVICE_ID = 1

        private const val VPN_INTERFACE_PRIVATE_LAN = "10.111.222.1"
        private const val VPN_INTERFACE_PREFIX_LENGTH = 24
        private const val VPN_INTERFACE_MTU = 1500

        fun start(context: Context) {
            val intent = Intent(context, OutlineVpnService::class.java).apply {
                action = ACTION_START
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, OutlineVpnService::class.java))
        }
    }

    private var isRunning = false
    private var tunFd: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand")
        when (intent?.action) {
            ACTION_START -> if (!isRunning) startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        Log.i(TAG, "Starting VPN service tunnel")
        try {
            val builder = Builder()
                .setSession("LumiNet VPN")
                .setMtu(VPN_INTERFACE_MTU)
                .addAddress(VPN_INTERFACE_PRIVATE_LAN, VPN_INTERFACE_PREFIX_LENGTH)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setBlocking(true)
                .addDisallowedApplication(packageName)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val established = builder.establish()
            if (established == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            tunFd = established
            isRunning = true
            Log.i(TAG, "VPN interface established with fd: ${established.fd}")
            // The descriptor is passed to the Go mobile binding when that runtime is packaged.
            startForegroundWithNotification()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN: ${e.message}", e)
            closeTunnel()
            stopSelf()
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping VPN service tunnel")
        closeTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeTunnel() {
        try {
            tunFd?.close()
        } catch (e: IOException) {
            Log.e(TAG, "Failed to close TUN fd: ${e.message}")
        } finally {
            tunFd = null
            isRunning = false
        }
    }

    private fun startForegroundWithNotification() {
        val notification = getNotificationBuilder()
            .setContentText("LumiNet Proxy Active")
            .build()
        startForeground(NOTIFICATION_SERVICE_ID, notification)
    }

    private fun getNotificationBuilder(): Notification.Builder {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "LumiNet",
                NotificationManager.IMPORTANCE_LOW,
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }).apply {
            setSmallIcon(R.drawable.ic_luminet_status)
            setContentTitle("LumiNet VPN Connection")
            setColor(NOTIFICATION_COLOR)
            setContentIntent(pendingIntent)
            setShowWhen(true)
            setUsesChronometer(true)
            setOngoing(true)
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.i(TAG, "VPN permission revoked")
        stopVpn()
    }

    override fun onDestroy() {
        closeTunnel()
        Log.i(TAG, "onDestroy")
        super.onDestroy()
    }
}
