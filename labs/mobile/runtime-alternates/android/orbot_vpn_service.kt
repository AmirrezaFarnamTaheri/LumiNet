// Ported from: orbot-android-master / Tor_Onion_Proxy_Library-master (Projects 019, 028)
// Target path: desktop/android/orbot_vpn_service.kt
//
// Kotlin VpnService that wraps a native Tor child process:
//  1. Unpacks architecture-specific (arm64-v8a, armeabi-v7a, x86_64) Tor
//     binaries from the application's `assets/` overlay into the app's
//     private data directory and marks them executable.
//  2. Spawns the Tor binary with auto-generated torrc (SocksPort 9050,
//     ControlPort 9051, CookieAuthentication 1).
//  3. Pipes the Tor child process's stdout/stderr into the Android log
//     monitoring channel (`Log.i`) so the UI surface stays debuggable.
//  4. Leverages the `hev-socks5-tunnel` JNI interface to forward raw
//     TUN interface socket frames directly to `127.0.0.1:9050` so all
//     device traffic flows through Tor's SOCKS5 listener.
//
// Relies on:
//   - `com.luminet.android.jni.HevSocks5Tunnel` (NDK .so) being loaded by
//     `System.loadLibrary("hevsocks5tunnel")` during Application start.
//   - `VpnEngineService` providing a stable TUN FD (its `stableNativeFd`
//     is forwarded as the JNI tunnel's tun_fd argument).

package com.luminet.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.res.AssetManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * VpnService that owns the Tor child process lifecycle.
 *
 * Lifecycle:
 *   - [onStartCommand] receives [ACTION_START] -> unpack binary, spawn Tor,
 *     start the VPN tunnel, start the hev-socks5-tunnel JNI bridge.
 *   - [onDestroy]/[onRevoke] -> stop everything in reverse order, kill the
 *     Tor process, close the TUN FD, release the JNI tunnel.
 */
class OrbotVpnService : VpnService() {

    companion object {
        private const val TAG = "OrbotVpnService"
        private const val CHANNEL_ID = "luminet_orbot_channel"
        private const val NOTIFICATION_ID = 1002

        private const val ACTION_START = "com.luminet.android.orbot.START"
        private const val ACTION_STOP = "com.luminet.android.orbot.STOP"

        /** Relative path inside `assets/` where arch-specific Tor binaries live. */
        private const val ASSET_TOR_PREFIX = "tor/"

        /** Tor SOCKS5 listener port inside the VPN tunnel. */
        private const val TOR_SOCKS_PORT = 9050
        /** Tor control port. */
        private const val TOR_CONTROL_PORT = 9051
        /** 30-second timeout waiting for the SOCKS port to accept connections. */
        private const val SOCKS_BOOT_TIMEOUT_MS = 30_000L

        @Volatile
        private var instance: OrbotVpnService? = null

        /** Returns the active Orbot VPN service instance, or null when stopped. */
        fun get(): OrbotVpnService? = instance
    }

    private val running = AtomicBoolean(false)
    private val tunFd = AtomicReference<ParcelFileDescriptor?>(null)
    private val torProcess = AtomicReference<Process?>(null)
    private var jniTunnelHandle: Long = 0L

    // -------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startEngine()
            ACTION_STOP -> { stopEngine(); stopSelf() }
            else -> {
                // Default to start so a freshly-booted foreground-service
                // intent still brings the engine up.
                startEngine()
            }
        }
        return START_STICKY
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onDestroy() {
        stopEngine()
        instance = null
        super.onDestroy()
    }

    override fun onRevoke() {
        // System or user revoked the VPN consent — terminate immediately.
        stopEngine()
        stopSelf()
    }

    // -------------------------------------------------------------------
    // Engine start/stop
    // -------------------------------------------------------------------

    private fun startEngine() {
        if (!running.compareAndSet(false, true)) return
        startForeground(NOTIFICATION_ID, buildNotification("Tor VPN starting"))

        try {
            val torBinary = ensureTorBinary()
            val configFile = writeTorrc()
            val process = spawnTor(torBinary, configFile)
            torProcess.set(process)
            waitForSocks()

            // Establish the VPN TUN interface; reads the FD inherited by the
            // hev-socks5-tunnel JNI bridge.
            val pfd = establishVpn()
            tunFd.set(pfd)
            val fd = pfd?.detachFd() ?: -1

            // Bring up the JNI socks5-tunnel: every TUN frame is wrapped by
            // the NDK side into a SOCKS5 CONNECT toward 127.0.0.1:9050.
            jniTunnelHandle = HevSocks5TunnelBridge.tunnelStart(fd, "127.0.0.1", TOR_SOCKS_PORT)
            if (jniTunnelHandle == 0L) {
                throw IllegalStateException("hev-socks5-tunnel JNI initialization failed")
            }

            updateNotification("Tor VPN active · SOCKS5 127.0.0.1:$TOR_SOCKS_PORT")
        } catch (t: Throwable) {
            Log.e(TAG, "startEngine failed", t)
            stopEngine()
            stopSelf()
        }
    }

    private fun stopEngine() {
        if (!running.compareAndSet(true, false)) return

        if (jniTunnelHandle != 0L) {
            HevSocks5TunnelBridge.tunnelStop(jniTunnelHandle)
            jniTunnelHandle = 0L
        }
        torProcess.getAndSet(null)?.let { p ->
            p.destroy()
            if (!p.waitFor(2_000, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                p.destroyForcibly()
            }
        }
        tunFd.getAndSet(null)?.let { runCatching { it.close() } }
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // -------------------------------------------------------------------
    // Asset-to-disk Tor binary unpacking
    // -------------------------------------------------------------------

    /**
     * Unpacks the architecture-specific Tor binary from `assets/tor/<abi>/tor`
     * into `filesDir/tor/bin/tor`, marks it executable, and returns the path.
     *
     * Skips work if the binary is already present and from the same APK
     * version — a simple sample marker file pairs the version. ponytail: real
     * Armed-only build would compute SHA-256 + signature; add verifiers when
     * shipping.
     */
    private fun ensureTorBinary(): String {
        val abi = pickSupportedAbi()
        val assetPath = "$ASSET_TOR_PREFIX$abi/tor"
        val outDir = File(filesDir, "tor/bin").apply { mkdirs() }
        val outFile = File(outDir, "tor")

        val assets = assets
        val versionMarker = File(outDir, ".version")
        val currentVersion = packageManager.getPackageInfo(packageName, 0).let { it.longVersionCode }

        if (outFile.exists() && versionMarker.exists() &&
            versionMarker.readText().trim().toLongOrNull() == currentVersion
        ) {
            return outFile.absolutePath
        }

        copyAsset(assets, assetPath, outFile)
        Os.chmod(outFile.absolutePath, 0b111_101_101) // 0755 rwxr-xr-x
        versionMarker.writeText(currentVersion.toString())
        return outFile.absolutePath
    }

    private fun pickSupportedAbi(): String {
        // ponytail: Build.SUPPORTED_ABIS is ordered by preference; we pick
        // the first one we ship an asset for. Add a build flag if you want
        // to shave APKs via app-bundle ABI splits instead.
        val supported = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Build.SUPPORTED_ABIS.orArrayOf("arm64-v8a")
        } else {
            arrayOf("armeabi-v7a")
        }
        val shipped = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        return supported.firstOrNull { it in shipped } ?: "arm64-v8a"
    }

    private fun copyAsset(assets: AssetManager, path: String, dest: File) {
        assets.open(path).use { input ->
            FileOutputStream(dest).use { output -> input.copyTo(output) }
        }
    }

    // -------------------------------------------------------------------
    // Process spawn + log pump
    // -------------------------------------------------------------------

    private fun writeTorrc(): String {
        val dir = File(filesDir, "tor/run").apply { mkdirs() }
        val cfg = File(dir, "torrc")
        cfg.writeText(
            """
            SocksPort 127.0.0.1:$TOR_SOCKS_PORT
            ControlPort 127.0.0.1:$TOR_CONTROL_PORT
            CookieAuthentication 1
            CookieAuthFile ${File(dir, "control_auth_cookie").absolutePath}
            DataDirectory ${File(dir, "data").absolutePath}
            AvoidDiskWrites 0
            RunAsDaemon 0
            Log notice stdout
            """.trimIndent()
        )
        return cfg.absolutePath
    }

    private fun spawnTor(binaryPath: String, torrcPath: String): Process {
        val pb = ProcessBuilder(binaryPath, "-f", torrcPath)
            .redirectErrorStream(true)
        val process = pb.start()
        // Pump stdout+stderr lines to the Android log so the diagnostics
        // panel surfaces bootstrap messages in real time.
        val logThread = Thread {
            BufferedReader(InputStreamReader(process.inputStream)).use { r ->
                var line = r.readLine()
                while (line != null) {
                    Log.i(TAG, "[tor] $line")
                    line = r.readLine()
                }
            }
        }.apply { isDaemon = true; name = "tor-log-pump" }
        logThread.start()
        return process
    }

    private fun waitForSocks() {
        val deadline = System.currentTimeMillis() + SOCKS_BOOT_TIMEOUT_MS
        val addr = java.net.InetSocketAddress("127.0.0.1", TOR_SOCKS_PORT)
        while (System.currentTimeMillis() < deadline) {
            if (!running.get()) throw InterruptedException("shutdown requested")
            try {
                java.net.Socket().use { s -> s.connect(addr, 500); return }
            } catch (_: java.io.IOException) {
                Thread.sleep(250)
            }
        }
        throw java.io.IOException("Tor SOCKS port $TOR_SOCKS_PORT did not come up in time")
    }

    // -------------------------------------------------------------------
    // VpnService.Builder
    // -------------------------------------------------------------------

    private fun establishVpn(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(packageName + ".orbot")
            .addAddress("10.88.1.2", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("10.88.0.1")
            .setMtu(1500)
            .setBlocking(true)
        return builder.establish()
    }

    // -------------------------------------------------------------------
    // Foreground notification plumbing
    // -------------------------------------------------------------------

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Tor VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "LumiNet Orbot-mode Tor VPN service" }
        )
    }

    private fun buildNotification(text: String): Notification {
        val intent = packageManager.getLaunchIntentForPackage(packageName) ?: Intent()
        val pi = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("LumiNet Tor VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}

// ----------------------------------------------------------------------
// hev-socks5-tunnel JNI bridge
// ----------------------------------------------------------------------
//
// The native side (`libhevsocks5tunnel.so`) exposes three entry points:
//   long  hev_socks5_tunnel_start(int tunFd, const char* socksAddr, int socksPort)
//   void  hev_socks5_tunnel_stop(long handle)
//   void  hev_socks5_tunnel_join(long handle)  // optional, blocks until stop
//
// ponytail: thin wrapper over System.loadLibrary + the native symbols.
// Returns a handle the Kotlin side stores in `jniTunnelHandle`. If the
// native library is not present, calls throw UnsatisfiedLinkError on the
// first invocation; the service surfaces this as a start failure.
private object HevSocks5TunnelBridge {
    init {
        System.loadLibrary("hevsocks5tunnel")
    }

    @JvmStatic external fun tunnelStart(tunFd: Int, socksAddr: String, socksPort: Int): Long
    @JvmStatic external fun tunnelStop(handle: Long)
    @JvmStatic external fun tunnelJoin(handle: Long)
}

// ponytail: Build.SUPPORTED_ABIS baseline on Eclair+ — helper here only
// because Kotlin's null-elvis `?:` does a no-op only on the array type.
private fun Array<String>?.orArrayOf(default: String): Array<String> = this ?: arrayOf(default)
