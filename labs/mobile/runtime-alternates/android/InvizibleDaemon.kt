// Ported from: InviZible-master
// Target path: desktop/android/InvizibleDaemon.kt

package com.luminet.android

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * InviZible-style multi-protocol daemon manager for LumiNet Android.
 *
 * Manages three concurrently running privacy daemons:
 *  - **Tor** — SOCKS5 proxy on port 9050 for onion routing.
 *  - **I2P** — HTTP proxy on port 4444 for garlic-routed I2P traffic.
 *  - **DNSCrypt** — UDP DNS resolver on port 5354 with DoH/DoT fallback.
 *
 * Each daemon is spawned as a `Process` via [ProcessBuilder] with the
 * native binaries bundled in the app's `nativeLibraryDir`.
 *
 * Ported from InviZible Pro (com.github.invizible) process management.
 */
class InvizibleDaemon(private val context: Context) {

    companion object {
        private const val TAG = "InvizibleDaemon"

        private const val TOR_SOCKS_PORT = 9050
        private const val TOR_CONTROL_PORT = 9051
        private const val I2P_HTTP_PORT = 4444
        private const val DNSCRYPT_PORT = 5354

        private const val RESTART_DELAY_MS = 5_000L
        private const val MAX_RESTART_ATTEMPTS = 5
    }

    /** Represents a managed native process. */
    data class DaemonProcess(
        val name: String,
        val binaryName: String,
        val configArgs: List<String>,
        val port: Int,
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val torRunning = AtomicBoolean(false)
    private val i2pRunning = AtomicBoolean(false)
    private val dnsCryptRunning = AtomicBoolean(false)

    private val torRestarts = AtomicLong(0)
    private val i2pRestarts = AtomicLong(0)
    private val dnsCryptRestarts = AtomicLong(0)

    private var torProcess: Process? = null
    private var i2pProcess: Process? = null
    private var dnsCryptProcess: Process? = null

    private val nativeDir: String
        get() = context.applicationInfo.nativeLibraryDir

    // ── Daemon Definitions ────────────────────────────────────────────────────

    private val torDaemon = DaemonProcess(
        name = "Tor",
        binaryName = "libtorsocks.so",
        configArgs = listOf(
            "--SocksPort", TOR_SOCKS_PORT.toString(),
            "--ControlPort", TOR_CONTROL_PORT.toString(),
            "--DataDirectory", "${context.filesDir}/tor",
            "--CookieAuthentication", "1",
            "--Log", "notice stderr"
        ),
        port = TOR_SOCKS_PORT
    )

    private val i2pDaemon = DaemonProcess(
        name = "I2P",
        binaryName = "libi2pd.so",
        configArgs = listOf(
            "--httpproxy.enabled", "true",
            "--httpproxy.port", I2P_HTTP_PORT.toString(),
            "--datadir", "${context.filesDir}/i2pd"
        ),
        port = I2P_HTTP_PORT
    )

    private val dnsCryptDaemon = DaemonProcess(
        name = "DNSCrypt",
        binaryName = "libdnscrypt-proxy.so",
        configArgs = listOf(
            "-config", "${context.filesDir}/dnscrypt-proxy.toml"
        ),
        port = DNSCRYPT_PORT
    )

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /** Starts all three daemons concurrently with automatic restart on crash. */
    fun startAll() {
        Log.i(TAG, "Starting all InviZible daemons")
        scope.launch { manageDaemon(torDaemon, torRunning, torRestarts) { torProcess = it } }
        scope.launch { manageDaemon(i2pDaemon, i2pRunning, i2pRestarts) { i2pProcess = it } }
        scope.launch { manageDaemon(dnsCryptDaemon, dnsCryptRunning, dnsCryptRestarts) { dnsCryptProcess = it } }
    }

    /** Stops all daemons gracefully. */
    fun stopAll() {
        Log.i(TAG, "Stopping all InviZible daemons")
        torRunning.set(false)
        i2pRunning.set(false)
        dnsCryptRunning.set(false)

        torProcess?.destroy()
        i2pProcess?.destroy()
        dnsCryptProcess?.destroy()

        scope.cancel()
    }

    /** Restarts a single named daemon. */
    fun restart(name: String) {
        when (name.lowercase()) {
            "tor" -> {
                torProcess?.destroy()
                scope.launch { manageDaemon(torDaemon, torRunning, torRestarts) { torProcess = it } }
            }
            "i2p" -> {
                i2pProcess?.destroy()
                scope.launch { manageDaemon(i2pDaemon, i2pRunning, i2pRestarts) { i2pProcess = it } }
            }
            "dnscrypt" -> {
                dnsCryptProcess?.destroy()
                scope.launch { manageDaemon(dnsCryptDaemon, dnsCryptRunning, dnsCryptRestarts) { dnsCryptProcess = it } }
            }
        }
    }

    // ── Process Management ────────────────────────────────────────────────────

    /**
     * Supervises a daemon process, restarting it on failure up to
     * [MAX_RESTART_ATTEMPTS] times.
     */
    private suspend fun manageDaemon(
        daemon: DaemonProcess,
        runningFlag: AtomicBoolean,
        restartCounter: AtomicLong,
        processSink: (Process) -> Unit,
    ) {
        runningFlag.set(true)
        restartCounter.set(0)

        while (runningFlag.get() && isActive) {
            val process = launchProcess(daemon)
            if (process == null) {
                Log.e(TAG, "${daemon.name} binary not found at $nativeDir/${daemon.binaryName}")
                break
            }

            processSink(process)
            Log.i(TAG, "${daemon.name} started (PID: ${process.pid()})")

            // Pipe stderr to logcat
            scope.launch { pipeLog(daemon.name, process) }

            val exitCode = withContext(Dispatchers.IO) { process.waitFor() }
            Log.w(TAG, "${daemon.name} exited with code $exitCode")

            if (!runningFlag.get()) break

            val attempt = restartCounter.incrementAndGet()
            if (attempt > MAX_RESTART_ATTEMPTS) {
                Log.e(TAG, "${daemon.name} exceeded max restarts ($MAX_RESTART_ATTEMPTS), giving up")
                break
            }

            Log.i(TAG, "${daemon.name} restarting in ${RESTART_DELAY_MS}ms (attempt $attempt)")
            delay(RESTART_DELAY_MS)
        }

        runningFlag.set(false)
    }

    /** Launches the daemon's native binary. Returns null if the binary is missing. */
    private fun launchProcess(daemon: DaemonProcess): Process? {
        val binary = "$nativeDir/${daemon.binaryName}"
        val file = java.io.File(binary)
        if (!file.exists()) return null

        val cmd = mutableListOf(binary).also { it.addAll(daemon.configArgs) }
        return ProcessBuilder(cmd)
            .redirectErrorStream(false)
            .start()
    }

    /** Forwards process stderr to Android LogCat. */
    private fun pipeLog(name: String, process: Process) {
        try {
            process.errorStream.bufferedReader().useLines { lines ->
                lines.forEach { line -> Log.d("$TAG/$name", line) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read $name daemon logs", e)
        }
    }

    // ── Status ────────────────────────────────────────────────────────────────

    /** Returns true if the Tor daemon is running. */
    fun isTorRunning(): Boolean = torRunning.get() && torProcess?.isAlive == true

    /** Returns true if the I2P daemon is running. */
    fun isI2pRunning(): Boolean = i2pRunning.get() && i2pProcess?.isAlive == true

    /** Returns true if the DNSCrypt daemon is running. */
    fun isDnsCryptRunning(): Boolean = dnsCryptRunning.get() && dnsCryptProcess?.isAlive == true

    /** Returns a status snapshot of all daemons. */
    fun statusSnapshot(): Map<String, Boolean> = mapOf(
        "tor" to isTorRunning(),
        "i2p" to isI2pRunning(),
        "dnscrypt" to isDnsCryptRunning(),
    )

    /** Returns restart counts for monitoring. */
    fun restartCounts(): Map<String, Long> = mapOf(
        "tor" to torRestarts.get(),
        "i2p" to i2pRestarts.get(),
        "dnscrypt" to dnsCryptRestarts.get(),
    )

    /** Returns the SOCKS5 proxy address for the Tor daemon. */
    fun torProxy(): Pair<String, Int> = Pair("127.0.0.1", TOR_SOCKS_PORT)

    /** Returns the HTTP proxy address for the I2P daemon. */
    fun i2pProxy(): Pair<String, Int> = Pair("127.0.0.1", I2P_HTTP_PORT)

    /** Returns the DNS resolver address for the DNSCrypt daemon. */
    fun dnsCryptResolver(): Pair<String, Int> = Pair("127.0.0.1", DNSCRYPT_PORT)
}
