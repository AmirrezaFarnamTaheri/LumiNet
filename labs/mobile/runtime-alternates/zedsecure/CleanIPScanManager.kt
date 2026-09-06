package com.luminet.zedsecure

import android.content.Context
import android.util.Log
import java.io.File
import java.util.Collections
import java.util.UUID

/**
 * CleanIPScanManager manages scan settings, session states, and telemetry.
 * Ported from: WhiteDNS-Android-main (shop/whitedns/client/scan/...)
 * Target path: client/android/app/src/main/kotlin/com/luminet/zedsecure/CleanIPScanManager.kt
 */
class CleanIPScanManager(private val context: Context) {

    private val TAG = "CleanIPScanManager"
    private var activeSessionId: String = ""
    private var isScanRunning = false
    private val activeWorkers = Collections.synchronizedList(mutableListOf<String>())
    private val scanLogs = Collections.synchronizedList(mutableListOf<String>())

    // ─── ScanSettings Struct & Properties ─────────────────────────────────────

    class ScanSettings {
        var workerCount: Int = 4
        var maxConcurrentProbes: Int = 200
        var probeTimeoutMs: Long = 5000L
        var logVerbosity: String = "info"
        var lowBandwidth: Boolean = false
        var probeIntervalMs: Int = 10
        var quarantineTTLSec: Double = 60.0
        var requireHTMLForDomainTokens: Boolean = true
        var acceptOnCertMatch: Boolean = true

        // Getters & Setters
        fun getWorkerCount(): Int = workerCount
        fun setWorkerCount(v: Int) { workerCount = v }
        fun getMaxConcurrentProbes(): Int = maxConcurrentProbes
        fun setMaxConcurrentProbes(v: Int) { maxConcurrentProbes = v }
        fun getProbeTimeoutMs(): Long = probeTimeoutMs
        fun setProbeTimeoutMs(v: Long) { probeTimeoutMs = v }
        fun getLogVerbosity(): String = logVerbosity
        fun setLogVerbosity(v: String) { logVerbosity = v }
        fun getLowBandwidth(): Boolean = lowBandwidth
        fun setLowBandwidth(v: Boolean) { lowBandwidth = v }
        fun getProbeIntervalMs(): Int = probeIntervalMs
        fun setProbeIntervalMs(v: Int) { probeIntervalMs = v }

        // Builders
        fun withWorkerCount(v: Int): ScanSettings { setWorkerCount(v); return this }
        fun withMaxConcurrentProbes(v: Int): ScanSettings { setMaxConcurrentProbes(v); return this }
        fun withProbeTimeoutMs(v: Long): ScanSettings { setProbeTimeoutMs(v); return this }
        fun withLowBandwidth(v: Boolean): ScanSettings { setLowBandwidth(v); return this }
    }

    // ─── ScanState Struct & Properties ────────────────────────────────────────

    class ScanState {
        var sessionId: String = ""
        var status: String = "idle" // idle, running, completed, failed, stopped
        var totalResolvers: Int = 0
        var completedResolvers: Int = 0
        var validResolversCount: Int = 0
        var rejectedResolversCount: Int = 0
        var startedAtMillis: Long = 0L
        var updatedAtMillis: Long = 0L
        var durationMillis: Long = 0L
        var message: String = ""
        val validResolversList = mutableListOf<String>()
        val rejectedResolversList = mutableListOf<String>()
        val failuresList = mutableListOf<String>()

        // Getters & Setters
        fun getSessionId(): String = sessionId
        fun setSessionId(v: String) { sessionId = v }
        fun getStatus(): String = status
        fun setStatus(v: String) { status = v }
        fun getTotalResolvers(): Int = totalResolvers
        fun setTotalResolvers(v: Int) { totalResolvers = v }
        fun getCompletedResolvers(): Int = completedResolvers
        fun setCompletedResolvers(v: Int) { completedResolvers = v }
        fun getValidResolversCount(): Int = validResolversCount
        fun setValidResolversCount(v: Int) { validResolversCount = v }
        fun getRejectedResolversCount(): Int = rejectedResolversCount
        fun setRejectedResolversCount(v: Int) { rejectedResolversCount = v }
        fun getStartedAtMillis(): Long = startedAtMillis
        fun setStartedAtMillis(v: Long) { startedAtMillis = v }
        fun getUpdatedAtMillis(): Long = updatedAtMillis
        fun setUpdatedAtMillis(v: Long) { updatedAtMillis = v }
        fun getDurationMillis(): Long = durationMillis
        fun setDurationMillis(v: Long) { durationMillis = v }
        fun getMessage(): String = message
        fun setMessage(v: String) { message = v }

        // Array Mutators
        fun addValidResolver(r: String) { validResolversList.add(r); validResolversCount = validResolversList.size }
        fun addRejectedResolver(r: String) { rejectedResolversList.add(r); rejectedResolversCount = rejectedResolversList.size }
        fun addFailure(f: String) { failuresList.add(f) }
        fun clearLists() {
            validResolversList.clear()
            rejectedResolversList.clear()
            failuresList.clear()
            validResolversCount = 0
            rejectedResolversCount = 0
        }

        // Builders
        fun withSessionId(v: String): ScanState { setSessionId(v); return this }
        fun withStatus(v: String): ScanState { setStatus(v); return this }
        fun withTotalResolvers(v: Int): ScanState { setTotalResolvers(v); return this }
    }

    private var currentSettings = ScanSettings()
    private var currentState = ScanState()
    private val stateMutex = Any()

    // ─── Scan Manager API Methods ─────────────────────────────────────────────

    fun getActiveSessionId(): String = activeSessionId
    fun isScanRunning(): Boolean = isScanRunning

    fun getSettings(): ScanSettings = currentSettings
    fun updateSettings(newSettings: ScanSettings) {
        currentSettings = newSettings
    }

    fun getCurrentState(): ScanState = synchronized(stateMutex) { currentState }

    /**
     * Start a new scanning session.
     */
    fun startNewSession(sourceName: String, totalResolvers: Int): String {
        synchronized(stateMutex) {
            val sessionId = UUID.randomUUID().toString()
            activeSessionId = sessionId
            isScanRunning = true
            scanLogs.clear()
            activeWorkers.clear()

            currentState = ScanState()
                .withSessionId(sessionId)
                .withStatus("running")
                .withTotalResolvers(totalResolvers)
            currentState.setStartedAtMillis(System.currentTimeMillis())
            currentState.setUpdatedAtMillis(System.currentTimeMillis())
            currentState.setMessage("Scan session started for source: $sourceName")

            Log.i(TAG, "Started scan session $sessionId for source $sourceName")
            return sessionId
        }
    }

    /**
     * Terminate the active scanning session.
     */
    fun terminateSession(reason: String) {
        synchronized(stateMutex) {
            if (!isScanRunning) return
            isScanRunning = false
            currentState.setStatus("stopped")
            currentState.setUpdatedAtMillis(System.currentTimeMillis())
            currentState.setDurationMillis(System.currentTimeMillis() - currentState.getStartedAtMillis())
            currentState.setMessage("Scan session stopped: $reason")
            Log.i(TAG, "Terminated scan session $activeSessionId. Reason: $reason")
        }
    }

    /**
     * Record a valid resolver found during the scan.
     */
    fun recordValidResolver(resolver: String) {
        synchronized(stateMutex) {
            if (!isScanRunning) return
            currentState.addValidResolver(resolver)
            currentState.setCompletedResolvers(currentState.getCompletedResolvers() + 1)
            currentState.setUpdatedAtMillis(System.currentTimeMillis())
        }
    }

    /**
     * Record a rejected resolver found during the scan.
     */
    fun recordRejectedResolver(resolver: String) {
        synchronized(stateMutex) {
            if (!isScanRunning) return
            currentState.addRejectedResolver(resolver)
            currentState.setCompletedResolvers(currentState.getCompletedResolvers() + 1)
            currentState.setUpdatedAtMillis(System.currentTimeMillis())
        }
    }

    /**
     * Record a scan worker failure message.
     */
    fun recordFailure(workerName: String, error: String) {
        synchronized(stateMutex) {
            if (!isScanRunning) return
            currentState.addFailure("[$workerName] $error")
            currentState.setUpdatedAtMillis(System.currentTimeMillis())
        }
    }

    // ─── Logger & Diagnostics ─────────────────────────────────────────────────

    fun addLog(msg: String) {
        val timestamped = "[${System.currentTimeMillis()}] $msg"
        scanLogs.add(timestamped)
        if (scanLogs.size > 500) {
            scanLogs.removeAt(0)
        }
        Log.d(TAG, msg)
    }

    fun getLogs(): List<String> = scanLogs.toList()

    fun getWorkerCount(): Int = activeWorkers.size
    fun registerWorker(workerId: String) {
        if (!activeWorkers.contains(workerId)) {
            activeWorkers.add(workerId)
        }
    }

    fun unregisterWorker(workerId: String) {
        activeWorkers.remove(workerId)
    }

    // ─── Partition Helper ─────────────────────────────────────────────────────

    /**
     * Partitions a list of resolver endpoints round-robin into separate worker files.
     */
    fun partitionResolvers(resolvers: List<String>, workerCount: Int): List<List<String>> {
        val count = maxOf(1, workerCount)
        val partitions = List(count) { mutableListOf<String>() }
        for (i in resolvers.indices) {
            partitions[i % count].add(resolvers[i])
        }
        return partitions
    }
}
