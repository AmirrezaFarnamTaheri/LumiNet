package com.luminet.android

enum class VpnRuntimeStage {
    IDLE,
    STARTING,
    CONNECTED,
    STOPPING,
    ERROR,
}

data class VpnRuntimeState(
    val stage: VpnRuntimeStage = VpnRuntimeStage.IDLE,
    val failureCode: String? = null,
)
