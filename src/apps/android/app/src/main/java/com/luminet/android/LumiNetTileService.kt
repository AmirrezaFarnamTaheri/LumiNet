package com.luminet.android

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat

/**
 * Quick Settings observer/controller for the canonical [VpnEngineService].
 *
 * This service never creates a TUN or a VPN engine. It only requests the same
 * permission/start/stop lifecycle exposed by the main Activity.
 */
class LumiNetTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        when (VpnEngineService.runtimeState.value.stage) {
            VpnRuntimeStage.CONNECTED,
            VpnRuntimeStage.STARTING,
            -> requestStop()
            VpnRuntimeStage.STOPPING -> Unit
            VpnRuntimeStage.IDLE,
            VpnRuntimeStage.ERROR,
            -> requestStart()
        }
        refreshTile()
    }

    private fun requestStart() {
        if (VpnService.prepare(this) == null) {
            ContextCompat.startForegroundService(
                this,
                Intent(this, VpnEngineService::class.java),
            )
            return
        }
        val intent = Intent(this, LumiNetActivity::class.java)
            .putExtra(LumiNetActivity.EXTRA_REQUEST_VPN, true)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = PendingIntent.getActivity(
                this,
                TILE_ACTIVITY_REQUEST,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun requestStop() {
        startService(
            Intent(this, VpnEngineService::class.java)
                .setAction(VpnEngineService.ACTION_STOP),
        )
    }

    private fun refreshTile() {
        val tile = qsTile ?: return
        val state = VpnEngineService.runtimeState.value
        tile.label = getString(R.string.vpn_tile_label)
        tile.state = when (state.stage) {
            VpnRuntimeStage.CONNECTED -> Tile.STATE_ACTIVE
            VpnRuntimeStage.STARTING,
            VpnRuntimeStage.STOPPING,
            -> Tile.STATE_UNAVAILABLE
            VpnRuntimeStage.IDLE,
            VpnRuntimeStage.ERROR,
            -> Tile.STATE_INACTIVE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(runtimeStatusLabel(state.stage))
        }
        tile.updateTile()
    }

    private fun runtimeStatusLabel(stage: VpnRuntimeStage): Int = when (stage) {
        VpnRuntimeStage.IDLE -> R.string.vpn_status_idle
        VpnRuntimeStage.STARTING -> R.string.vpn_status_starting
        VpnRuntimeStage.CONNECTED -> R.string.vpn_status_connected
        VpnRuntimeStage.STOPPING -> R.string.vpn_status_stopping
        VpnRuntimeStage.ERROR -> R.string.vpn_status_error
    }

    private companion object {
        const val TILE_ACTIVITY_REQUEST = 1002
    }
}
