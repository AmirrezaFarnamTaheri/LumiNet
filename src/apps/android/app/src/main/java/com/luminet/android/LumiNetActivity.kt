package com.luminet.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat

class LumiNetActivity : ComponentActivity() {
    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpnService()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SovereignGlassTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFF0A0E1A),
                ) {
                    val runtimeState by VpnEngineService.runtimeState.collectAsStateWithLifecycle()
                    var perAppPolicy by remember { mutableStateOf(PerAppVpnPolicyStore.load(this@LumiNetActivity)) }
                    DashboardScreen(
                        runtimeState = runtimeState,
                        perAppPolicy = perAppPolicy,
                        onSavePerAppPolicy = { candidate ->
                            try {
                                perAppPolicy = PerAppVpnPolicyStore.save(this@LumiNetActivity, candidate)
                                null
                            } catch (ex: IllegalArgumentException) {
                                ex.message ?: "Invalid per-app policy"
                            } catch (ex: IllegalStateException) {
                                ex.message ?: "Unable to save per-app policy"
                            }
                        },
                        onToggleConnection = {
                            if (runtimeState.stage == VpnRuntimeStage.CONNECTED || runtimeState.stage == VpnRuntimeStage.STARTING) {
                                stopVpnService()
                            } else {
                                requestVpnStart()
                            }
                        },
                    )
                }
            }
        }
        if (intent?.getBooleanExtra(EXTRA_REQUEST_VPN, false) == true) {
            intent?.removeExtra(EXTRA_REQUEST_VPN)
            requestVpnStart()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_REQUEST_VPN, false)) {
            intent.removeExtra(EXTRA_REQUEST_VPN)
            requestVpnStart()
        }
    }

    private fun requestVpnStart() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            vpnPermissionLauncher.launch(permissionIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, VpnEngineService::class.java),
        )
    }

    private fun stopVpnService() {
        startService(
            Intent(this, VpnEngineService::class.java)
                .setAction(VpnEngineService.ACTION_STOP),
        )
    }

    companion object {
        const val EXTRA_REQUEST_VPN = "com.luminet.android.REQUEST_VPN"
    }
}

@Composable
private fun SovereignGlassTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF00F0FF),
            background = Color(0xFF0A0E1A),
            surface = Color(0xFF121829),
        ),
        content = content,
    )
}

@Composable
private fun DashboardScreen(
    runtimeState: VpnRuntimeState,
    perAppPolicy: PerAppVpnPolicy,
    onSavePerAppPolicy: (PerAppVpnPolicy) -> String?,
    onToggleConnection: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isConnected = runtimeState.stage == VpnRuntimeStage.CONNECTED
    val tunnelBusy = runtimeState.stage == VpnRuntimeStage.STARTING || runtimeState.stage == VpnRuntimeStage.STOPPING
    val statusLabel = when (runtimeState.stage) {
        VpnRuntimeStage.IDLE -> stringResource(R.string.vpn_status_idle)
        VpnRuntimeStage.STARTING -> stringResource(R.string.vpn_status_starting)
        VpnRuntimeStage.CONNECTED -> stringResource(R.string.vpn_status_connected)
        VpnRuntimeStage.STOPPING -> stringResource(R.string.vpn_status_stopping)
        VpnRuntimeStage.ERROR -> stringResource(R.string.vpn_status_error)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(28.dp),
    ) {
        Text(
            text = "LumiNet Sovereign Mobile",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = Color(0xFF00F0FF),
        )

        Button(
            onClick = onToggleConnection,
            enabled = !tunnelBusy,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected) Color(0xFF00FF66) else Color(0xFFFF0055),
            ),
            modifier = Modifier.size(160.dp),
        ) {
            Text(
                text = statusLabel.uppercase(),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = Color.Black,
            )
        }

        Text(
            text = if (runtimeState.stage == VpnRuntimeStage.ERROR && runtimeState.failureCode != null) {
                stringResource(R.string.vpn_status_error_detail, runtimeState.failureCode)
            } else {
                statusLabel
            },
            color = MaterialTheme.colorScheme.onBackground,
        )

        PerAppPolicyEditor(
            policy = perAppPolicy,
            isConnected = isConnected,
            onSave = onSavePerAppPolicy,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun PerAppPolicyEditor(
    policy: PerAppVpnPolicy,
    isConnected: Boolean,
    onSave: (PerAppVpnPolicy) -> String?,
    modifier: Modifier = Modifier,
) {
    var mode by remember(policy) { mutableStateOf(policy.mode) }
    var packageText by remember(policy) { mutableStateOf(policy.packages.joinToString("\n")) }
    var status by remember(policy) { mutableStateOf<String?>(null) }

    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Per-app VPN", fontWeight = FontWeight.SemiBold)
            Text(
                "Choose which Android apps enter the LumiNet TUN. Package policy is enforced by Android before the tunnel is established.",
                style = MaterialTheme.typography.bodySmall,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PerAppVpnMode.entries.forEach { candidate ->
                    FilterChip(
                        selected = mode == candidate,
                        onClick = { mode = candidate; status = null },
                        label = {
                            Text(
                                when (candidate) {
                                    PerAppVpnMode.ALL -> "All"
                                    PerAppVpnMode.INCLUDE -> "Only selected"
                                    PerAppVpnMode.EXCLUDE -> "All except"
                                },
                            )
                        },
                    )
                }
            }

            if (mode != PerAppVpnMode.ALL) {
                OutlinedTextField(
                    value = packageText,
                    onValueChange = { packageText = it; status = null },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                    maxLines = 8,
                    label = { Text("Package names") },
                    supportingText = {
                        Text("One per line or comma-separated; max ${PerAppVpnPolicy.MAX_PACKAGES}.")
                    },
                )
            }

            if (isConnected) {
                Text(
                    "Policy changes take effect on the next VPN connection.",
                    color = MaterialTheme.colorScheme.tertiary,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                status?.let {
                    Text(
                        it,
                        color = if (it == "Saved") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                    )
                } ?: Spacer(Modifier.weight(1f))
                Button(onClick = {
                    val candidate = PerAppVpnPolicy.parse(mode, packageText)
                    status = onSave(candidate) ?: "Saved"
                }) {
                    Text("Save policy")
                }
            }
        }
    }
}
