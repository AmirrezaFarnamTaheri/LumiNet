#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "src/apps/android/app/src/main/java/com/luminet/android/LumiNetActivity.kt": "1a7924d7e646624fb50c6effc9807ba28d4b02e0",
    "src/apps/android/app/src/main/AndroidManifest.xml": "a28fafb6216962cfbdd231b538f9384241c13f31",
}
for rel, expected in EXPECTED.items():
    actual = subprocess.check_output(["git", "hash-object", rel], cwd=ROOT, text=True).strip()
    if actual != expected:
        raise SystemExit(f"{rel} drifted: expected {expected}, got {actual}")


def replace_once(rel: str, old: str, new: str, label: str) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{rel}: {label}: expected one match, got {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")

activity = "src/apps/android/app/src/main/java/com/luminet/android/LumiNetActivity.kt"
replace_once(
    activity,
    '''import android.content.Intent
import android.net.VpnService''',
    '''import android.content.Context
import android.content.Intent
import android.net.VpnService''',
    "Context import",
)
replace_once(
    activity,
    '''import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle''',
    '''import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle''',
    "LocalContext import",
)
replace_once(
    activity,
    '''    val isConnected = runtimeState.stage == VpnRuntimeStage.CONNECTED
    val tunnelBusy = runtimeState.stage == VpnRuntimeStage.STARTING || runtimeState.stage == VpnRuntimeStage.STOPPING
    val statusLabel = when (runtimeState.stage) {''',
    '''    val isConnected = runtimeState.stage == VpnRuntimeStage.CONNECTED
    val tunnelBusy = runtimeState.stage == VpnRuntimeStage.STARTING || runtimeState.stage == VpnRuntimeStage.STOPPING
    val actionLabel = if (isConnected) "Disconnect" else "Connect"
    val statusLabel = when (runtimeState.stage) {''',
    "action label",
)
replace_once(
    activity,
    '''        Button(
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
        )''',
    '''        Text(
            text = if (runtimeState.stage == VpnRuntimeStage.ERROR && runtimeState.failureCode != null) {
                stringResource(R.string.vpn_status_error_detail, runtimeState.failureCode)
            } else {
                "Status: $statusLabel"
            },
            color = MaterialTheme.colorScheme.onBackground,
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
                text = actionLabel.uppercase(),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = Color.Black,
            )
        }''',
    "status/action separation",
)
replace_once(
    activity,
    '''    var mode by remember(policy) { mutableStateOf(policy.mode) }
    var packageText by remember(policy) { mutableStateOf(policy.packages.joinToString("\\n")) }
    var status by remember(policy) { mutableStateOf<String?>(null) }

    Card(modifier = modifier) {''',
    '''    val context = LocalContext.current
    val launchableApps = remember(context) { loadLaunchableApps(context) }
    var mode by remember(policy) { mutableStateOf(policy.mode) }
    var selectedPackages by remember(policy) { mutableStateOf(policy.packages.toSet()) }
    var search by remember { mutableStateOf("") }
    var status by remember(policy) { mutableStateOf<String?>(null) }
    val visibleApps = remember(launchableApps, search) {
        val needle = search.trim().lowercase()
        launchableApps
            .asSequence()
            .filter { needle.isEmpty() || it.label.lowercase().contains(needle) || it.packageName.lowercase().contains(needle) }
            .take(50)
            .toList()
    }
    val launchablePackages = remember(launchableApps) { launchableApps.mapTo(mutableSetOf()) { it.packageName } }
    val hiddenConfiguredPackages = remember(selectedPackages, launchablePackages) { selectedPackages.filterNot(launchablePackages::contains) }

    Card(modifier = modifier) {''',
    "app picker state",
)
replace_once(
    activity,
    '''            Text(
                "Choose which Android apps enter the LumiNet TUN. Package policy is enforced by Android before the tunnel is established.",
                style = MaterialTheme.typography.bodySmall,
            )''',
    '''            Text(
                "Choose launchable Android apps by name. LumiNet stores package identifiers internally and Android enforces the selected policy before the tunnel is established.",
                style = MaterialTheme.typography.bodySmall,
            )''',
    "app picker explanation",
)
replace_once(
    activity,
    '''            if (mode != PerAppVpnMode.ALL) {
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
            }''',
    '''            if (mode != PerAppVpnMode.ALL) {
                OutlinedTextField(
                    value = search,
                    onValueChange = { search = it; status = null },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Search installed apps") },
                    supportingText = {
                        Text("Shows launchable apps visible through Android's package-visibility contract; max ${PerAppVpnPolicy.MAX_PACKAGES} selections.")
                    },
                )

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 320.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    visibleApps.forEach { app ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Checkbox(
                                checked = app.packageName in selectedPackages,
                                onCheckedChange = { checked ->
                                    selectedPackages = if (checked) selectedPackages + app.packageName else selectedPackages - app.packageName
                                    status = null
                                },
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.label, style = MaterialTheme.typography.bodyMedium)
                                Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                    if (visibleApps.isEmpty()) {
                        Text("No launchable apps match this search.", style = MaterialTheme.typography.bodySmall)
                    }
                }

                if (hiddenConfiguredPackages.isNotEmpty()) {
                    Text(
                        "${hiddenConfiguredPackages.size} previously configured package(s) are not launcher-visible on this device and will be preserved unless the policy is reset.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                    )
                }
                Text(
                    "Selected: ${selectedPackages.size}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }''',
    "manual package editor replacement",
)
replace_once(
    activity,
    '''                Button(onClick = {
                    val candidate = PerAppVpnPolicy.parse(mode, packageText)
                    status = onSave(candidate) ?: "Saved"
                }) {''',
    '''                Button(onClick = {
                    val candidate = PerAppVpnPolicy(mode = mode, packages = selectedPackages.toList()).normalized()
                    status = onSave(candidate) ?: "Saved"
                }) {''',
    "app picker save",
)
activity_path = ROOT / activity
text = activity_path.read_text(encoding="utf-8")
text += '''

private data class LaunchableAppOption(
    val label: String,
    val packageName: String,
)

@Suppress("DEPRECATION")
private fun loadLaunchableApps(context: Context): List<LaunchableAppOption> {
    val packageManager = context.packageManager
    val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return packageManager.queryIntentActivities(launcherIntent, 0)
        .asSequence()
        .mapNotNull { info ->
            val packageName = info.activityInfo?.packageName?.trim().orEmpty()
            if (packageName.isEmpty() || packageName == context.packageName) return@mapNotNull null
            val label = runCatching { info.loadLabel(packageManager).toString().trim() }
                .getOrDefault(packageName)
                .ifEmpty { packageName }
            LaunchableAppOption(label = label, packageName = packageName)
        }
        .distinctBy { it.packageName }
        .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label }.thenBy { it.packageName })
        .toList()
}
'''
activity_path.write_text(text, encoding="utf-8")

manifest = "src/apps/android/app/src/main/AndroidManifest.xml"
replace_once(
    manifest,
    '''    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />

    <application''',
    '''    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />

    <!-- Narrow package visibility for the per-app VPN picker. This intentionally
         avoids QUERY_ALL_PACKAGES and exposes only launcher activities. -->
    <queries>
        <intent>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent>
    </queries>

    <application''',
    "narrow package visibility",
)

print("Android action semantics and launcher-app picker applied")
