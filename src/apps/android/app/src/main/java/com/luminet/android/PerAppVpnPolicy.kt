package com.luminet.android

import android.content.Context
import android.net.VpnService

/**
 * Android-native per-app VPN policy.
 *
 * Android's VpnService.Builder does not allow an allowed-app list and a
 * disallowed-app list on the same Builder. The policy therefore selects one
 * closed mode per tunnel and validates the complete package set before any
 * Builder mutation occurs.
 */
enum class PerAppVpnMode(val storageValue: String) {
    ALL("all"),
    INCLUDE("include"),
    EXCLUDE("exclude");

    companion object {
        fun fromStorage(value: String?): PerAppVpnMode =
            entries.firstOrNull { it.storageValue == value } ?: ALL
    }
}

data class PerAppVpnPolicy(
    val mode: PerAppVpnMode = PerAppVpnMode.ALL,
    val packages: List<String> = emptyList(),
) {
    fun normalized(): PerAppVpnPolicy = copy(
        packages = packages
            .asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinct()
            .sorted()
            .toList(),
    )

    fun validate(selfPackage: String): PerAppVpnPolicy {
        val normalized = normalized()
        require(normalized.packages.size <= MAX_PACKAGES) {
            "per-app policy exceeds $MAX_PACKAGES packages"
        }
        normalized.packages.forEach { packageName ->
            require(packageName.length <= MAX_PACKAGE_BYTES && PACKAGE_NAME.matches(packageName)) {
                "invalid Android package name: $packageName"
            }
        }
        if (normalized.mode == PerAppVpnMode.INCLUDE) {
            require(normalized.packages.isNotEmpty()) {
                "include mode requires at least one package"
            }
            require(selfPackage !in normalized.packages) {
                "LumiNet cannot be included in its own VPN tunnel"
            }
        }
        return normalized
    }

    /**
     * Applies exactly one Android package-selection mode to [builder].
     *
     * Validation happens first so invalid input cannot partially configure a
     * Builder. NameNotFoundException and platform policy errors deliberately
     * propagate to the caller: tunnel startup then fails closed rather than
     * silently enforcing only a subset of the requested applications.
     */
    fun applyTo(builder: VpnService.Builder, selfPackage: String) {
        val policy = validate(selfPackage)
        when (policy.mode) {
            PerAppVpnMode.ALL -> builder.addDisallowedApplication(selfPackage)
            PerAppVpnMode.INCLUDE -> policy.packages.forEach(builder::addAllowedApplication)
            PerAppVpnMode.EXCLUDE -> {
                builder.addDisallowedApplication(selfPackage)
                policy.packages
                    .asSequence()
                    .filter { it != selfPackage }
                    .forEach(builder::addDisallowedApplication)
            }
        }
    }

    companion object {
        const val MAX_PACKAGES = 256
        private const val MAX_PACKAGE_BYTES = 255
        private val PACKAGE_NAME = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

        fun parse(mode: PerAppVpnMode, rawPackages: String): PerAppVpnPolicy {
            val packages = rawPackages
                .split(Regex("[,\\n\\r\\t ]+"))
                .filter(String::isNotBlank)
            return PerAppVpnPolicy(mode, packages).normalized()
        }
    }
}

/**
 * Small versioned persistence owner for mobile-only package selection.
 * Desktop/daemon configuration remains intentionally separate because it does
 * not own Android's VpnService.Builder authority.
 */
object PerAppVpnPolicyStore {
    private const val PREFERENCES = "luminet_mobile_vpn_policy"
    private const val KEY_SCHEMA = "schema_version"
    private const val KEY_MODE = "mode"
    private const val KEY_PACKAGES = "packages"
    private const val SCHEMA_VERSION = 1

    fun load(context: Context): PerAppVpnPolicy {
        val prefs = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        if (prefs.getInt(KEY_SCHEMA, SCHEMA_VERSION) != SCHEMA_VERSION) {
            return PerAppVpnPolicy()
        }
        return PerAppVpnPolicy(
            mode = PerAppVpnMode.fromStorage(prefs.getString(KEY_MODE, null)),
            packages = prefs.getStringSet(KEY_PACKAGES, emptySet())?.toList().orEmpty(),
        ).normalized()
    }

    fun save(context: Context, policy: PerAppVpnPolicy): PerAppVpnPolicy {
        val validated = policy.validate(context.packageName)
        val committed = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY_SCHEMA, SCHEMA_VERSION)
            .putString(KEY_MODE, validated.mode.storageValue)
            .putStringSet(KEY_PACKAGES, validated.packages.toSet())
            .commit()
        check(committed) { "failed to persist per-app VPN policy" }
        return validated
    }
}
