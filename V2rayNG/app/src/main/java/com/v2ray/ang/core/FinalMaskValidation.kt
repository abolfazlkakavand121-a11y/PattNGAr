package com.v2ray.ang.core

import com.google.gson.JsonElement
import com.google.gson.JsonParser

/**
 * Checks the outer structure of Xray's FinalMask object before PattNG stores it.
 *
 * The accepted names, directions and TLS-record settings mirror the Xray fork's
 * FinalMask configuration loader. Protocol-specific settings other than tls-record
 * remain the responsibility of Xray's parser.
 */
object FinalMaskValidation {

    private val tcpTypes = setOf(
        "filter",
        "header-custom",
        "fragment",
        "tls-record",
        "borrow",
        "merge",
        "sudoku",
        "xmc",
    )

    private val udpTypes = setOf(
        "filter",
        "header-custom",
        "mkcp-legacy",
        "noise",
        "salamander",
        "sudoku",
        "xdns",
        "xicmp",
        "realm",
        "udphop",
    )

    private val tcpKeys = setOf("tcp", "tcp4", "tcp6")
    private val udpKeys = setOf("udp", "udp4", "udp6")
    private val rootKeys = tcpKeys + udpKeys + "quicParams"
    private val quicParamKeys = setOf(
        "congestion",
        "debug",
        "bbrProfile",
        "brutalUp",
        "brutalDown",
        "brutalDisableLossCompensation",
        "initStreamReceiveWindow",
        "maxStreamReceiveWindow",
        "initConnectionReceiveWindow",
        "maxConnectionReceiveWindow",
        "maxIdleTimeout",
        "keepAlivePeriod",
        "disablePathMTUDiscovery",
        "disableChromeParrot",
        "disableGSO",
        "maxIncomingStreams",
        "disableStatelessReset",
    )
    private val tlsRecordSettingsKeys = setOf(
        "splitAt",
        "recordVersion",
        "firstFragmentVersion",
        "remainingFragmentVersion",
        "sniSplit",
    )
    private val sniSplitModes = setOf(
        "before-extension",
        "extension-header",
        "mid-hostname",
        "after-extension",
    )

    /**
     * A blank value means no mask and is valid. A nonblank value must contain a
     * recognized mask or a QUIC parameter object. Mask names are case-sensitive,
     * matching the Xray config loader.
     */
    fun isValid(raw: String?): Boolean {
        if (raw.isNullOrBlank()) return true

        val root = try {
            JsonParser.parseString(raw)
        } catch (_: RuntimeException) {
            return false
        }
        if (!root.isJsonObject) return false

        val config = root.asJsonObject
        if (config.keySet().isEmpty() || !rootKeys.containsAll(config.keySet())) return false

        for (key in tcpKeys) {
            val masks = config.get(key) ?: continue
            if (!validMasks(masks, tcpTypes)) return false
        }
        for (key in udpKeys) {
            val masks = config.get(key) ?: continue
            if (!validMasks(masks, udpTypes)) return false
        }

        val quicParams = config.get("quicParams")
        if (quicParams != null && !validQuicParams(quicParams)) return false

        val hasTcpMask = tcpKeys.any { key -> config.get(key)?.let(::hasMasks) == true }
        val hasUdpMask = udpKeys.any { key -> config.get(key)?.let(::hasMasks) == true }
        // An empty object is meaningful: Xray applies its default QUIC parameters.
        val hasQuicSettings = quicParams?.isJsonObject == true
        return hasTcpMask || hasUdpMask || hasQuicSettings
    }

    private fun hasMasks(element: JsonElement): Boolean =
        element.isJsonArray && !element.asJsonArray.isEmpty

    private fun validMasks(element: JsonElement, allowedTypes: Set<String>): Boolean {
        if (element.isJsonNull) return true
        if (!element.isJsonArray) return false
        return element.asJsonArray.all { item ->
            if (!item.isJsonObject) return@all false
            val mask = item.asJsonObject
            if (mask.keySet().any { it != "type" && it != "settings" }) return@all false

            val typeElement = mask.get("type") ?: return@all false
            if (!typeElement.isJsonPrimitive || !typeElement.asJsonPrimitive.isString) return@all false
            val type = typeElement.asString
            if (type !in allowedTypes) return@all false

            val settings = mask.get("settings")
            if (settings == null || settings.isJsonNull) {
                true
            } else if (!settings.isJsonObject) {
                false
            } else if (type == "tls-record") {
                validTlsRecordSettings(settings.asJsonObject)
            } else {
                true
            }
        }
    }

    private fun validTlsRecordSettings(settings: com.google.gson.JsonObject): Boolean {
        if (!tlsRecordSettingsKeys.containsAll(settings.keySet())) return false

        val splitAt = settings.get("splitAt")?.let(::readInt) ?: 0
        val recordVersion = settings.get("recordVersion")?.let(::readInt) ?: 0
        val firstVersion = settings.get("firstFragmentVersion")?.let(::readInt) ?: 0
        val remainingVersion = settings.get("remainingFragmentVersion")?.let(::readInt) ?: 0
        val sniElement = settings.get("sniSplit")

        if (
            splitAt == INVALID_INT || recordVersion == INVALID_INT ||
            firstVersion == INVALID_INT || remainingVersion == INVALID_INT
        ) return false

        if (sniElement != null) {
            if (!sniElement.isJsonPrimitive || !sniElement.asJsonPrimitive.isString) return false
            val mode = sniElement.asString
            if (mode.isNotEmpty() && mode !in sniSplitModes) return false
            if (mode.isNotEmpty()) {
                return splitAt == 0 && recordVersion == 0 && firstVersion == 0 && remainingVersion == 0
            }
        }

        if (recordVersion != 0) {
            return recordVersion in TLS_RECORD_VERSION_MIN..TLS_RECORD_VERSION_MAX &&
                splitAt == 0 && firstVersion == 0 && remainingVersion == 0
        }

        if (firstVersion != 0 || remainingVersion != 0) {
            return firstVersion in TLS_RECORD_VERSION_MIN..TLS_RECORD_VERSION_MAX &&
                remainingVersion in TLS_RECORD_VERSION_MIN..TLS_RECORD_VERSION_MAX &&
                splitAt in 0..MAX_TLS_RECORD_SPLIT
        }

        // splitAt=0 delegates to the core's default offset of two bytes.
        return splitAt in 0..MAX_TLS_RECORD_SPLIT
    }

    private fun readInt(element: JsonElement): Int {
        if (!element.isJsonPrimitive || !element.asJsonPrimitive.isNumber) return INVALID_INT
        return element.asString.toIntOrNull() ?: INVALID_INT
    }

    private fun validQuicParams(element: JsonElement): Boolean {
        if (element.isJsonNull) return true
        if (!element.isJsonObject) return false
        return quicParamKeys.containsAll(element.asJsonObject.keySet())
    }

    private const val INVALID_INT = Int.MIN_VALUE
    private const val TLS_RECORD_VERSION_MIN = 0x0301
    private const val TLS_RECORD_VERSION_MAX = 0x0303
    private const val MAX_TLS_RECORD_SPLIT = 512
}
