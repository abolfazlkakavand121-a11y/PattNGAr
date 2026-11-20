package com.v2ray.ang.core

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Checks the outer structure of Xray's FinalMask object before PattNG stores it.
 *
 * This deliberately validates the same direction-specific mask identifiers as the core's
 * TCP/UDP config loaders, but leaves type-specific settings to Xray's own parser.
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

    /**
     * A blank value means no mask and is valid. A nonblank value must contain at least one
     * recognized TCP/UDP mask or a nonempty QUIC parameter object.
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
        // Even an empty QUIC params object is meaningful: Xray applies its default QUIC parameters.
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
            val type = typeElement.asString.lowercase()
            if (type !in allowedTypes) return@all false

            val settings = mask.get("settings")
            settings == null || settings.isJsonNull || settings.isJsonObject
        }
    }

    private fun validQuicParams(element: JsonElement): Boolean {
        if (element.isJsonNull) return true
        if (!element.isJsonObject) return false
        return quicParamKeys.containsAll(element.asJsonObject.keySet())
    }
}
