package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FinalMaskValidationTest {

    @Test
    fun blankMaskMeansNoMask() {
        assertTrue(FinalMaskValidation.isValid(null))
        assertTrue(FinalMaskValidation.isValid(""))
        assertTrue(FinalMaskValidation.isValid("  \n"))
    }

    @Test
    fun acceptsRecognizedTcpAndTlsRecordMasks() {
        val masks = listOf(
            """{"tcp":[{"type":"tls-record","settings":{"recordVersion":769}}]}""",
            """{"tcp":[{"type":"tls-record","settings":{"recordVersion":771}}]}""",
            """{"tcp":[{"type":"tls-record","settings":{"sniSplit":"before-extension"}}]}""",
            """{"tcp":[{"type":"tls-record","settings":{"sniSplit":"mid-hostname"}}]}""",
            """{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200"}}]}""",
            """{"tcp":[{"type":"merge","settings":{}}]}""",
        )
        masks.forEach { assertTrue(FinalMaskValidation.isValid(it), it) }
    }

    @Test
    fun acceptsUdpQuicAndCombinedMasks() {
        assertTrue(FinalMaskValidation.isValid("""{"udp":[{"type":"noise","settings":{}}]}"""))
        assertTrue(FinalMaskValidation.isValid("""{"quicParams":{"congestion":"bbr"}}"""))
        assertTrue(
            FinalMaskValidation.isValid(
                """{"tcp":[{"type":"fragment","settings":{}}],"udp":[{"type":"salamander","settings":{"password":"x"}}],"quicParams":{"congestion":"bbr"}}"""
            )
        )
        assertTrue(FinalMaskValidation.isValid("""{"tcp":[],"udp":[{"type":"noise"}]}"""))
    }


    @Test
    fun acceptsAddressFamilySpecificMasksAndTheCompleteQuicParameterShape() {
        assertTrue(FinalMaskValidation.isValid("""{"tcp4":[{"type":"tls-record","settings":{"recordVersion":771}}]}"""))
        assertTrue(FinalMaskValidation.isValid("""{"tcp6":[{"type":"fragment","settings":{}}]}"""))
        assertTrue(FinalMaskValidation.isValid("""{"udp4":[{"type":"noise","settings":{}}]}"""))
        assertTrue(FinalMaskValidation.isValid("""{"udp6":[{"type":"salamander","settings":{}}]}"""))
        assertTrue(FinalMaskValidation.isValid("""{"quicParams":{}}"""))
        assertTrue(
            FinalMaskValidation.isValid(
                """{"quicParams":{"congestion":"bbr","debug":false,"bbrProfile":"standard","brutalUp":"10mbps","brutalDown":"20mbps","brutalDisableLossCompensation":false,"initStreamReceiveWindow":65536,"maxStreamReceiveWindow":1048576,"initConnectionReceiveWindow":65536,"maxConnectionReceiveWindow":1048576,"maxIdleTimeout":30,"keepAlivePeriod":10,"disablePathMTUDiscovery":false,"disableChromeParrot":false,"disableGSO":false,"maxIncomingStreams":100,"disableStatelessReset":false}}"""
            )
        )
        assertTrue(FinalMaskValidation.isValid("""{"tcp":null,"tcp4":[{"type":"fragment","settings":{}}]}"""))
    }

    @Test
    fun rejectsSyntacticallyValidJsonThatIsNotAFinalMask() {
        val invalid = listOf(
            """{"tag":"proxy"}""",
            """{"outbounds":[{"tag":"proxy"}]}""",
            """[]""",
            """"proxy"""",
            """{}""",
            """{"tcp":[]}""",
            """{"udp":[]}""",
            """{"tcp":{"type":"fragment","settings":{}}}""",
            """{"tcp":[null]}""",
            """{"tcp":[{}]}""",
            """{"tcp":[{"type":""}]}""",
            """{"tcp":[{"type":"not-a-mask","settings":{}}]}""",
            """{"tcp":[{"type":"noise","settings":{}}]}""",
            """{"udp":[{"type":"tls-record","settings":{"recordVersion":769}}]}""",
            """{"tcp4":[{"type":"noise","settings":{}}]}""",
            """{"udp6":[{"type":"tls-record","settings":{"recordVersion":769}}]}""",
            """{"quicParams":{"unknown":"value"}}""",
            """{"tcp":[{"type":"fragment","settings":[] }]}""",
            """{"tcp":[{"type":"fragment","settings":{},"tag":"proxy"}]}""",
            """{"tcp":[{"type":"fragment","settings":{}}],"unknown":true}""",
            """{"quicParams":[]}""",
            """{"quicParams":{"unknown":"value"}}""",
        )
        invalid.forEach { assertFalse(FinalMaskValidation.isValid(it), it) }
    }

    @Test
    fun rejectsMalformedJson() {
        assertFalse(FinalMaskValidation.isValid("""{"tcp":[{"type":"fragment"}]"""))
        assertFalse(FinalMaskValidation.isValid("{"))
    }
}
