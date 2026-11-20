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
