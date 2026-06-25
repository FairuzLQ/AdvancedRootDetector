package id.jayatech.rootdetector.detector

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Hardware-backed boot integrity check via Android Key Attestation.
 *
 * Unlike all other detectors (which work in userspace), Key Attestation is
 * executed inside the device's TEE (Trusted Execution Environment) or
 * StrongBox. The attestation certificate is signed by Google's hardware
 * root keys baked into the firmware — it CANNOT be spoofed by:
 *   - Magisk DenyList / Shamiko (userspace mount namespace tricks)
 *   - LSPosed / Xposed hooks (Java-layer only)
 *   - File hiding or prop manipulation
 *
 * The attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) records:
 *   - deviceLocked  : whether the bootloader is locked
 *   - verifiedBootState : VERIFIED / SELF_SIGNED / UNVERIFIED / FAILED
 *
 * We only trust hardware-backed attestation (securityLevel = TEE or StrongBox).
 * Software-backed attestation (emulators / key attestation bypass modules) is
 * explicitly ignored — it can be faked.
 *
 * Limitation: advanced attackers can install "key attestation bypass" Magisk
 * modules that intercept certificate generation at the HAL level. In that case
 * the chain will usually be self-signed (not rooted to Google PKI), which we
 * could detect by verifying the root certificate — not implemented here.
 */
internal class IntegrityDetector(context: Context) : BaseDetector(context) {

    companion object {
        private const val KEY_ALIAS = "rd_attest_v1"
        private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }

    // Sealed class to distinguish WHY attestation did or didn't produce a result
    private sealed class AttestResult {
        object Unsupported   : AttestResult()   // API < 24 or no AndroidKeyStore
        object GenFailed     : AttestResult()   // exception during keygen — bypass may have blocked it
        object ExtStripped   : AttestResult()   // cert exists but attestation OID was removed by bypass
        object ParseFailed   : AttestResult()   // OID present but our ASN.1 parser couldn't read it
        data class Ok(val info: AttestInfo) : AttestResult()
    }

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // ro.boot.verifiedbootstate is written by the bootloader before Android userspace starts.
        // It cannot be intercepted by Magisk module hooks (which only run in userspace).
        val propBoot = readProp("ro.boot.verifiedbootstate")  // "green" / "orange" / "yellow"
        val isOrange = propBoot == "orange"

        val attest = runKeyAttestation()

        when {
            // ── Case 1: TEE/StrongBox directly confirms unlocked bootloader ──────────────
            attest is AttestResult.Ok &&
            attest.info.securityLevel != SecurityLevel.SOFTWARE &&
            (!attest.info.deviceLocked || attest.info.bootState != BootState.VERIFIED) -> {
                val secStr   = attest.info.securityLevel.label
                val stateStr = attest.info.bootState.name.lowercase().replaceFirstChar { it.uppercaseChar() }
                findings += RootIndicator(
                    id       = "integrity_key_attest",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Hardware Attestation: Boot Integrity Compromised",
                    detail   = "TEE Key Attestation ($secStr) directly confirms bootloader is unlocked — " +
                                "this runs in secure hardware, unreachable by Magisk DenyList or any userspace hook",
                    risk     = RiskLevel.HIGH,
                    evidence = listOf(
                        "Attestation source: $secStr",
                        "deviceLocked: ${attest.info.deviceLocked}",
                        "verifiedBootState: $stateStr"
                    )
                )
            }

            // ── Case 2: Content-faked bypass (PlayIntegrity Fix / USNF) ─────────────────
            // Attestation returns locked+VERIFIED but prop says orange.
            // Prop (set by bootloader) and TEE cert cannot legitimately contradict each other.
            attest is AttestResult.Ok &&
            attest.info.securityLevel != SecurityLevel.SOFTWARE &&
            attest.info.deviceLocked && attest.info.bootState == BootState.VERIFIED &&
            isOrange -> {
                findings += RootIndicator(
                    id       = "integrity_attest_bypass",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Key Attestation Bypass Detected (Content Faked)",
                    detail   = "TEE claims deviceLocked=true/VERIFIED but ro.boot.verifiedbootstate=orange — " +
                                "a module is intercepting Key Attestation at the HAL layer and faking the content",
                    risk     = RiskLevel.CRITICAL,
                    evidence = listOf(
                        "ro.boot.verifiedbootstate=orange (set by bootloader — reliable)",
                        "TEE attestation: deviceLocked=true, verifiedBootState=Verified (contradicts prop)",
                        "Likely: PlayIntegrity Fix, Universal SafetyNet Fix, or MagiskHide Props Config"
                    )
                )
            }

            // ── Case 3: OID stripped bypass ──────────────────────────────────────────────
            // KeyPair was generated successfully (bypassed past keygen) but the attestation
            // extension OID is missing from the leaf cert. On real hardware with a properly
            // functioning TEE, setAttestationChallenge ALWAYS produces the OID — its absence
            // means the bypass module removed it after cert generation.
            attest is AttestResult.ExtStripped && isOrange -> {
                findings += RootIndicator(
                    id       = "integrity_attest_stripped",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Key Attestation Bypass Detected (OID Stripped)",
                    detail   = "Key was generated but the attestation certificate has no attestation extension — " +
                                "a bypass module intercepted the HAL and removed the OID to prevent boot state disclosure",
                    risk     = RiskLevel.CRITICAL,
                    evidence = listOf(
                        "ro.boot.verifiedbootstate=orange (unlocked)",
                        "KeyPair generation: succeeded",
                        "Attestation OID (1.3.6.1.4.1.11129.2.1.17): ABSENT from leaf cert",
                        "Likely: PlayIntegrity Fix aggressive mode or similar module"
                    )
                )
            }

            // ── Case 4: Generation blocked by bypass ─────────────────────────────────────
            // Some bypass modules throw an exception to abort attestation entirely.
            // A legitimate device never throws on a standard EC keygen with attestation.
            attest is AttestResult.GenFailed && isOrange -> {
                findings += RootIndicator(
                    id       = "integrity_attest_blocked",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Key Attestation Blocked by Module",
                    detail   = "Key Attestation call threw an exception while bootloader prop shows orange — " +
                                "a bypass module is actively blocking attestation to hide bootloader state",
                    risk     = RiskLevel.HIGH,
                    evidence = listOf(
                        "ro.boot.verifiedbootstate=orange (unlocked)",
                        "KeyPair generation with setAttestationChallenge: FAILED (exception)",
                        "Real hardware never fails this call without a bypass module interfering"
                    )
                )
            }

            // ── Case 5: Software-backed cert returned ────────────────────────────────────
            // Bypass swapped out the TEE with a software KeyStore provider.
            attest is AttestResult.Ok &&
            attest.info.securityLevel == SecurityLevel.SOFTWARE && isOrange -> {
                findings += RootIndicator(
                    id       = "integrity_sw_attest",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Key Attestation Bypass (Software Provider)",
                    detail   = "Key Attestation returned software-level security on physical hardware — " +
                                "a bypass module replaced the TEE provider with a software implementation",
                    risk     = RiskLevel.HIGH,
                    evidence = listOf(
                        "Attestation security level: Software (expected TEE/StrongBox)",
                        "ro.boot.verifiedbootstate=orange"
                    )
                )
            }
        }

        return findings
    }

    private fun runKeyAttestation(): AttestResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return AttestResult.Unsupported
        var certGenerated = false
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
            ks.deleteEntry(KEY_ALIAS)

            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setAttestationChallenge("rootdetector_check_v1".toByteArray())
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build()
                )
            }.generateKeyPair()

            val chain = ks.getCertificateChain(KEY_ALIAS)
            ks.deleteEntry(KEY_ALIAS)

            if (chain.isNullOrEmpty()) return AttestResult.GenFailed
            val cert = chain[0] as? X509Certificate ?: return AttestResult.GenFailed
            certGenerated = true

            // If cert exists but attestation OID is absent → bypass stripped it
            val extDer = cert.getExtensionValue(ATTESTATION_OID)
                ?: return AttestResult.ExtStripped

            val info = parseAttestationExt(extDer) ?: return AttestResult.ParseFailed
            AttestResult.Ok(info)
        } catch (_: Exception) {
            runCatching {
                KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }.deleteEntry(KEY_ALIAS)
            }
            // If cert generation itself threw → bypass blocked us
            if (!certGenerated) AttestResult.GenFailed else AttestResult.ExtStripped
        }
    }

    // -------------------------------------------------------------------------
    // Minimal ASN.1 DER parser for the Key Attestation extension
    //
    // KeyDescription ::= SEQUENCE {
    //   attestationVersion         INTEGER,
    //   attestationSecurityLevel   ENUMERATED,   ← we read this
    //   keymasterVersion           INTEGER,
    //   keymasterSecurityLevel     ENUMERATED,
    //   attestationChallenge       OCTET STRING,
    //   uniqueId                   OCTET STRING,
    //   softwareEnforced           AuthorizationList,
    //   teeEnforced                AuthorizationList  ← scan for rootOfTrust [704]
    // }
    //
    // RootOfTrust ::= SEQUENCE {
    //   verifiedBootKey    OCTET STRING,
    //   deviceLocked       BOOLEAN,              ← we read this
    //   verifiedBootState  ENUMERATED            ← we read this
    // }
    // -------------------------------------------------------------------------

    private enum class SecurityLevel(val label: String) {
        SOFTWARE("Software"), TEE("TrustedEnvironment"), STRONGBOX("StrongBox"), UNKNOWN("Unknown")
    }
    private enum class BootState { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED, UNKNOWN }
    private data class AttestInfo(val securityLevel: SecurityLevel, val deviceLocked: Boolean, val bootState: BootState)

    private fun parseAttestationExt(der: ByteArray): AttestInfo? {
        val ext = unwrapOctetString(der) ?: return null
        return parseKeyDescription(ext)
    }

    private fun unwrapOctetString(b: ByteArray): ByteArray? {
        if (b.isEmpty() || b[0] != 0x04.toByte()) return null
        val (len, off) = derLen(b, 1)
        if (off + len > b.size) return null
        return b.copyOfRange(off, off + len)
    }

    private fun parseKeyDescription(b: ByteArray): AttestInfo? {
        if (b.isEmpty() || b[0] != 0x30.toByte()) return null
        val (_, start) = derLen(b, 1)
        var p = start

        // 1. INTEGER attestationVersion — skip
        p = skipTag(b, p) ?: return null
        // 2. ENUMERATED attestationSecurityLevel — read
        if (p >= b.size || b[p] != 0x0A.toByte()) return null
        val (elLen, elOff) = derLen(b, p + 1)
        val secLevel = when (derReadInt(b, elOff, elLen)) {
            0    -> SecurityLevel.SOFTWARE
            1    -> SecurityLevel.TEE
            2    -> SecurityLevel.STRONGBOX
            else -> SecurityLevel.UNKNOWN
        }
        p = elOff + elLen
        // 3. INTEGER keymasterVersion — skip
        p = skipTag(b, p) ?: return null
        // 4. ENUMERATED keymasterSecurityLevel — skip
        p = skipTag(b, p) ?: return null
        // 5. OCTET STRING attestationChallenge — skip
        p = skipTag(b, p) ?: return null
        // 6. OCTET STRING uniqueId — skip
        p = skipTag(b, p) ?: return null
        // 7. SEQUENCE softwareEnforced — skip
        p = skipTag(b, p) ?: return null
        // 8. SEQUENCE teeEnforced — search for rootOfTrust
        if (p >= b.size || b[p] != 0x30.toByte()) return null
        val (teeLen, teeOff) = derLen(b, p + 1)
        if (teeOff + teeLen > b.size) return null
        val tee = b.copyOfRange(teeOff, teeOff + teeLen)

        val (locked, bootState) = parseRootOfTrust(tee) ?: return null
        return AttestInfo(secLevel, locked, bootState)
    }

    /**
     * Scan teeEnforced AuthorizationList for rootOfTrust.
     * Tag 704 encodes as 0xBF 0x85 0x40:
     *   0xBF = context-specific | constructed | multi-byte-tag
     *   704 in base-128: 704 = 5×128 + 64 → [0x85, 0x40]
     */
    private fun parseRootOfTrust(authList: ByteArray): Pair<Boolean, BootState>? {
        var p = 0
        while (p < authList.size) {
            val tagByte = authList[p].toInt() and 0xFF
            if (tagByte and 0x1F == 0x1F) {
                // Multi-byte tag — find end of tag bytes
                var tagEnd = p + 1
                while (tagEnd < authList.size && (authList[tagEnd].toInt() and 0x80) != 0) tagEnd++
                if (tagEnd >= authList.size) return null
                tagEnd++ // last byte of tag (high bit clear)

                val tagWidth = tagEnd - p
                // Check for tag 704: 0xBF 0x85 0x40
                if (tagWidth == 3 &&
                    tagByte == 0xBF &&
                    (authList[p + 1].toInt() and 0xFF) == 0x85 &&
                    (authList[p + 2].toInt() and 0xFF) == 0x40
                ) {
                    val (innerLen, innerOff) = derLen(authList, tagEnd)
                    if (innerOff + innerLen > authList.size) return null
                    val inner = authList.copyOfRange(innerOff, innerOff + innerLen)
                    return parseRootOfTrustSequence(inner)
                }
                val (skipLen, skipOff) = derLen(authList, tagEnd)
                p = skipOff + skipLen
            } else {
                val (skipLen, skipOff) = derLen(authList, p + 1)
                p = skipOff + skipLen
            }
        }
        return null
    }

    private fun parseRootOfTrustSequence(b: ByteArray): Pair<Boolean, BootState>? {
        if (b.isEmpty() || b[0] != 0x30.toByte()) return null
        val (_, seqOff) = derLen(b, 1)
        var p = seqOff
        // 1. OCTET STRING verifiedBootKey — skip
        p = skipTag(b, p) ?: return null
        // 2. BOOLEAN deviceLocked (tag 0x01)
        if (p >= b.size || b[p] != 0x01.toByte()) return null
        val (bLen, bOff) = derLen(b, p + 1)
        val locked = bOff < b.size && b[bOff] != 0x00.toByte()
        p = bOff + bLen
        // 3. ENUMERATED verifiedBootState (tag 0x0A)
        if (p >= b.size || b[p] != 0x0A.toByte()) return null
        val (eLen, eOff) = derLen(b, p + 1)
        val bootState = when (derReadInt(b, eOff, eLen)) {
            0 -> BootState.VERIFIED
            1 -> BootState.SELF_SIGNED
            2 -> BootState.UNVERIFIED
            3 -> BootState.FAILED
            else -> BootState.UNKNOWN
        }
        return Pair(locked, bootState)
    }

    // --- DER primitives ---

    private fun derLen(b: ByteArray, offset: Int): Pair<Int, Int> {
        if (offset >= b.size) return Pair(0, offset)
        val first = b[offset].toInt() and 0xFF
        return if (first < 0x80) {
            Pair(first, offset + 1)
        } else {
            val n = first and 0x7F
            var len = 0
            for (i in 1..n) {
                if (offset + i >= b.size) return Pair(0, offset)
                len = (len shl 8) or (b[offset + i].toInt() and 0xFF)
            }
            Pair(len, offset + 1 + n)
        }
    }

    private fun skipTag(b: ByteArray, p: Int): Int? {
        if (p >= b.size) return null
        val tagByte = b[p].toInt() and 0xFF
        val tagEnd = if (tagByte and 0x1F == 0x1F) {
            var t = p + 1
            while (t < b.size && (b[t].toInt() and 0x80) != 0) t++
            if (t >= b.size) return null
            t + 1
        } else p + 1
        val (len, off) = derLen(b, tagEnd)
        return if (off + len <= b.size) off + len else null
    }

    private fun derReadInt(b: ByteArray, off: Int, len: Int): Int {
        var r = 0
        for (i in 0 until len) {
            if (off + i >= b.size) break
            r = (r shl 8) or (b[off + i].toInt() and 0xFF)
        }
        return r
    }
}
