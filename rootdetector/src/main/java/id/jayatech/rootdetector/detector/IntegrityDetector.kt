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

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // Read the real system prop — set by the bootloader itself at boot,
        // very difficult to fake without also hooking property reads in every process.
        val propBootState = readProp("ro.boot.verifiedbootstate")    // "green" / "orange" / "yellow" / "red"
        val propSecure    = readProp("ro.secure")                    // "0" on unlocked eng builds

        val attest = runKeyAttestation()

        when {
            // Case 1: TEE attestation confirms compromise directly
            attest != null &&
            attest.securityLevel != SecurityLevel.SOFTWARE &&
            (!attest.deviceLocked || attest.bootState != BootState.VERIFIED) -> {
                val secStr  = attest.securityLevel.label
                val stateStr = attest.bootState.name.lowercase().replaceFirstChar { it.uppercaseChar() }
                findings += RootIndicator(
                    id       = "integrity_key_attest",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Hardware Attestation: Boot Integrity Compromised",
                    detail   = "TEE Key Attestation ($secStr) confirms bootloader is unlocked — " +
                                "cannot be spoofed by Magisk DenyList, Shamiko, or any userspace hook",
                    risk     = RiskLevel.HIGH,
                    evidence = listOf(
                        "Attestation source: $secStr",
                        "deviceLocked: ${attest.deviceLocked}",
                        "verifiedBootState: $stateStr"
                    )
                )
            }

            // Case 2: PlayIntegrity Fix / USNF bypass detected
            // Attestation claims locked+verified BUT system prop says bootloader is orange.
            // These two cannot both be true on a genuine device — one of them is lying.
            // The prop is set by the bootloader itself; the attestation is being manipulated.
            attest != null &&
            attest.securityLevel != SecurityLevel.SOFTWARE &&
            attest.deviceLocked && attest.bootState == BootState.VERIFIED &&
            propBootState == "orange" -> {
                findings += RootIndicator(
                    id       = "integrity_attest_bypass",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Key Attestation Bypass Detected",
                    detail   = "TEE claims deviceLocked=true/VERIFIED but ro.boot.verifiedbootstate=orange — " +
                                "a module (PlayIntegrity Fix / USNF) is intercepting Key Attestation at the HAL layer",
                    risk     = RiskLevel.CRITICAL,
                    evidence = listOf(
                        "ro.boot.verifiedbootstate: orange (bootloader unlocked — set by bootloader, hard to fake)",
                        "Key Attestation: deviceLocked=true, verifiedBootState=Verified (contradicts prop → bypass active)",
                        "Common culprits: PlayIntegrity Fix, Universal SafetyNet Fix, MagiskHide Props Config"
                    )
                )
            }

            // Case 3: Software-backed attestation returned (key attestation bypass via software provider)
            // We cannot trust the content, but the fact it's software-backed is itself suspicious.
            attest != null && attest.securityLevel == SecurityLevel.SOFTWARE && propBootState == "orange" -> {
                findings += RootIndicator(
                    id       = "integrity_sw_attest",
                    category = DetectorCategory.INTEGRITY,
                    title    = "Software-Backed Attestation (Bypass Active)",
                    detail   = "Key Attestation returned software-level security (not from TEE) while bootloader prop shows orange — " +
                                "a bypass module replaced hardware attestation with a software implementation",
                    risk     = RiskLevel.HIGH,
                    evidence = listOf(
                        "Attestation security level: Software (should be TEE/StrongBox on real hardware)",
                        "ro.boot.verifiedbootstate: orange"
                    )
                )
            }
        }

        return findings
    }

    private fun runKeyAttestation(): AttestInfo? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return null
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

            if (chain.isNullOrEmpty()) return null
            val cert = chain[0] as? X509Certificate ?: return null
            val extDer = cert.getExtensionValue(ATTESTATION_OID) ?: return null
            parseAttestationExt(extDer)
        } catch (_: Exception) {
            runCatching {
                KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }.deleteEntry(KEY_ALIAS)
            }
            null
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
