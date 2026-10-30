package com.keyvault.vpn

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class PacketCipher(key: ByteArray) {
    private val secretKey = SecretKeySpec(key, "AES")
    private val rng = SecureRandom()
    private val serpent = Serpent256(key)

    fun encrypt(plain: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val serpentOut = serpentCtr(plain, nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
        val ct = cipher.doFinal(serpentOut)
        val result = ByteArray(2 + 12 + ct.size)
        result[0] = (ct.size ushr 8).toByte()
        result[1] = ct.size.toByte()
        System.arraycopy(nonce, 0, result, 2, 12)
        System.arraycopy(ct, 0, result, 14, ct.size)
        return result
    }

    private fun serpentCtr(plain: ByteArray, nonce: ByteArray): ByteArray {
        val out = ByteArray(plain.size)
        val ks = ByteArray(16)
        var ctr = 0; var off = 0
        while (off < plain.size) {
            val blk = ByteArray(16)
            System.arraycopy(nonce, 0, blk, 0, 12)
            blk[12] = (ctr ushr 24).toByte(); blk[13] = (ctr ushr 16).toByte()
            blk[14] = (ctr ushr 8).toByte(); blk[15] = ctr.toByte()
            serpent.encryptBlock(blk, 0, ks, 0)
            val n = minOf(16, plain.size - off)
            for (i in 0 until n) out[off + i] = (plain[off + i].toInt() xor ks[i].toInt()).toByte()
            off += n; ctr++
        }
        return out
    }
}
