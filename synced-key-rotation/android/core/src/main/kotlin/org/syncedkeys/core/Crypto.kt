package org.syncedkeys.core

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/** فشل التحقق من حزمة مشفرة (تعديل أو تزوير). */
class CryptoFailure(message: String) : Exception(message)

/** مولّد العشوائية أعطى نتيجة مشبوهة؛ البرنامج يرفض الاستمرار. */
class RandomnessFailure(message: String) : Exception(message)

/**
 * الأدوات التشفيرية، مطابقة بايتًا ببايت لنسخة بايثون (common.py و online_node.py).
 * كلها من مكتبة BouncyCastle المعروفة، لا شيء مخترع.
 */
object Crypto {
    private val system = SecureRandom()
    private val recentOutputs = ArrayDeque<String>()

    /**
     * عشوائية حقيقية من النظام مع فحص صحة: يرفض المخرجات المتكررة أو المتشابهة
     * بشكل غير طبيعي (أعطال من نوع PlayStation 3 و Debian).
     */
    @Synchronized
    fun secureRandom(size: Int, source: ((Int) -> ByteArray)? = null): ByteArray {
        val data = source?.invoke(size) ?: ByteArray(size).also { system.nextBytes(it) }
        if (data.size != size) throw RandomnessFailure("مولّد العشوائية لم يُعطِ العدد المطلوب من البايتات")
        if (size >= 12) {
            if (data.toSet().size < minOf(size / 4, 64)) {
                throw RandomnessFailure("مخرجات مولّد العشوائية متشابهة بشكل غير طبيعي — توقف البرنامج احتياطًا")
            }
            val digest = sha256(data).toHex()
            if (digest in recentOutputs) {
                throw RandomnessFailure("مولّد العشوائية كرر نتيجة سابقة حرفيًا — توقف البرنامج احتياطًا")
            }
            recentOutputs.addLast(digest)
            if (recentOutputs.size > 256) recentOutputs.removeFirst()
        }
        return data
    }

    fun sha256(data: ByteArray): ByteArray {
        val digest = SHA256Digest()
        digest.update(data, 0, data.size)
        return ByteArray(32).also { digest.doFinal(it, 0) }
    }

    /** دالة باتجاه واحد: HMAC-SHA256(key, label). */
    fun oneWay(key: ByteArray, label: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(label, 0, label.size)
        return ByteArray(32).also { mac.doFinal(it, 0) }
    }

    fun oneWay(key: ByteArray, label: String): ByteArray = oneWay(key, label.toByteArray(Charsets.UTF_8))

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info))
        return ByteArray(length).also { generator.generateBytes(it, 0, length) }
    }

    /** بصمة قصيرة لسرّ (مثل XXXX-XXXX-XXXX-XXXX) لا تكشفه. */
    fun fingerprint(secret: ByteArray, purpose: String): String {
        val digest = sha256("fingerprint|$purpose|".toByteArray(Charsets.UTF_8) + secret).toHex()
            .substring(0, 16).uppercase()
        return digest.chunked(4).joinToString("-")
    }

    // ------------------------------------------------------------------ //
    // التشفير المتماثل: AES-256-GCM و ChaCha20-Poly1305 (الناتج = نص مشفر + ختم 16 بايت)
    // ------------------------------------------------------------------ //
    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plain: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        return runCipher(cipher::getOutputSize, cipher::processBytes, cipher::doFinal, plain)
    }

    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
        return try {
            runCipher(cipher::getOutputSize, cipher::processBytes, cipher::doFinal, sealed)
        } catch (e: Exception) {
            throw CryptoFailure("فشل التحقق")
        }
    }

    fun chachaSeal(key: ByteArray, nonce: ByteArray, plain: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        return runCipher(cipher::getOutputSize, cipher::processBytes, cipher::doFinal, plain)
    }

    fun chachaOpen(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
        return try {
            runCipher(cipher::getOutputSize, cipher::processBytes, cipher::doFinal, sealed)
        } catch (e: Exception) {
            throw CryptoFailure("فشل التحقق")
        }
    }

    private inline fun runCipher(
        outputSize: (Int) -> Int,
        process: (ByteArray, Int, Int, ByteArray, Int) -> Int,
        finish: (ByteArray, Int) -> Int,
        input: ByteArray,
    ): ByteArray {
        val out = ByteArray(outputSize(input.size))
        var length = process(input, 0, input.size, out, 0)
        length += finish(out, length)
        return if (length == out.size) out else out.copyOf(length)
    }

    // ------------------------------------------------------------------ //
    // X25519 (Diffie-Hellman)
    // ------------------------------------------------------------------ //
    /** سرّ عشوائي جديد (مفحوص) ونصفه العام. */
    fun x25519KeyPair(): Pair<ByteArray, ByteArray> {
        val private = secureRandom(32)
        return private to x25519Public(private)
    }

    fun x25519Public(private: ByteArray): ByteArray =
        X25519PrivateKeyParameters(private, 0).generatePublicKey().encoded

    fun dh(private: ByteArray, public: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(private, 0))
        val out = ByteArray(32)
        try {
            agreement.calculateAgreement(X25519PublicKeyParameters(public, 0), out, 0)
        } catch (e: Exception) {
            throw CryptoFailure("نصف عام غير صالح")
        }
        return out
    }

    // ------------------------------------------------------------------ //
    // ML-KEM-1024 (المقاوم للحاسوب الكمّي): المفتاح الخاص = بذرة 64 بايت
    // ------------------------------------------------------------------ //
    const val KEM_SEED_BYTES = 64

    fun mlkemKeyPair(): Pair<ByteArray, ByteArray> {
        val seed = secureRandom(KEM_SEED_BYTES)
        return seed to mlkemPublic(seed)
    }

    fun mlkemPublic(seed: ByteArray): ByteArray =
        MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, seed).publicKeyParameters.encoded

    /** يضع سرًا عشوائيًا في صندوق مقفل بالقفل public: (السرّ، الصندوق). */
    fun mlkemLock(public: ByteArray): Pair<ByteArray, ByteArray> {
        val key = try {
            MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, public)
        } catch (e: Exception) {
            throw CryptoFailure("قفل ML-KEM غير صالح")
        }
        val result = MLKEMGenerator(system).generateEncapsulated(key)
        return result.secret to result.encapsulation
    }

    fun mlkemUnlock(seed: ByteArray, box: ByteArray): ByteArray =
        MLKEMExtractor(MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, seed)).extractSecret(box)
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "طول غير صحيح" }
    return ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

fun ByteArray.constantEquals(other: ByteArray?): Boolean =
    other != null && java.security.MessageDigest.isEqual(this, other)
