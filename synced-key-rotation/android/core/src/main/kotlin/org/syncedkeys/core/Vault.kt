package org.syncedkeys.core

import org.json.JSONObject
import java.time.Instant

/** خطأ في الخزنة. */
class VaultError(message: String) : Exception(message)

/** مفتاح فترة واحدة، كما تُخرجه الخزنة. */
data class KeyBundle(
    val pairId: String,
    val role: String,
    val epoch: Int,
    val validFrom: Instant,
    val validUntil: Instant,
    val key: ByteArray,
)

/**
 * الخزنة (الجهة الأوفلاين): مطابقة بايتًا ببايت لـ offline_vault.py.
 *
 *   بذرة ──► سلسلة(1) ──► سلسلة(2) ──► ...
 *              ├► مفتاح(1)   ├► مفتاح(2)
 *              └► مدة(1)     └► مدة(2)      (المدة عشوائية سرية بين حدّين)
 *
 * تتقدّم في اتجاه واحد فقط وتُتلف حالتها القديمة.
 */
class Vault(
    val pairId: String,
    val role: String,
    val minSeconds: Long,
    val maxSeconds: Long,
    epoch: Int,
    epochStart: Instant,
    chainKey: ByteArray,
    releasedEpoch: Int? = null,
) {
    var epoch: Int = epoch
        private set
    var epochStart: Instant = epochStart
        private set
    private var chainKey: ByteArray = chainKey
    var releasedEpoch: Int? = releasedEpoch
        private set

    init {
        if (role !in ROLES) throw VaultError("دور غير معروف: $role")
        if (chainKey.size != SEED_BYTES) throw VaultError("حالة الخزنة تالفة")
    }

    /** موعد التغيير القادم (سري). */
    fun nextChange(): Instant = epochStart.plusSeconds(periodLength(chainKey, minSeconds, maxSeconds))

    fun upcomingChanges(count: Int): List<Instant> {
        var chain = chainKey
        var start = epochStart
        return List(count) {
            start = start.plusSeconds(periodLength(chain, minSeconds, maxSeconds))
            chain = nextChainKey(chain)
            start
        }
    }

    private fun advanceTo(now: Instant) {
        if (now.isBefore(epochStart)) {
            throw VaultError("الوقت المطلوب أقدم من حالة الخزنة: مفاتيحه أُتلفت نهائيًا (السرية الأمامية)")
        }
        while (!now.isBefore(nextChange())) {
            epochStart = nextChange()
            chainKey = nextChainKey(chainKey)
            epoch += 1
        }
    }

    /** يُخرج مفتاح الفترة الحالية فقط. */
    fun release(now: Instant): KeyBundle {
        advanceTo(now)
        releasedEpoch = epoch
        return KeyBundle(pairId, role, epoch, epochStart, nextChange(), deriveVaultKey(chainKey))
    }

    /** مثل release، لكن لا يُخرج شيئًا إذا لم يحن موعد تغيير جديد. */
    fun releaseIfNew(now: Instant): KeyBundle? {
        advanceTo(now)
        return if (releasedEpoch == epoch) null else release(now)
    }

    fun toJson(): JSONObject = JSONObject()
        .put("format", "offline-vault").put("version", FORMAT_VERSION)
        .put("pair_id", pairId).put("role", role)
        .put("min_seconds", minSeconds).put("max_seconds", maxSeconds)
        .put("epoch", epoch).put("epoch_start", epochStart.epochSecond)
        .put("chain_key", chainKey.toHex())
        .put("released_epoch", releasedEpoch ?: JSONObject.NULL)

    companion object {
        const val FORMAT_VERSION = 3
        const val SEED_BYTES = 32
        val ROLES = listOf("A", "B")
        private const val PAIRING_VERSION = 1
        private val PAIRING_ORIGIN: Instant = Instant.parse("2020-01-01T00:00:00Z")
        private const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        fun nextChainKey(chain: ByteArray) = Crypto.oneWay(chain, "chain:next")
        fun deriveVaultKey(chain: ByteArray) = Crypto.oneWay(chain, "vault:key")

        fun periodLength(chain: ByteArray, minSeconds: Long, maxSeconds: Long): Long {
            val span = maxSeconds - minSeconds + 1
            val bytes = Crypto.oneWay(chain, "schedule:length")
            var value = 0L
            for (i in 0 until 8) value = (value shl 8) or (bytes[i].toLong() and 0xff)
            return minSeconds + java.lang.Long.remainderUnsigned(value, span)
        }

        fun fromJson(data: JSONObject): Vault {
            if (data.optString("format") != "offline-vault" || data.optInt("version") != FORMAT_VERSION) {
                throw VaultError("هذا الملف ليس خزنة صالحة")
            }
            return Vault(
                data.getString("pair_id"), data.getString("role"),
                data.getLong("min_seconds"), data.getLong("max_seconds"),
                data.getInt("epoch"), Instant.ofEpochSecond(data.getLong("epoch_start")),
                data.getString("chain_key").hexToBytes(),
                if (data.isNull("released_epoch")) null else data.getInt("released_epoch"),
            )
        }

        fun fromSeed(seed: ByteArray, role: String, epochStart: Instant, minSeconds: Long, maxSeconds: Long) =
            Vault(Crypto.fingerprint(seed, "pair"), role, minSeconds, maxSeconds, 0, epochStart, seed)

        /** حدود المدة العشوائية بين تغييرين (مقرّبة إلى الدقيقة). */
        fun scheduleSeconds(minHours: Double, maxHours: Double): Pair<Long, Long> {
            val min = Math.round(minHours * 60) * 60
            val max = Math.round(maxHours * 60) * 60
            if (min < 60) throw VaultError("أقصر مدة بين تغييرين يجب أن تكون دقيقة واحدة على الأقل")
            if (max < min) throw VaultError("أطول مدة يجب أن تكون أكبر من أقصر مدة أو مساوية لها")
            return min to max
        }

        // ------------------------------------------------------------------ //
        // طقس البذرة
        // ------------------------------------------------------------------ //
        fun parseDice(text: String): List<Int> = text.mapNotNull { ch ->
            when {
                ch in " \t\n,،;-" -> null
                ch in '1'..'6' -> ch - '0'
                else -> throw VaultError("قيمة غير صالحة في رميات النرد: '$ch' (المسموح من 1 إلى 6 فقط)")
            }
        }

        fun mixSeed(sources: List<Pair<String, ByteArray>>): ByteArray {
            val mac = org.bouncycastle.crypto.macs.HMac(org.bouncycastle.crypto.digests.SHA256Digest())
            mac.init(org.bouncycastle.crypto.params.KeyParameter("seed-mix|v3".toByteArray()))
            for ((label, value) in sources) {
                val name = label.toByteArray(Charsets.UTF_8)
                val chunk = beInt(name.size, 2) + name + beInt(value.size, 4) + value
                mac.update(chunk, 0, chunk.size)
            }
            return ByteArray(32).also { mac.doFinal(it, 0) }
        }

        fun makeSeed(peerRandomness: ByteArray? = null, dice: String? = null): ByteArray {
            val sources = mutableListOf("this-device" to Crypto.secureRandom(SEED_BYTES))
            if (peerRandomness != null) {
                if (peerRandomness.size < 16) throw VaultError("عشوائية الطرف الآخر قصيرة جدًا")
                sources += "peer-device" to peerRandomness
            }
            if (!dice.isNullOrBlank()) {
                val rolls = parseDice(dice)
                if (rolls.isNotEmpty()) sources += "dice" to ByteArray(rolls.size) { rolls[it].toByte() }
            }
            return mixSeed(sources)
        }

        // ------------------------------------------------------------------ //
        // رمز الاقتران (مطابق لبايثون: يمكن الاقتران بين هاتف وحاسوب)
        // ------------------------------------------------------------------ //
        fun encodePairingCode(seed: ByteArray, epochStart: Instant, minSeconds: Long, maxSeconds: Long): String {
            val minutes = (epochStart.epochSecond - PAIRING_ORIGIN.epochSecond) / 60
            val payload = byteArrayOf(PAIRING_VERSION.toByte()) + seed + beInt(minutes.toInt(), 4) +
                beInt((minSeconds / 60).toInt(), 2) + beInt((maxSeconds / 60).toInt(), 2)
            val check = Crypto.sha256("pairing-check|".toByteArray() + payload).copyOf(3)
            return base32(payload + check).chunked(4).joinToString("-")
        }

        data class PairingData(val seed: ByteArray, val epochStart: Instant, val minSeconds: Long, val maxSeconds: Long)

        fun decodePairingCode(code: String): PairingData {
            val text = code.uppercase().filter { it.isLetterOrDigit() }
            val raw = unbase32(text) ?: throw VaultError("رمز الاقتران غير صالح: تحقق من الحروف")
            if (raw.size != 1 + SEED_BYTES + 8 + 3 || raw[0].toInt() != PAIRING_VERSION) {
                throw VaultError("رمز الاقتران غير صالح: طوله غير صحيح")
            }
            val payload = raw.copyOf(raw.size - 3)
            val check = raw.copyOfRange(raw.size - 3, raw.size)
            if (!check.constantEquals(Crypto.sha256("pairing-check|".toByteArray() + payload).copyOf(3))) {
                throw VaultError("رمز الاقتران غير صحيح: يوجد خطأ في الكتابة")
            }
            val seed = payload.copyOfRange(1, 1 + SEED_BYTES)
            val rest = payload.copyOfRange(1 + SEED_BYTES, payload.size)
            val start = PAIRING_ORIGIN.plusSeconds(readBe(rest, 0, 4) * 60)
            val min = readBe(rest, 4, 2) * 60
            val max = readBe(rest, 6, 2) * 60
            if (min < 60 || max < min) throw VaultError("رمز الاقتران غير صالح")
            return PairingData(seed, start, min, max)
        }

        private fun beInt(value: Int, bytes: Int) = ByteArray(bytes) { (value ushr (8 * (bytes - 1 - it))).toByte() }

        private fun readBe(data: ByteArray, offset: Int, length: Int): Long {
            var value = 0L
            for (i in 0 until length) value = (value shl 8) or (data[offset + i].toLong() and 0xff)
            return value
        }

        private fun base32(data: ByteArray): String {
            val out = StringBuilder()
            var buffer = 0
            var bits = 0
            for (byte in data) {
                buffer = (buffer shl 8) or (byte.toInt() and 0xff)
                bits += 8
                while (bits >= 5) {
                    out.append(BASE32[(buffer shr (bits - 5)) and 31])
                    bits -= 5
                }
            }
            if (bits > 0) out.append(BASE32[(buffer shl (5 - bits)) and 31])
            return out.toString()
        }

        private fun unbase32(text: String): ByteArray? {
            val out = java.io.ByteArrayOutputStream()
            var buffer = 0
            var bits = 0
            for (ch in text) {
                val value = BASE32.indexOf(ch)
                if (value < 0) return null
                buffer = (buffer shl 5) or value
                bits += 5
                if (bits >= 8) {
                    out.write((buffer shr (bits - 8)) and 0xff)
                    bits -= 8
                }
            }
            return out.toByteArray()
        }
    }
}
