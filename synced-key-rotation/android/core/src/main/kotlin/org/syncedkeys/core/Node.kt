package org.syncedkeys.core

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.time.Duration
import java.time.Instant
import java.util.Base64

open class NodeError(message: String) : Exception(message)
open class KeyUnavailable(message: String) : NodeError(message)
class HandshakePending(message: String) : KeyUnavailable(message)
open class MessageRejected(message: String) : NodeError(message)
class ReplayRejected(message: String) : MessageRejected(message)

/** نتيجة استقبال حزمة. */
data class Received(
    val kind: String,                       // "handshake" أو "message" أو "dummy"
    val epoch: Int,
    val texts: List<String> = emptyList(),
    val duplicate: Boolean = false,
    val waiting: Boolean = false,
    val clockSkew: Double? = null,
)

/** حالة فترة واحدة (أسماء السقّاطة كما في المواصفات: DHs, DHr, RK, CKs, CKr, Ns, Nr, PN). */
class EpochState(
    var validFrom: Instant,
    var validUntil: Instant,
    var hsKey: ByteArray,
    var hsPublic: ByteArray,
    var hsPrivate: ByteArray? = null,
    var vaultKey: ByteArray? = null,
    var hsKemPrivate: ByteArray? = null,
    var hsKemPublic: ByteArray? = null,
    var hsKemBox: ByteArray? = null,
    var peerHsPublic: ByteArray? = null,
    var peerHsKemPublic: ByteArray? = null,
    var keyFp: String? = null,
    var headerKey: ByteArray? = null,
    var peerConfirmed: Boolean = false,
    var dhsPrivate: ByteArray? = null,
    var dhsPublic: ByteArray? = null,
    var dhr: ByteArray? = null,
    var kemSPrivate: ByteArray? = null,
    var kemSPublic: ByteArray? = null,
    var kemBoxOut: ByteArray? = null,
    var rk: ByteArray? = null,
    var cks: ByteArray? = null,
    var ckr: ByteArray? = null,
    var ns: Int = 0,
    var nr: Int = 0,
    var pn: Int = 0,
    val skipped: LinkedHashMap<String, ByteArray> = LinkedHashMap(),   // "half_hex:n" → مفتاح
    var oldHalves: MutableList<ByteArray> = mutableListOf(),
) {
    val ready get() = headerKey != null

    fun copy(): EpochState = fromJson(toJson())

    fun toJson(): JSONObject {
        val data = JSONObject()
            .put("valid_from", validFrom.epochSecond).put("valid_until", validUntil.epochSecond)
            .put("key_fp", keyFp ?: JSONObject.NULL).put("peer_confirmed", peerConfirmed)
            .put("ns", ns).put("nr", nr).put("pn", pn)
            .put("skipped", JSONObject().apply { skipped.forEach { (k, v) -> put(k, v.toHex()) } })
            .put("old_halves", JSONArray(oldHalves.map { it.toHex() }))
        for ((name, value) in bytesFields()) data.put(name, value?.toHex() ?: JSONObject.NULL)
        return data
    }

    private fun bytesFields(): List<Pair<String, ByteArray?>> = listOf(
        "hs_key" to hsKey, "hs_public" to hsPublic, "hs_private" to hsPrivate, "vault_key" to vaultKey,
        "hs_kem_private" to hsKemPrivate, "hs_kem_public" to hsKemPublic, "hs_kem_box" to hsKemBox,
        "peer_hs_public" to peerHsPublic, "peer_hs_kem_public" to peerHsKemPublic, "header_key" to headerKey,
        "dhs_private" to dhsPrivate, "dhs_public" to dhsPublic, "dhr" to dhr, "kem_s_private" to kemSPrivate,
        "kem_s_public" to kemSPublic, "kem_box_out" to kemBoxOut, "rk" to rk, "cks" to cks, "ckr" to ckr,
    )

    companion object {
        fun fromJson(d: JSONObject): EpochState {
            fun b(name: String) = if (d.isNull(name)) null else d.getString(name).hexToBytes()
            val state = EpochState(
                Instant.ofEpochSecond(d.getLong("valid_from")), Instant.ofEpochSecond(d.getLong("valid_until")),
                b("hs_key")!!, b("hs_public")!!, b("hs_private"), b("vault_key"), b("hs_kem_private"),
                b("hs_kem_public"), b("hs_kem_box"), b("peer_hs_public"), b("peer_hs_kem_public"),
                if (d.isNull("key_fp")) null else d.getString("key_fp"), b("header_key"),
                d.getBoolean("peer_confirmed"), b("dhs_private"), b("dhs_public"), b("dhr"),
                b("kem_s_private"), b("kem_s_public"), b("kem_box_out"), b("rk"), b("cks"), b("ckr"),
                d.getInt("ns"), d.getInt("nr"), d.getInt("pn"),
            )
            val skipped = d.getJSONObject("skipped")
            for (key in skipped.keys()) state.skipped[key] = skipped.getString(key).hexToBytes()
            val halves = d.getJSONArray("old_halves")
            for (i in 0 until halves.length()) state.oldHalves.add(halves.getString(i).hexToBytes())
            return state
        }
    }
}

/** أسرار الفترة المشتقة من الأقفال الثلاثة. */
class EpochSecrets(val headerKey: ByteArray, val rootKey: ByteArray, val initialChainB: ByteArray, val fingerprint: String)

/**
 * النظام المتصل: مطابق بايتًا ببايت لـ online_node.py.
 * المصافحة الهجينة (الخزنة + X25519 + ML-KEM-1024)، والسقّاطة المزدوجة الهجينة،
 * وطبقتا تشفير، وحزم بطول ثابت ورأس مخفي.
 */
class OnlineNode(var pairId: String? = null, var role: String? = null) {
    val epochs = sortedMapOf<Int, EpochState>()

    val peerRole get() = if (role == "A") "B" else "A"

    // ------------------------------------------------------------------ //
    fun purge(now: Instant) {
        for ((epoch, state) in epochs.entries.toList()) {
            if (!now.isBefore(state.validUntil.plus(GRACE))) epochs.remove(epoch)
            else if (!now.isBefore(state.validUntil) && state.cks != null) state.cks = null
        }
    }

    fun currentState(now: Instant): Pair<Int, EpochState> {
        for ((epoch, state) in epochs) {
            if (!now.isBefore(state.validFrom) && now.isBefore(state.validUntil)) return epoch to state
        }
        throw KeyUnavailable("لا يوجد مفتاح للوقت الحالي: حان موعد تغيير جديد (أو لم يصل أي مفتاح من الجهة الأوفلاين بعد)")
    }

    fun keyFingerprint(now: Instant): String? = try { currentState(now).second.keyFp } catch (e: KeyUnavailable) { null }

    // ------------------------------------------------------------------ //
    // 1) مفتاح الفترة من الجهة الأوفلاين
    // ------------------------------------------------------------------ //
    fun importBundle(bundle: KeyBundle, now: Instant): Int {
        if (bundle.role !in Vault.ROLES) throw NodeError("دور غير معروف في حزمة المفتاح")
        when {
            pairId == null -> { pairId = bundle.pairId; role = bundle.role }
            bundle.pairId != pairId -> throw NodeError("هذا المفتاح صادر من خزنة أخرى غير مقترنة — رُفض")
            bundle.role != role -> throw NodeError("هذا المفتاح صادر من خزنة الطرف الآخر — رُفض")
        }
        if (bundle.key.size != KEY_BYTES) throw NodeError("طول المفتاح غير صحيح")
        if (!bundle.validUntil.isAfter(bundle.validFrom)) throw NodeError("مدة صلاحية المفتاح غير صحيحة")
        purge(now)
        if (!now.isBefore(bundle.validUntil.plus(GRACE))) throw NodeError("مفتاح الفترة ${bundle.epoch} منتهي الصلاحية")
        val state = epochs[bundle.epoch]
        if (state == null) {
            val (private, public) = Crypto.x25519KeyPair()
            val fresh = EpochState(bundle.validFrom, bundle.validUntil, Crypto.oneWay(bundle.key, "handshake"),
                public, hsPrivate = private, vaultKey = bundle.key)
            if (bundle.role == "B") {
                val (kemPrivate, kemPublic) = Crypto.mlkemKeyPair()
                fresh.hsKemPrivate = kemPrivate
                fresh.hsKemPublic = kemPublic
            }
            epochs[bundle.epoch] = fresh
        } else if (!state.ready && !bundle.key.constantEquals(state.vaultKey)) {
            throw NodeError("مفتاح خزنة مختلف لفترة استُورد مفتاحها سابقًا — رُفض")
        }
        return bundle.epoch
    }

    // ------------------------------------------------------------------ //
    // 2) الإرسال
    // ------------------------------------------------------------------ //
    private fun handshakePacket(epoch: Int, state: EpochState, now: Instant): String {
        val (headerKey, bodyKey) = handshakeKeys(state.hsKey)
        val header = packHeader('H', epoch, role!!, state.hsPublic, 0, 0,
            if (role == "A") state.hsKemBox ?: NO_KEM_CT else NO_KEM_CT,
            if (role == "B") state.hsKemPublic!! else NO_KEM_PUBLIC)
        val payload = byteArrayOf(if (state.ready) 1 else 0) + ByteBuffer.allocate(8).putLong(now.epochSecond).array()
        return seal(headerKey, bodyKey, header, payload)
    }

    fun myHandshake(now: Instant): String {
        val (epoch, state) = currentState(now)
        return handshakePacket(epoch, state, now)
    }

    fun sealPacket(texts: List<String>, now: Instant): String {
        purge(now)
        val (epoch, state) = currentState(now)
        if (!state.ready) throw HandshakePending("مفتاح هذه الفترة غير مكتمل: بانتظار اكتمال المصافحة مع الطرف الآخر")
        val cks = state.cks ?: throw KeyUnavailable("هذه الفترة انتهت وأُتلفت سلسلة إرسالها")
        val payload = encodePassengers(texts)
        val messageKey = chainMessageKey(cks)
        val header = packHeader('M', epoch, role!!, state.dhsPublic!!, state.pn, state.ns,
            state.kemBoxOut!!, state.kemSPublic!!)
        state.cks = chainNext(cks)
        state.ns += 1
        return seal(state.headerKey!!, messageKey, header, payload)
    }

    fun send(text: String, now: Instant): String {
        if (text.toByteArray(Charsets.UTF_8).size > MAX_TEXT_BYTES) {
            throw NodeError("النص أطول من الحد المسموح ($MAX_TEXT_BYTES بايت)؛ قسّمه إلى عدة رسائل")
        }
        return sealPacket(listOf(text), now)
    }

    fun sendDummy(now: Instant) = sealPacket(emptyList(), now)

    // ------------------------------------------------------------------ //
    // 3) الاستقبال
    // ------------------------------------------------------------------ //
    fun receive(packet: String, now: Instant): Received {
        val raw = decodePacket(packet)
        if (role == null) throw KeyUnavailable("لم يصل أي مفتاح من الجهة الأوفلاين بعد")
        purge(now)
        for ((epoch, state) in epochs.entries.reversed()) {
            if (state.ready) {
                openHeader(state.headerKey!!, raw)?.let { return receiveMessage(epoch, state, it, raw, now) }
            }
            openHeader(handshakeKeys(state.hsKey).first, raw)?.let { return receiveHandshake(epoch, state, it, raw, now) }
        }
        throw MessageRejected("تعذّر فتح الحزمة بأي مفتاح متاح: مزوّرة أو معدّلة أو ضجيج، أو لفترة لم يصل مفتاحها بعد، أو قديمة")
    }

    private class Header(val kind: Char, val version: Int, val epoch: Int, val role: String, val half: ByteArray,
                         val pn: Int, val n: Int, val box: ByteArray, val kemPublic: ByteArray)

    private fun parseHeader(bytes: ByteArray, kind: Char, epoch: Int): Header {
        val b = ByteBuffer.wrap(bytes)
        val header = Header(b.get().toInt().toChar(), b.get().toInt() and 0xff, b.getInt(), b.get().toInt().toChar().toString(),
            ByteArray(DH_BYTES).also { b.get(it) }, b.getInt(), b.getInt(),
            ByteArray(KEM_CT_BYTES).also { b.get(it) }, ByteArray(KEM_PUBLIC_BYTES).also { b.get(it) })
        if (header.kind != kind || header.version != FORMAT_VERSION || header.epoch != epoch) {
            throw MessageRejected("رأس الحزمة غير متّسق — رُفضت")
        }
        if (header.role !in Vault.ROLES) throw MessageRejected("دور غير معروف في الحزمة — رُفضت")
        if (header.role == role) throw MessageRejected("هذه حزمة صادرة منك أنت أُعيدت إليك — رُفضت")
        return header
    }

    private fun receiveHandshake(epoch: Int, state: EpochState, headerBytes: ByteArray, raw: ByteArray, now: Instant): Received {
        val h = parseHeader(headerBytes, 'H', epoch)
        val body = openBody(handshakeKeys(state.hsKey).second, raw, headerBytes)
        val peerReady = body[0].toInt() == 1
        val skew = (ByteBuffer.wrap(body, 1, 8).long - now.epochSecond).toDouble()
        val hasBox = !h.box.constantEquals(NO_KEM_CT)

        if (state.ready) {
            var consistent = h.half.constantEquals(state.peerHsPublic)
            if (role == "A") consistent = consistent && h.kemPublic.constantEquals(state.peerHsKemPublic)
            else if (hasBox) consistent = consistent && h.box.constantEquals(state.hsKemBox)
            if (!consistent) throw MessageRejected("مصافحة مختلفة لفترة اكتملت مصافحتها — رُفضت")
            if (peerReady) state.peerConfirmed = true
            return Received("handshake", epoch, duplicate = true, clockSkew = skew)
        }

        val dhShared = Crypto.dh(state.hsPrivate!!, h.half)
        val secrets: EpochSecrets
        if (role == "A") {
            if (h.kemPublic.constantEquals(NO_KEM_PUBLIC)) throw MessageRejected("قفل ML-KEM مفقود — رُفض")
            val (kemShared, box) = Crypto.mlkemLock(h.kemPublic)
            state.hsKemBox = box
            state.peerHsKemPublic = h.kemPublic
            secrets = deriveEpoch(state.vaultKey!!, epoch, dhShared, kemShared, state.hsPublic, h.half, h.kemPublic, box)
        } else {
            if (!hasBox) return Received("handshake", epoch, waiting = true, clockSkew = skew)
            val kemShared = Crypto.mlkemUnlock(state.hsKemPrivate!!, h.box)
            state.hsKemBox = h.box
            secrets = deriveEpoch(state.vaultKey!!, epoch, dhShared, kemShared, h.half, state.hsPublic, state.hsKemPublic!!, h.box)
        }
        state.headerKey = secrets.headerKey
        state.keyFp = secrets.fingerprint
        state.peerHsPublic = h.half
        if (role == "A") {
            val (dhsPrivate, dhsPublic) = Crypto.x25519KeyPair()
            val (kemPrivate, kemPublic) = Crypto.mlkemKeyPair()
            state.dhsPrivate = dhsPrivate; state.dhsPublic = dhsPublic
            state.kemSPrivate = kemPrivate; state.kemSPublic = kemPublic
            state.dhr = h.half
            val (kemOut, box) = Crypto.mlkemLock(h.kemPublic)
            state.kemBoxOut = box
            val (rk, cks) = kdfRoot(secrets.rootKey, Crypto.dh(dhsPrivate, h.half), kemOut)
            state.rk = rk; state.cks = cks
            state.ckr = secrets.initialChainB
        } else {
            state.dhsPrivate = state.hsPrivate; state.dhsPublic = state.hsPublic
            state.kemSPrivate = state.hsKemPrivate; state.kemSPublic = state.hsKemPublic
            state.kemBoxOut = NO_KEM_CT
            state.dhr = null
            state.rk = secrets.rootKey
            state.cks = secrets.initialChainB
            state.ckr = null
        }
        state.ns = 0; state.nr = 0; state.pn = 0
        state.peerConfirmed = peerReady
        state.hsPrivate = null; state.hsKemPrivate = null; state.vaultKey = null    // نُتلف ما لم نعد نحتاجه
        return Received("handshake", epoch, clockSkew = skew)
    }

    private fun receiveMessage(epoch: Int, state: EpochState, headerBytes: ByteArray, raw: ByteArray, now: Instant): Received {
        val h = parseHeader(headerBytes, 'M', epoch)
        val work = state.copy()          // نعمل على نسخة، ولا نعتمدها إلا بعد نجاح التحقق
        val skipKey = "${h.half.toHex()}:${h.n}"
        val messageKey: ByteArray
        if (work.skipped.containsKey(skipKey)) {
            messageKey = work.skipped.remove(skipKey)!!
        } else {
            val isCurrent = work.dhr != null && h.half.constantEquals(work.dhr)
            val replay = (!isCurrent && work.oldHalves.any { h.half.constantEquals(it) }) || (isCurrent && h.n < work.nr)
            if (replay) throw ReplayRejected("هذه الرسالة قُرئت من قبل، أو أنها إعادة إرسال لرسالة مسجّلة — رُفضت")
            if (!isCurrent) {
                skip(work, h.pn)
                ratchet(work, h.half, h.box, h.kemPublic)
            }
            skip(work, h.n)
            messageKey = chainMessageKey(work.ckr!!)
            work.ckr = chainNext(work.ckr!!)
            work.nr += 1
        }
        val texts = decodePassengers(openBody(messageKey, raw, headerBytes))
        work.peerConfirmed = true
        if (!now.isBefore(work.validUntil)) work.cks = null
        epochs[epoch] = work                  // التحقق نجح: نعتمد الحالة الجديدة
        return Received(if (texts.isEmpty()) "dummy" else "message", epoch, texts)
    }

    private fun skip(work: EpochState, until: Int) {
        val ckr = work.ckr ?: return
        if (until - work.nr > MAX_SKIP) throw MessageRejected("رقم الرسالة بعيد جدًا عن المتوقع — رُفضت")
        var chain = ckr
        while (work.nr < until) {
            work.skipped["${work.dhr!!.toHex()}:${work.nr}"] = chainMessageKey(chain)
            chain = chainNext(chain)
            work.nr += 1
        }
        work.ckr = chain
        while (work.skipped.size > MAX_STORED_SKIPPED) work.skipped.remove(work.skipped.keys.first())
    }

    private fun ratchet(work: EpochState, half: ByteArray, box: ByteArray, kemPublic: ByteArray) {
        if (box.constantEquals(NO_KEM_CT) || kemPublic.constantEquals(NO_KEM_PUBLIC)) {
            throw MessageRejected("خطوة سقّاطة بلا حماية ML-KEM — رُفضت")
        }
        work.dhr?.let { work.oldHalves = (work.oldHalves + it).takeLast(MAX_OLD_HALVES).toMutableList() }
        work.pn = work.ns; work.ns = 0; work.nr = 0
        work.dhr = half
        val kemIn = Crypto.mlkemUnlock(work.kemSPrivate!!, box)
        val (rk1, ckr) = kdfRoot(work.rk!!, Crypto.dh(work.dhsPrivate!!, half), kemIn)
        work.rk = rk1; work.ckr = ckr
        val (dhsPrivate, dhsPublic) = Crypto.x25519KeyPair()
        val (kemPrivate, kemPublicMine) = Crypto.mlkemKeyPair()
        work.dhsPrivate = dhsPrivate; work.dhsPublic = dhsPublic
        work.kemSPrivate = kemPrivate; work.kemSPublic = kemPublicMine
        val (kemOut, boxOut) = Crypto.mlkemLock(kemPublic)
        work.kemBoxOut = boxOut
        val (rk2, cks) = kdfRoot(rk1, Crypto.dh(dhsPrivate, half), kemOut)
        work.rk = rk2; work.cks = cks
    }

    // ------------------------------------------------------------------ //
    fun toJson(): JSONObject = JSONObject()
        .put("format", "online-node").put("version", FORMAT_VERSION)
        .put("pair_id", pairId ?: JSONObject.NULL).put("role", role ?: JSONObject.NULL)
        .put("epochs", JSONObject().apply { epochs.forEach { (e, s) -> put(e.toString(), s.toJson()) } })

    companion object {
        const val FORMAT_VERSION = 3
        const val KEY_BYTES = 32
        const val DH_BYTES = 32
        const val KEM_PUBLIC_BYTES = 1568
        const val KEM_CT_BYTES = 1568
        const val NONCE_BYTES = 12
        const val TAG_BYTES = 16
        const val PACKET_BYTES = 6144
        const val HEADER_BYTES = 1 + 1 + 4 + 1 + DH_BYTES + 4 + 4 + KEM_CT_BYTES + KEM_PUBLIC_BYTES
        const val SEALED_HEADER_BYTES = HEADER_BYTES + TAG_BYTES
        const val BODY_OFFSET = NONCE_BYTES + SEALED_HEADER_BYTES
        const val BODY_PLAIN_BYTES = PACKET_BYTES - BODY_OFFSET - 2 * TAG_BYTES
        const val MAX_TEXT_BYTES = BODY_PLAIN_BYTES - 1 - 2
        val GRACE: Duration = Duration.ofHours(12)
        const val MAX_SKIP = 1000
        const val MAX_STORED_SKIPPED = 2000
        const val MAX_OLD_HALVES = 64
        val NO_KEM_CT = ByteArray(KEM_CT_BYTES)
        val NO_KEM_PUBLIC = ByteArray(KEM_PUBLIC_BYTES)

        fun fromJson(data: JSONObject): OnlineNode {
            if (data.optString("format") != "online-node" || data.optInt("version") != FORMAT_VERSION) {
                throw NodeError("ملف غير صالح")
            }
            val node = OnlineNode(if (data.isNull("pair_id")) null else data.getString("pair_id"),
                if (data.isNull("role")) null else data.getString("role"))
            val epochs = data.getJSONObject("epochs")
            for (key in epochs.keys()) node.epochs[key.toInt()] = EpochState.fromJson(epochs.getJSONObject(key))
            return node
        }

        fun chainMessageKey(chain: ByteArray) = Crypto.oneWay(chain, "msg:key")
        fun chainNext(chain: ByteArray) = Crypto.oneWay(chain, "msg:next")
        fun layerKeys(key: ByteArray) = Crypto.oneWay(key, "layer:aes") to Crypto.oneWay(key, "layer:chacha")
        fun handshakeKeys(hsKey: ByteArray) = Crypto.oneWay(hsKey, "hs:header") to Crypto.oneWay(hsKey, "hs:body")

        fun kdfRoot(rootKey: ByteArray, dh: ByteArray, kem: ByteArray): Pair<ByteArray, ByteArray> {
            val out = Crypto.hkdf(dh + kem, rootKey, "ratchet:root:hybrid".toByteArray(), 2 * KEY_BYTES)
            return out.copyOfRange(0, KEY_BYTES) to out.copyOfRange(KEY_BYTES, 2 * KEY_BYTES)
        }

        /** مفتاح الفترة = الخزنة + X25519 + ML-KEM، مع ربط كل ما تبادله الطرفان. */
        fun deriveEpoch(vaultKey: ByteArray, epoch: Int, dh: ByteArray, kem: ByteArray, pubA: ByteArray,
                        pubB: ByteArray, kemPublicB: ByteArray, kemBox: ByteArray): EpochSecrets {
            val transcript = ByteBuffer.allocate(4).putInt(epoch).array() + pubA + pubB +
                Crypto.sha256(kemPublicB) + Crypto.sha256(kemBox)
            val epochKey = Crypto.hkdf(dh + kem, Crypto.oneWay(vaultKey, "epoch-mix"),
                "epoch-key:hybrid|".toByteArray() + transcript, KEY_BYTES)
            return EpochSecrets(Crypto.oneWay(epochKey, "header"), Crypto.oneWay(epochKey, "root"),
                Crypto.oneWay(epochKey, "chain:B:initial"), Crypto.fingerprint(epochKey, "epoch-key"))
        }

        /** رقم صندوق البريد: سري ويتغيّر مع كل فترة (مطابق لـ messenger.py). */
        fun mailboxFor(state: EpochState, role: String) =
            Crypto.oneWay(state.hsKey, "mailbox:$role").copyOf(16).toHex()

        fun packHeader(kind: Char, epoch: Int, role: String, half: ByteArray, pn: Int, n: Int,
                       box: ByteArray, kemPublic: ByteArray): ByteArray =
            ByteBuffer.allocate(HEADER_BYTES).put(kind.code.toByte()).put(FORMAT_VERSION.toByte()).putInt(epoch)
                .put(role[0].code.toByte()).put(half).putInt(pn).putInt(n).put(box).put(kemPublic).array()

        fun encodePassengers(texts: List<String>): ByteArray {
            if (texts.size > 255) throw NodeError("عدد الرسائل في الحزمة كبير جدًا")
            val out = java.io.ByteArrayOutputStream()
            out.write(texts.size)
            for (text in texts) {
                val data = text.toByteArray(Charsets.UTF_8)
                out.write(data.size shr 8); out.write(data.size and 0xff); out.write(data)
            }
            if (out.size() > BODY_PLAIN_BYTES) throw NodeError("النص أطول من الحد المسموح ($MAX_TEXT_BYTES بايت)")
            return out.toByteArray()
        }

        fun passengersFit(texts: List<String>) =
            1 + texts.sumOf { 2 + it.toByteArray(Charsets.UTF_8).size } <= BODY_PLAIN_BYTES

        fun decodePassengers(body: ByteArray): List<String> {
            try {
                val count = body[0].toInt() and 0xff
                var position = 1
                return List(count) {
                    val size = ((body[position].toInt() and 0xff) shl 8) or (body[position + 1].toInt() and 0xff)
                    position += 2
                    if (position + size > body.size) throw IndexOutOfBoundsException()
                    String(body, position, size, Charsets.UTF_8).also { position += size }
                }
            } catch (e: IndexOutOfBoundsException) {
                throw MessageRejected("محتوى الحزمة غير متّسق — رُفضت")
            }
        }

        fun seal(headerKey: ByteArray, bodyKey: ByteArray, header: ByteArray, payload: ByteArray): String {
            val nonce = Crypto.secureRandom(NONCE_BYTES)
            val body = payload.copyOf(BODY_PLAIN_BYTES)                       // حشو بأصفار حتى الطول الثابت
            val (kAes, kChacha) = layerKeys(bodyKey)
            val inner = Crypto.aesGcmSeal(kAes, nonce, body, header)          // الطبقة 1
            val outer = Crypto.chachaSeal(kChacha, nonce, inner, header)      // الطبقة 2
            val sealedHeader = Crypto.aesGcmSeal(headerKey, nonce, header, null)
            return Base64.getUrlEncoder().encodeToString(nonce + sealedHeader + outer)
        }

        fun decodePacket(packet: String): ByteArray {
            val raw = try {
                Base64.getUrlDecoder().decode(packet.trim())
            } catch (e: IllegalArgumentException) {
                throw MessageRejected("النص ليس حزمة صالحة")
            }
            if (raw.size != PACKET_BYTES) throw MessageRejected("طول الحزمة غير صحيح")
            return raw
        }

        fun randomFiller(): String = Base64.getUrlEncoder().encodeToString(Crypto.secureRandom(PACKET_BYTES))

        fun openHeader(headerKey: ByteArray, raw: ByteArray): ByteArray? = try {
            Crypto.aesGcmOpen(headerKey, raw.copyOf(NONCE_BYTES), raw.copyOfRange(NONCE_BYTES, BODY_OFFSET), null)
        } catch (e: CryptoFailure) {
            null
        }

        fun openBody(bodyKey: ByteArray, raw: ByteArray, header: ByteArray): ByteArray {
            val nonce = raw.copyOf(NONCE_BYTES)
            val (kAes, kChacha) = layerKeys(bodyKey)
            return try {
                val inner = Crypto.chachaOpen(kChacha, nonce, raw.copyOfRange(BODY_OFFSET, raw.size), header)
                Crypto.aesGcmOpen(kAes, nonce, inner, header)
            } catch (e: CryptoFailure) {
                throw MessageRejected("فشل التحقق: الحزمة مُعدّلة أو مزوّرة — رُفضت")
            }
        }
    }
}
