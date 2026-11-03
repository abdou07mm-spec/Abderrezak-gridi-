package org.syncedkeys.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** خادم الترحيل (صناديق البريد): نفس واجهة relay_server.py. */
interface Relay {
    fun put(box: String, packet: String)
    fun take(box: String): List<String>
}

class HttpRelay(baseUrl: String, private val timeoutMs: Int = 10_000) : Relay {
    private val base = baseUrl.trimEnd('/')

    override fun put(box: String, packet: String) {
        val connection = URL("$base/box/$box").openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "text/plain")
            connection.outputStream.use { it.write(packet.toByteArray(Charsets.US_ASCII)) }
            if (connection.responseCode != 204) throw java.io.IOException("الخادم رفض الحزمة: ${connection.responseCode}")
        } finally {
            connection.disconnect()
        }
    }

    override fun take(box: String): List<String> {
        val connection = URL("$base/box/$box").openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            if (connection.responseCode != 200) throw java.io.IOException("خطأ من الخادم: ${connection.responseCode}")
            val text = connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            val array = JSONObject(text).getJSONArray("packets")
            return List(array.length()) { array.getString(it) }
        } finally {
            connection.disconnect()
        }
    }
}

data class Departure(val time: Instant, val packet: String, val kind: String, val texts: List<String> = emptyList())

/**
 * الحافلة (مطابقة لـ bus.py): حزمة في مواعيد عشوائية، حقيقية أو وهمية أو مصافحة أو ضجيج.
 */
class Bus(private val node: OnlineNode, var nextDeparture: Instant,
          private val minGap: Duration, private val maxGap: Duration) {
    val queue = ArrayDeque<Pair<Instant, String>>()

    fun enqueue(text: String, now: Instant) {
        if (text.toByteArray(Charsets.UTF_8).size > OnlineNode.MAX_TEXT_BYTES) {
            throw NodeError("النص أطول من الحد المسموح (${OnlineNode.MAX_TEXT_BYTES} بايت)")
        }
        queue.addLast(now to text)
    }

    fun departuresUntil(now: Instant): List<Departure> {
        val out = mutableListOf<Departure>()
        while (!nextDeparture.isAfter(now)) {
            out += depart(nextDeparture)
            nextDeparture = nextDeparture.plus(randomGap(minGap, maxGap))
        }
        return out
    }

    private fun depart(moment: Instant): Departure {
        val state = try {
            node.currentState(moment).second
        } catch (e: KeyUnavailable) {
            return Departure(moment, OnlineNode.randomFiller(), "noise")
        }
        if (!state.ready || !state.peerConfirmed) return Departure(moment, node.myHandshake(moment), "handshake")
        val riders = mutableListOf<Pair<Instant, String>>()
        while (queue.isNotEmpty() && OnlineNode.passengersFit(riders.map { it.second } + queue.first().second)) {
            riders += queue.removeFirst()
        }
        val packet = try {
            node.sealPacket(riders.map { it.second }, moment)
        } catch (e: KeyUnavailable) {
            riders.asReversed().forEach { queue.addFirst(it) }          // الركاب ينتظرون الحافلة التالية
            return Departure(moment, OnlineNode.randomFiller(), "noise")
        }
        return Departure(moment, packet, if (riders.isEmpty()) "dummy" else "message", riders.map { it.second })
    }

    companion object {
        val MIN_GAP: Duration = Duration.ofSeconds(150)
        val MAX_GAP: Duration = Duration.ofSeconds(450)

        fun randomGap(min: Duration, max: Duration): Duration {
            val bytes = Crypto.secureRandom(16)
            var value = 0L
            for (i in 0 until 8) value = (value shl 8) or (bytes[i].toLong() and 0xff)
            val fraction = (value ushr 11).toDouble() / (1L shl 53).toDouble()
            return min.plusMillis(((max.toMillis() - min.toMillis()) * fraction).toLong())
        }
    }
}

/**
 * قلب التطبيق (مطابق لـ messenger.py): الحافلة + صناديق البريد + مفاتيح الجهة الأوفلاين.
 * لا يعرف شيئًا عن أندرويد، فيُختبر على الحاسوب مباشرة.
 */
class MessengerEngine(
    val node: OnlineNode,
    var relay: Relay?,
    var name: String = "",
    minGap: Duration = Bus.MIN_GAP,
    maxGap: Duration = Bus.MAX_GAP,
    private val pollEvery: Duration = Duration.ofSeconds(20),
    now: Instant = Instant.now(),
    private val offlineStale: Duration = Duration.ofMinutes(2),
    private val persist: (OnlineNode) -> Unit = {},
) {
    private val lock = Any()
    val bus = Bus(node, now.plus(Bus.randomGap(minGap, maxGap)), minGap, maxGap)
    private var nextPoll = now
    val outbox = ArrayDeque<Pair<String, String>>()
    val log = mutableListOf<JSONObject>()
    private var nextId = 1
    val stats = linkedMapOf("packets_out" to 0, "packets_in" to 0, "dummies_in" to 0, "unopened" to 0)
    var relayOk: Boolean? = null
        private set
    private var lastPeerBox: String? = null
    private var lastError: String? = null
    private val skewWarned = mutableSetOf<Int>()
    private var offlineIsolation: String? = null
    private var offlineHeartbeat: Instant? = null

    fun note(who: String, text: String, moment: Instant) {
        log += JSONObject().put("id", nextId++).put("who", who).put("text", text)
            .put("time", TIME.format(moment.atZone(ZoneId.systemDefault())))
        while (log.size > 1000) log.removeAt(0)
    }

    private fun errorOnce(text: String, now: Instant) {
        if (text != lastError) { lastError = text; note("system", text, now) }
    }

    /**
     * مفتاح فترة وصل من الجهة الأوفلاين (مع نبضتها).
     * adoptNewPairing: إذا كان المصدر موثوقًا (في أندرويد: تطبيق بالتوقيع نفسه فقط) وجاء
     * مفتاح من اقتران جديد، نترك الاقتران القديم ونبدأ من جديد بدل رفض كل المفاتيح.
     */
    fun deliverKey(bundle: KeyBundle, isolation: String, now: Instant, adoptNewPairing: Boolean = false) = synchronized(lock) {
        offlineIsolation = isolation
        offlineHeartbeat = now
        val oldPair = node.pairId
        if (adoptNewPairing && oldPair != null && oldPair != bundle.pairId) {
            node.pairId = null
            node.role = null
            node.epochs.clear()
            outbox.clear()                 // حزم الاقتران القديم لم تعد مفهومة لأحد
            lastPeerBox = null
            skewWarned.clear()
            note("system", "اقتران جديد في الخزنة (بصمة ${bundle.pairId}): نُسي الاقتران السابق وبدأنا من جديد.", now)
        }
        val known = node.epochs.containsKey(bundle.epoch)
        try {
            node.importBundle(bundle, now)
            persist(node)
            if (!known) note("system", "وصل مفتاح الفترة ${bundle.epoch} من الجهة الأوفلاين (تغيير سري). " +
                "المصافحة الهجينة تركب الحافلات التالية.", now)
        } catch (e: NodeError) {
            errorOnce("تعذّر استيراد مفتاح الخزنة: ${e.message}", now)
        }
    }

    fun enqueue(text: String) = synchronized(lock) { bus.enqueue(text, Instant.now()) }

    /** دورة واحدة: إطلاق الحافلات، والإرسال، وتفقّد الصندوق. */
    fun step(now: Instant = Instant.now()) {
        val relay = relay ?: return
        val outgoing: List<Pair<String, String>>
        var boxes = emptyList<String>()
        synchronized(lock) {
            val departures = bus.departuresUntil(now)
            for (departure in departures) load(departure)
            if (departures.isNotEmpty()) persist(node)        // كل حزمة تُقدّم السلاسل: نحفظ قبل الإرسال
            outgoing = outbox.toList()
            if (!now.isBefore(nextPoll)) {
                nextPoll = now.plus(pollEvery)
                node.role?.let { role -> boxes = node.epochs.values.map { OnlineNode.mailboxFor(it, role) } }
            }
        }
        var sent = 0
        for ((box, packet) in outgoing) {                   // الشبكة خارج القفل
            try { relay.put(box, packet); sent++; relayOk = true } catch (e: Exception) { relayOk = false; break }
        }
        val fetched = mutableListOf<String>()
        for (box in boxes) {
            try { fetched += relay.take(box); relayOk = true } catch (e: Exception) { relayOk = false }
        }
        synchronized(lock) {
            repeat(sent) { outbox.removeFirst() }
            stats["packets_out"] = stats["packets_out"]!! + sent
            for (packet in fetched) receive(packet, now)
            if (fetched.isNotEmpty()) persist(node)
        }
    }

    private fun load(departure: Departure) {
        val box = try {
            OnlineNode.mailboxFor(node.currentState(departure.time).second, node.peerRole)
        } catch (e: KeyUnavailable) {
            lastPeerBox                                        // ضجيج: إلى آخر صندوق معروف
        } ?: return
        lastPeerBox = box
        outbox.addLast(box to departure.packet)
        while (outbox.size > 2000) outbox.removeFirst()
        for (text in departure.texts) note("me", text, departure.time)
    }

    private fun receive(packet: String, now: Instant) {
        val result = try {
            node.receive(packet, now)
        } catch (e: NodeError) {
            stats["unopened"] = stats["unopened"]!! + 1
            return
        }
        stats["packets_in"] = stats["packets_in"]!! + 1
        when (result.kind) {
            "message" -> result.texts.forEach { note("peer", it, now) }
            "dummy" -> stats["dummies_in"] = stats["dummies_in"]!! + 1
        }
        val skew = result.clockSkew
        if (result.kind == "handshake" && skew != null && skew > CLOCK_WARNING_SECONDS && skewWarned.add(result.epoch)) {
            note("system", "⚠ ساعة الطرف الآخر متقدّمة على ساعتك بحوالي ${Math.round(skew / 60)} دقيقة على الأقل. " +
                "اطلبا من الجهازين ضبط الوقت تلقائيًا.", now)
        }
        if (result.kind == "handshake" && !result.duplicate && !result.waiting) {
            note("system", "اكتملت المصافحة الهجينة للفترة ${result.epoch}. بصمة المفتاح: ${node.epochs[result.epoch]?.keyFp}", now)
        }
    }

    /** الحالة للواجهة (نفس شكل /api/state في messenger.py). */
    fun snapshot(afterId: Int, now: Instant = Instant.now()): JSONObject = synchronized(lock) {
        val current = try { node.currentState(now) } catch (e: KeyUnavailable) { null }
        val state = current?.second
        val offline = offlineHeartbeat?.let {
            JSONObject().put("isolation", offlineIsolation).put("alive", Duration.between(it, now) < offlineStale)
        }
        JSONObject()
            .put("name", name).put("role", node.role ?: JSONObject.NULL)
            .put("epoch", current?.first ?: JSONObject.NULL)
            .put("ready", state?.ready == true).put("confirmed", state?.peerConfirmed == true)
            .put("fingerprint", state?.keyFp ?: JSONObject.NULL)
            .put("next_bus", maxOf(0.0, Duration.between(now, bus.nextDeparture).toMillis() / 1000.0))
            .put("queue", JSONArray(bus.queue.map { it.second }))
            .put("relay_ok", relayOk ?: JSONObject.NULL)
            .put("offline", offline ?: JSONObject.NULL)
            .put("stats", JSONObject(stats as Map<*, *>))
            .put("messages", JSONArray(log.filter { it.getInt("id") > afterId }))
            .put("max_text", OnlineNode.MAX_TEXT_BYTES)
    }

    companion object {
        const val CLOCK_WARNING_SECONDS = 120.0
        private val TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")
    }
}
