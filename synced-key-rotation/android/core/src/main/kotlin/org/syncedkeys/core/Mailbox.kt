package org.syncedkeys.core

import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.time.Duration
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/*
 * صندوق البريد داخل الهاتف نفسه
 * ==============================
 * نفس عمل relay_server.py، لكن في التطبيق: الهاتف المضيف يحمل الصناديق، ويصل إليه
 * الطرف الآخر من أي مكان عبر عنوان ‎.onion على شبكة Tor (انظر SocksRelay).
 */

/** طول الحزمة بعد ترميز base64 (مطابق لـ PACKET_CHARS في relay_server.py). */
const val PACKET_CHARS = (OnlineNode.PACKET_BYTES + 2) / 3 * 4

private val PACKET_PATTERN = Regex("""\A[A-Za-z0-9_\-]+={0,2}\z""")
private val BOX_PATTERN = Regex("""\A/box/([0-9a-f]{32})\z""")

/**
 * الصناديق في الذاكرة فقط (لا شيء يُكتب على القرص)، كل حزمة تُحذف بعد 24 ساعة.
 *
 * حماية الهاتف من الإغراق: [isKnown] يعرّف صناديق المحادثة نفسها (يحسبها الهاتف المضيف من
 * مفاتيحه). من يعرف العنوان ولا يعرف المفاتيح لا يستطيع إلا ملء حصة صغيرة للصناديق
 * الغريبة ([maxStrangerPackets])، فلا يملأ الذاكرة ولا يزاحم المحادثة.
 */
class MailboxStore(
    private val ttl: Duration = Duration.ofHours(24),
    private val maxPacketsPerBox: Int = 1000,
    private val maxBoxes: Int = 10_000,
    private val maxStrangerPackets: Int = Int.MAX_VALUE,
    private val isKnown: (String) -> Boolean = { true },
    private val clock: () -> Long = System::nanoTime,
) {
    private val boxes = LinkedHashMap<String, ArrayDeque<Pair<Long, String>>>()
    private val strangers = LinkedHashSet<String>()         // صناديق لا يعرفها الهاتف المضيف (الأقدم أولًا)

    fun put(box: String, packet: String): Boolean {
        val known = isKnown(box)                             // خارج القفل: قد يسأل المحرك
        synchronized(this) {
            expire()
            if (!known && strangers.sumOf { boxes[it]?.size ?: 0 } >= maxStrangerPackets) return false
            val queue = boxes[box] ?: run {
                if (boxes.size >= maxBoxes) {
                    // لا يستطيع الغرباء أن يمنعوا صندوقًا لمحادثتنا: نُخرج أقدم صندوق غريب
                    val victim = strangers.firstOrNull()?.takeIf { known } ?: return false
                    boxes.remove(victim)
                    strangers -= victim
                }
                ArrayDeque<Pair<Long, String>>().also { boxes[box] = it }
            }
            if (known) strangers -= box else strangers += box
            queue.addLast(clock() to packet)
            while (queue.size > maxPacketsPerBox) queue.removeFirst()
            return true
        }
    }

    @Synchronized fun take(box: String): List<String> {
        expire()
        strangers -= box
        return boxes.remove(box)?.map { it.second } ?: emptyList()
    }

    @Synchronized fun count(): Int = boxes.values.sumOf { it.size }

    private fun expire() {
        val limit = clock() - ttl.toNanos()
        val iterator = boxes.entries.iterator()
        while (iterator.hasNext()) {
            val (box, queue) = iterator.next()
            while (queue.isNotEmpty() && queue.first().first - limit < 0) queue.removeFirst()
            if (queue.isEmpty()) { iterator.remove(); strangers -= box }
        }
    }
}

/** الهاتف المضيف يستعمل صناديقه مباشرة، بلا شبكة. */
class LocalRelay(private val store: MailboxStore) : Relay {
    override fun put(box: String, packet: String) {
        if (!store.put(box, packet)) throw IOException("صندوق البريد ممتلئ")
    }

    override fun take(box: String): List<String> = store.take(box)
}

/**
 * خادم HTTP صغير جدًا أمام [MailboxStore] (نفس بروتوكول relay_server.py، فيتحدث معه
 * messenger.py على الحاسوب أيضًا). يستمع على 127.0.0.1 فقط: لا يصل إليه أحد من الشبكة
 * المحلية، وإنما من شبكة Tor عبر خدمة ‎.onion التي تحوّل إليه.
 * لا يسجّل شيئًا.
 */
class RelayServer(
    private val store: MailboxStore,
    host: String = "127.0.0.1",
    port: Int = 0,
    workers: Int = 8,
    private val timeoutMs: Int = 30_000,
) : AutoCloseable {
    private val server = ServerSocket(port, 50, InetAddress.getByName(host))
    val port: Int get() = server.localPort
    @Volatile private var closed = false
    private val pool = ThreadPoolExecutor(1, workers, 30, TimeUnit.SECONDS, ArrayBlockingQueue(64),
        { r -> Thread(r, "relay").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())

    init {
        Thread({ acceptLoop() }, "relay-accept").apply { isDaemon = true }.start()
    }

    private fun acceptLoop() {
        while (!closed) {
            val socket = try { server.accept() } catch (e: SocketException) { break } catch (e: IOException) { continue }
            try {
                pool.execute { socket.use { serve(it) } }
            } catch (e: Exception) {
                socket.close()                                  // مشغول جدًا: نرفض بدل التكدّس
            }
        }
    }

    private fun serve(socket: Socket) {
        socket.soTimeout = timeoutMs
        val input = BufferedInputStream(socket.getInputStream())
        val out = socket.getOutputStream()
        try {
            val request = Http.readHead(input, isRequest = true) ?: return
            val parts = request.first.split(' ')
            if (parts.size != 3 || !parts[2].startsWith("HTTP/1.")) return reply(out, 400)
            val (method, path) = parts
            val headers = request.second
            if (headers.containsKey("transfer-encoding")) return reply(out, 400)
            if (method == "GET" && path == "/health") return reply(out, 200, "ok".toByteArray())
            val box = BOX_PATTERN.find(path)?.groupValues?.get(1) ?: return reply(out, 404)
            when (method) {
                "GET" -> {
                    val body = store.take(box).joinToString(",", "{\"packets\": [", "]}") { "\"$it\"" }
                    reply(out, 200, body.toByteArray(Charsets.US_ASCII), "application/json")
                }
                "POST" -> {
                    val length = headers["content-length"]?.toIntOrNull() ?: return reply(out, 400)
                    if (length != PACKET_CHARS) return reply(out, 400, "wrong packet size".toByteArray())
                    val packet = Http.readExactly(input, length).toString(Charsets.US_ASCII)
                    if (!PACKET_PATTERN.matches(packet)) return reply(out, 400, "not a packet".toByteArray())
                    if (!store.put(box, packet)) return reply(out, 503, "full".toByteArray())
                    reply(out, 204)
                }
                else -> reply(out, 405)
            }
        } catch (e: IOException) {
            // اتصال ناقص أو بطيء جدًا: نغلقه بصمت
        }
    }

    private fun reply(out: OutputStream, status: Int, body: ByteArray = ByteArray(0), kind: String = "text/plain") {
        val head = "HTTP/1.1 $status ${REASONS[status] ?: "Error"}\r\n" +
            "Content-Type: $kind\r\nContent-Length: ${body.size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        out.write(head.toByteArray(Charsets.US_ASCII))
        out.write(body)
        out.flush()
    }

    override fun close() {
        closed = true
        server.close()
        pool.shutdownNow()
    }

    companion object {
        private val REASONS = mapOf(200 to "OK", 204 to "No Content", 400 to "Bad Request", 404 to "Not Found",
            405 to "Method Not Allowed", 503 to "Service Unavailable")
    }
}

/** قراءة رأس HTTP/1.1 بحدود صارمة (لا نثق بما يصل). */
internal object Http {
    private const val MAX_LINE = 8 * 1024
    private const val MAX_HEADERS = 64

    fun readLine(input: InputStream): String? {
        val buffer = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) return if (buffer.size() == 0) null else throw IOException("سطر ناقص")
            if (b == '\n'.code) break
            if (buffer.size() >= MAX_LINE) throw IOException("سطر طويل جدًا")
            buffer.write(b)
        }
        return buffer.toString(Charsets.ISO_8859_1.name()).removeSuffix("\r")
    }

    /** السطر الأول + الرؤوس (بأسماء صغيرة). */
    fun readHead(input: InputStream, isRequest: Boolean): Pair<String, Map<String, String>>? {
        val first = readLine(input) ?: return null
        if (first.isEmpty() && isRequest) return null
        val headers = mutableMapOf<String, String>()
        var count = 0
        while (true) {
            val line = readLine(input) ?: throw IOException("رأس ناقص")
            if (line.isEmpty()) break
            if (++count > MAX_HEADERS) throw IOException("رؤوس كثيرة جدًا")
            val colon = line.indexOf(':')
            if (colon <= 0) throw IOException("رأس غير صالح")
            headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
        }
        return first to headers
    }

    fun readExactly(input: InputStream, length: Int): ByteArray {
        val data = ByteArray(length)
        var read = 0
        while (read < length) {
            val n = input.read(data, read, length - read)
            if (n < 0) throw IOException("انقطع الاتصال")
            read += n
        }
        return data
    }

    fun readAll(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val chunk = ByteArray(16 * 1024)
        while (true) {
            val n = input.read(chunk)
            if (n < 0) return out.toByteArray()
            out.write(chunk, 0, n)
            if (out.size() > limit) throw IOException("رد كبير جدًا")
        }
    }
}

/** عنوان صندوق البريد كما يكتبه المستخدم: عنوان ‎.onion أو رابط http(s). */
sealed class RelayAddress {
    data class Onion(val host: String) : RelayAddress()
    data class Web(val url: String) : RelayAddress()

    companion object {
        private val ONION = Regex("""[a-z2-7]{56}\.onion""")

        /**
         * يقبل ما يلصقه الناس عادةً: مسافات، أحرف كبيرة، http:// أمام ‎.onion، شرطة في الآخر،
         * أو الرسالة كاملة التي أرسلها زر «مشاركة» (نأخذ منها العنوان).
         */
        fun parse(input: String): RelayAddress {
            val text = input.trim().trimEnd('/')
            if (text.isEmpty()) throw IllegalArgumentException("اكتب عنوان صندوق البريد")
            val lower = text.lowercase()
            if (lower.contains(".onion")) {
                val found = ONION.findAll(lower).map { it.value }.toSet()
                val words = Regex("""[a-z2-7]+\.onion""").findAll(lower).map { it.value }.toSet()
                if (found.size != 1 || words != found) {
                    throw IllegalArgumentException("عنوان ‎.onion غير صحيح: يجب أن يكون 56 حرفًا قبل ‎.onion (انسخه كاملًا)")
                }
                return Onion(found.single())
            }
            if (!text.startsWith("http://") && !text.startsWith("https://")) {
                throw IllegalArgumentException("العنوان يجب أن ينتهي بـ ‎.onion أو يبدأ بـ http:// أو https://")
            }
            return Web(text)
        }
    }
}

/**
 * الوصول إلى صندوق بريد ‎.onion عبر Tor: Tor يفتح على الهاتف نفسه منفذ SOCKS5، ونطلب منه
 * الاتصال بالاسم (لا نحوّل ‎.onion إلى عنوان IP أبدًا، فهو لا يُحلّ إلا داخل Tor).
 * مسار الحزمة: هاتفك ← 3 مرحّلات Tor ← 3 مرحّلات للهاتف المضيف ← صندوق البريد.
 * لا يعرف أي طرف عنوان IP للآخر، ولا يرى المراقب على شبكتك إلا أنك تستعمل Tor.
 */
class SocksRelay(
    private val host: String,
    private val port: Int = 80,
    private val socksPort: () -> Int,
    private val socksHost: String = "127.0.0.1",
    private val timeoutMs: Int = 60_000,
) : Relay {
    override fun put(box: String, packet: String) {
        val (status, _) = request("POST", "/box/$box", packet.toByteArray(Charsets.US_ASCII))
        if (status != 204) throw IOException("صندوق البريد رفض الحزمة: $status")
    }

    override fun take(box: String): List<String> {
        val (status, body) = request("GET", "/box/$box", null)
        if (status != 200) throw IOException("خطأ من صندوق البريد: $status")
        val array = JSONObject(body.toString(Charsets.UTF_8)).getJSONArray("packets")
        return List(array.length()) { array.getString(it) }
    }

    /** هل يمكن الوصول إلى الصندوق الآن؟ */
    fun health(): Boolean = try {
        val (status, body) = request("GET", "/health", null)
        status == 200 && body.toString(Charsets.US_ASCII) == "ok"
    } catch (e: IOException) {
        false
    }

    private fun request(method: String, path: String, body: ByteArray?): Pair<Int, ByteArray> {
        val proxyPort = socksPort()
        if (proxyPort <= 0) throw IOException("Tor لم يجهز بعد")
        Socket().use { socket ->
            socket.connect(InetSocketAddress(socksHost, proxyPort), timeoutMs)
            socket.soTimeout = timeoutMs
            val out = socket.getOutputStream()
            val input = BufferedInputStream(socket.getInputStream())
            Socks5.connect(out, input, host, port)
            val head = StringBuilder("$method $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n")
            if (body != null) head.append("Content-Type: text/plain\r\nContent-Length: ${body.size}\r\n")
            head.append("\r\n")
            out.write(head.toString().toByteArray(Charsets.US_ASCII))
            body?.let(out::write)
            out.flush()
            val (statusLine, headers) = Http.readHead(input, isRequest = false) ?: throw IOException("لا رد")
            val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: throw IOException("رد غير مفهوم")
            val length = headers["content-length"]?.toIntOrNull()
            val data = if (length != null) {
                if (length > MAX_REPLY) throw IOException("رد كبير جدًا")
                Http.readExactly(input, length)
            } else Http.readAll(input, MAX_REPLY)
            return status to data
        }
    }

    companion object {
        const val MAX_REPLY = 12 * 1024 * 1024
    }
}

/** عميل SOCKS5 (RFC 1928) بأقل ما يلزم: بلا كلمة سر، والوجهة بالاسم. */
internal object Socks5 {
    fun connect(out: OutputStream, input: InputStream, host: String, port: Int) {
        val name = host.toByteArray(Charsets.US_ASCII)
        require(name.size in 1..255)
        out.write(byteArrayOf(5, 1, 0))                     // الإصدار 5، طريقة واحدة: بلا مصادقة
        out.flush()
        val method = Http.readExactly(input, 2)
        if (method[0] != 5.toByte() || method[1] != 0.toByte()) throw IOException("وكيل SOCKS غير متوافق")
        val request = ByteArrayOutputStream()
        request.write(byteArrayOf(5, 1, 0, 3, name.size.toByte()))   // CONNECT بالاسم (النوع 3)
        request.write(name)
        request.write(byteArrayOf((port shr 8).toByte(), port.toByte()))
        out.write(request.toByteArray())
        out.flush()
        val reply = Http.readExactly(input, 4)
        if (reply[0] != 5.toByte()) throw IOException("وكيل SOCKS غير متوافق")
        val code = reply[1].toInt() and 0xff
        if (code != 0) throw IOException(explain(code))
        val skip = when (reply[3].toInt()) {
            1 -> 4
            4 -> 16
            3 -> input.read().also { if (it < 0) throw IOException("انقطع الاتصال") }
            else -> throw IOException("رد SOCKS غير مفهوم")
        }
        Http.readExactly(input, skip + 2)                   // العنوان والمنفذ المربوطان: لا نحتاجهما
    }

    fun explain(code: Int): String = when (code) {
        4, 0xF0, 0xF2, 0xF3, 0xF4, 0xF6, 0xF7 ->
            "صندوق البريد غير متاح الآن (هاتف المضيف مطفأ أو غير متصل، أو لم يُنشر العنوان بعد)"
        6 -> "انتهت المهلة قبل الوصول إلى صندوق البريد"
        0xF1 -> "عنوان ‎.onion غير صحيح"
        0xF5 -> "عنوان ‎.onion محمي ويحتاج مفتاحًا"
        else -> "تعذّر الاتصال عبر Tor (الرمز $code)"
    }
}
