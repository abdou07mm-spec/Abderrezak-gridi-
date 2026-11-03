package org.syncedkeys.core

import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.time.Duration
import java.time.Instant
import java.util.Collections
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * يقوم مقام Tor في الاختبار: وكيل SOCKS5 يعرف عنوان ‎.onion واحدًا ويوصله بصندوق البريد.
 * يسجّل ما طُلب منه، لنتأكد أن العنوان يصل بالاسم ولا يُحوَّل إلى IP على الهاتف.
 */
class FakeTor(private val onion: String, private val targetPort: Int) : AutoCloseable {
    private val server = ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort
    val requested: MutableList<Pair<Int, String>> = Collections.synchronizedList(mutableListOf())

    init {
        Thread {
            while (true) {
                val client = try { server.accept() } catch (e: IOException) { break }
                Thread { handle(client) }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true }.start()
    }

    private fun handle(client: Socket) = client.use {
        val input = DataInputStream(BufferedInputStream(client.getInputStream()))
        val out = client.getOutputStream()
        input.readByte(); val methods = input.readUnsignedByte(); input.skipBytes(methods)
        out.write(byteArrayOf(5, 0))
        input.readByte(); input.readByte(); input.readByte()
        val type = input.readUnsignedByte()
        val name = when (type) {
            3 -> ByteArray(input.readUnsignedByte()).also { input.readFully(it) }.toString(Charsets.US_ASCII)
            1 -> ByteArray(4).also { input.readFully(it) }.joinToString(".") { (it.toInt() and 0xff).toString() }
            else -> ByteArray(16).also { input.readFully(it) }.toString()
        }
        val port = input.readUnsignedShort()
        requested += type to "$name:$port"
        if (type != 3 || name != onion || port != 80) {
            out.write(byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0))     // Tor: الخدمة غير موجودة
            return@use
        }
        Socket("127.0.0.1", targetPort).use { target ->
            out.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0))
            val up = Thread { try { input.copyTo(target.getOutputStream()); target.shutdownOutput() } catch (e: IOException) {} }
            up.start()
            try { target.getInputStream().copyTo(out) } catch (e: IOException) {}
            up.join(2000)
        }
    }

    override fun close() = server.close()
}

class MailboxTest {
    private val onion = "a".repeat(52) + "bcd2.onion"
    private val closers = mutableListOf<AutoCloseable>()
    private fun <T : AutoCloseable> keep(c: T): T = c.also { closers += it }

    @AfterTest fun cleanup() = closers.asReversed().forEach { it.close() }

    private fun packet() = OnlineNode.randomFiller()

    // ------------------------------------------------------------------ //
    // صندوق البريد نفسه
    // ------------------------------------------------------------------ //
    @Test fun `strangers get a small quota and cannot crowd out the conversation`() {
        val ours = setOf("1".repeat(32), "2".repeat(32))
        val store = MailboxStore(maxPacketsPerBox = 50, maxBoxes = 64, maxStrangerPackets = 10, isKnown = { it in ours })
        repeat(10) { assertTrue(store.put("f".repeat(31) + it.toString(16), "x")) }
        assertFalse(store.put("e".repeat(32), "x"))                   // الحصة الغريبة امتلأت
        repeat(50) { assertTrue(store.put("1".repeat(32), "p$it")) }  // صندوقنا يعمل كالعادة
        assertTrue(store.put("1".repeat(32), "p50"))
        assertEquals(50, store.take("1".repeat(32)).size)            // الأقدم يُحذف عند الامتلاء
        store.take("f".repeat(31) + "0")
        assertTrue(store.put("e".repeat(32), "x"))                    // أُفرغ صندوق غريب: مكان جديد
    }

    @Test fun `strangers cannot use up the box slots either`() {
        val ours = mutableSetOf<String>()
        val store = MailboxStore(maxBoxes = 8, maxStrangerPackets = 300, isKnown = { it in ours })
        repeat(8) { assertTrue(store.put("%032x".format(it), "x")) }   // كل الأماكن لغرباء
        assertFalse(store.put("%032x".format(99), "x"))
        val next = "9".repeat(32)                                     // صندوق الفترة الجديدة لمحادثتنا
        ours += next
        assertTrue(store.put(next, "handshake"))
        assertEquals(emptyList(), store.take("%032x".format(0)))     // أُخرج أقدم صندوق غريب
        assertEquals(listOf("handshake"), store.take(next))
    }

    @Test fun `a stranger box becomes ours once the host learns the key`() {
        val known = mutableSetOf<String>()
        val store = MailboxStore(maxStrangerPackets = 2, isKnown = { it in known })
        val box = "3".repeat(32)
        assertTrue(store.put(box, "early1"))                          // وصل قبل مفتاح الفترة عند المضيف
        assertTrue(store.put(box, "early2"))
        assertFalse(store.put("4".repeat(32), "x"))
        known += box                                                  // وصل المفتاح
        assertTrue(store.put(box, "later"))
        assertTrue(store.put("4".repeat(32), "x"))                    // لم يعد يُحسب من الحصة الغريبة
        assertEquals(listOf("early1", "early2", "later"), store.take(box))
    }

    @Test fun `packets expire after the time limit`() {
        var clock = 0L
        val store = MailboxStore(ttl = Duration.ofHours(24), clock = { clock })
        store.put("5".repeat(32), "old")
        clock += Duration.ofHours(23).toNanos()
        store.put("5".repeat(32), "new")
        clock += Duration.ofHours(2).toNanos()
        assertEquals(listOf("new"), store.take("5".repeat(32)))
        assertEquals(0, store.count())
    }

    @Test fun `the http server accepts packets only and rejects everything else`() {
        val store = MailboxStore()
        val server = keep(RelayServer(store))
        val relay = HttpRelay("http://127.0.0.1:${server.port}")
        val box = "a".repeat(32)
        val p = packet()
        relay.put(box, p)
        assertEquals(listOf(p), relay.take(box))
        assertEquals(emptyList(), relay.take(box))                    // يُعطى مرة واحدة ثم يُحذف

        fun raw(request: String): String = Socket("127.0.0.1", server.port).use {
            it.soTimeout = 5000
            it.getOutputStream().write(request.toByteArray(Charsets.ISO_8859_1))
            it.getInputStream().readBytes().toString(Charsets.ISO_8859_1)
        }
        assertTrue(raw("GET /health HTTP/1.1\r\nHost: x\r\n\r\n").let { it.startsWith("HTTP/1.1 200") && it.endsWith("ok") })
        assertTrue(raw("GET /etc/passwd HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 404"))
        assertTrue(raw("GET /box/${"A".repeat(32)} HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 404"))
        assertTrue(raw("POST /box/$box HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello").startsWith("HTTP/1.1 400"))
        val bad = "!" + p.substring(1)
        assertTrue(raw("POST /box/$box HTTP/1.1\r\nContent-Length: ${bad.length}\r\n\r\n$bad").startsWith("HTTP/1.1 400"))
        assertTrue(raw("POST /box/$box HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").startsWith("HTTP/1.1 400"))
        assertTrue(raw("DELETE /box/$box HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 405"))
        assertTrue(raw("GET /health HTTP/1.1\r\n" + "X: y\r\n".repeat(100) + "\r\n").isEmpty())   // رؤوس كثيرة: يُغلق
        assertEquals(0, store.count())                                 // لم يدخل شيء من هذا
        // الخادم ما زال يعمل بعد كل هذا
        relay.put(box, p)
        assertEquals(1, store.count())
    }

    @Test fun `server listens on this device only`() {
        val server = keep(RelayServer(MailboxStore()))
        val outside = java.net.NetworkInterface.getNetworkInterfaces().toList()
            .flatMap { it.inetAddresses.toList() }.firstOrNull { !it.isLoopbackAddress && it is java.net.Inet4Address }
            ?: return
        assertFailsWith<IOException> { Socket().use { it.connect(InetSocketAddress(outside, server.port), 2000) } }
    }

    // ------------------------------------------------------------------ //
    // العنوان الذي يكتبه المستخدم
    // ------------------------------------------------------------------ //
    @Test fun `relay addresses are parsed forgivingly but strictly`() {
        assertEquals(RelayAddress.Onion(onion), RelayAddress.parse("  ${onion.uppercase()}  "))
        assertEquals(RelayAddress.Onion(onion), RelayAddress.parse("http://$onion/"))
        assertEquals(RelayAddress.Onion(onion), RelayAddress.parse("$onion:80"))
        assertEquals(RelayAddress.Web("http://192.168.1.15:8000"), RelayAddress.parse("http://192.168.1.15:8000/"))
        assertEquals(RelayAddress.Web("https://relay.example.org"), RelayAddress.parse("https://relay.example.org"))
        val shared = "عنوان صندوق البريد للمراسلة الآمنة (الصقه في الإعداد):\n$onion"      // رسالة زر «مشاركة»
        assertEquals(RelayAddress.Onion(onion), RelayAddress.parse(shared))
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse("abc.onion") }          // ناقص
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse(onion.drop(1)) }        // حرف ضاع عند النسخ
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse("x$onion") }            // حرف زائد
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse("$onion ${"b".repeat(56)}.onion") }  // عنوانان
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse(onion.replace('a', '1')) } // 1 ليس من base32
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse("192.168.1.15:8000") }
        assertFailsWith<IllegalArgumentException> { RelayAddress.parse("") }
    }

    // ------------------------------------------------------------------ //
    // هاتف يستضيف الصندوق، وهاتف بعيد يصل إليه عبر Tor
    // ------------------------------------------------------------------ //
    @Test fun `two phones talk through a mailbox hosted on one of them`() {
        val start = Instant.parse("2026-11-03T18:00:00Z").minusSeconds(3600)
        val seed = Vault.makeSeed()
        val vaultA = Vault.fromSeed(seed, "A", start, 7200, 36000)
        val vaultB = Vault.fromSeed(seed, "B", start, 7200, 36000)
        val change = vaultA.upcomingChanges(1)[0]

        // الهاتف المضيف (A): صناديقه في ذاكرته، وحصة صغيرة للغرباء
        lateinit var host: MessengerEngine
        val store = MailboxStore(maxPacketsPerBox = 1000, maxBoxes = 64, maxStrangerPackets = 300,
            isKnown = { it in host.knownMailboxes() })
        host = MessengerEngine(OnlineNode(), LocalRelay(store), "المضيف", Duration.ofSeconds(2),
            Duration.ofSeconds(6), Duration.ofSeconds(1), change)
        val server = keep(RelayServer(store))
        val tor = keep(FakeTor(onion, server.port))

        // الهاتف البعيد (B): لا يعرف إلا عنوان ‎.onion
        val address = RelayAddress.parse(onion) as RelayAddress.Onion
        val remote = MessengerEngine(OnlineNode(), SocksRelay(address.host, socksPort = { tor.port }), "البعيد",
            Duration.ofSeconds(2), Duration.ofSeconds(6), Duration.ofSeconds(1), change)

        host.deliverKey(vaultA.release(change), "system", change)
        remote.deliverKey(vaultB.release(change), "system", change)
        var now = change
        fun run(seconds: Int) = repeat(seconds) {
            now = now.plusSeconds(1)
            host.step(now)
            remote.step(now)
        }
        run(60)
        val a = host.snapshot(0, now)
        val b = remote.snapshot(0, now)
        assertTrue(a.getBoolean("ready") && a.getBoolean("confirmed"))
        assertTrue(b.getBoolean("ready") && b.getBoolean("confirmed"))
        assertEquals(a.getString("fingerprint"), b.getString("fingerprint"))
        assertTrue(remote.relayOk == true)

        host.enqueue("مرحبا من الهاتف المضيف")
        remote.enqueue("وصلت؟ أنا بعيد جدًا")
        run(30)
        assertEquals(listOf("مرحبا من الهاتف المضيف"), remote.log.filter { it.getString("who") == "peer" }.map { it.getString("text") })
        assertEquals(listOf("وصلت؟ أنا بعيد جدًا"), host.log.filter { it.getString("who") == "peer" }.map { it.getString("text") })
        assertTrue(remote.stats["dummies_in"]!! > 3 && host.stats["dummies_in"]!! > 3)

        // كل الطلبات وصلت إلى «Tor» بالاسم (النوع 3)، ولم يحاول الهاتف حلّ ‎.onion بنفسه
        assertTrue(tor.requested.isNotEmpty())
        assertTrue(tor.requested.all { it == 3 to "$onion:80" })
    }

    @Test fun `when the host phone is off the remote keeps its packets and retries`() {
        val start = Instant.parse("2026-11-03T18:00:00Z").minusSeconds(3600)
        val vaultB = Vault.fromSeed(Vault.makeSeed(), "B", start, 7200, 36000)
        val change = vaultB.upcomingChanges(1)[0]
        val tor = keep(FakeTor("b".repeat(56) + ".onion", 1))            // عنوان آخر: «الهاتف مطفأ»
        val remote = MessengerEngine(OnlineNode(), SocksRelay(onion, socksPort = { tor.port }), "",
            Duration.ofSeconds(2), Duration.ofSeconds(6), Duration.ofSeconds(1), change)
        remote.deliverKey(vaultB.release(change), "system", change)
        var now = change
        repeat(20) { now = now.plusSeconds(1); remote.step(now) }
        assertFalse(remote.relayOk!!)
        assertTrue(remote.outbox.isNotEmpty())                          // لم يضِع شيء، ينتظر عودة المضيف
        val error = assertFailsWith<IOException> { SocksRelay(onion, socksPort = { tor.port }).take("0".repeat(32)) }
        assertTrue(error.message!!.contains("غير متاح"))
        assertFailsWith<IOException> { SocksRelay(onion, socksPort = { -1 }).take("0".repeat(32)) }   // Tor لم يجهز
    }

    // ------------------------------------------------------------------ //
    // الحاسوب (بايثون) يتصل بصندوق بريد يستضيفه هاتف
    // ------------------------------------------------------------------ //
    @Test fun `python messenger uses a mailbox hosted by the kotlin app`() {
        PythonPeer().use { py ->
            val t0 = Instant.parse("2026-11-02T20:00:00Z")
            lateinit var host: MessengerEngine
            val store = MailboxStore(maxStrangerPackets = 300, isKnown = { it in host.knownMailboxes() })
            val server = keep(RelayServer(store))
            val created = py.call("create", "now" to t0.epochSecond, "min_hours" to 2, "max_hours" to 10)
            val pair = Vault.decodePairingCode(created.getString("code"))
            val vault = Vault.fromSeed(pair.seed, "B", pair.epochStart, pair.minSeconds, pair.maxSeconds)
            val change = vault.upcomingChanges(1)[0]
            py.call("messenger_start", "relay" to "http://127.0.0.1:${server.port}", "now" to change.epochSecond,
                "min_gap" to 2, "max_gap" to 6, "poll" to 1)
            host = MessengerEngine(OnlineNode(), LocalRelay(store), "android", Duration.ofSeconds(2),
                Duration.ofSeconds(6), Duration.ofSeconds(1), change)
            py.call("messenger_release", "now" to change.epochSecond)
            host.deliverKey(vault.release(change), "system", change)
            var now = change
            fun run(seconds: Int) = repeat(seconds) {
                now = now.plusSeconds(1)
                host.step(now)
                py.call("messenger_step", "now" to now.epochSecond)
            }
            run(60)
            host.enqueue("الصندوق في هاتفي")
            py.call("messenger_enqueue", "text" to "وصلت إليه من الحاسوب", "now" to now.epochSecond)
            run(30)
            assertEquals(listOf("الصندوق في هاتفي"),
                py.call("messenger_texts", "now" to now.epochSecond).getJSONArray("texts").let { a -> List(a.length()) { a.getString(it) } })
            assertEquals(listOf("وصلت إليه من الحاسوب"),
                host.log.filter { it.getString("who") == "peer" }.map { it.getString("text") })
        }
    }
}
