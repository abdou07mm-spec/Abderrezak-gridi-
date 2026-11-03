package org.syncedkeys.core

import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.net.ServerSocket
import java.time.Duration
import java.time.Instant
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** نسخة بايثون تعمل كطرف آخر (android/interop/interop_peer.py). */
class PythonPeer : AutoCloseable {
    private val project = File(System.getProperty("python.project"))
    private val process = ProcessBuilder("python3", "android/interop/interop_peer.py")
        .directory(project).redirectError(ProcessBuilder.Redirect.INHERIT).start()
    private val reader: BufferedReader = process.inputStream.bufferedReader()

    fun call(cmd: String, vararg args: Pair<String, Any?>): JSONObject {
        val request = JSONObject().put("cmd", cmd)
        for ((k, v) in args) request.put(k, v)
        process.outputStream.write((request.toString() + "\n").toByteArray())
        process.outputStream.flush()
        val reply = JSONObject(reader.readLine())
        if (reply.has("fatal")) throw AssertionError("بايثون: ${reply.getString("fatal")}")
        return reply
    }

    override fun close() {
        process.outputStream.close()
        process.waitFor()
    }
}

class InteropTest {
    private lateinit var py: PythonPeer
    private val t0: Instant = Instant.parse("2026-11-02T20:00:00Z")

    @BeforeTest fun start() { py = PythonPeer() }
    @AfterTest fun stop() { py.close() }

    // ------------------------------------------------------------------ //
    // ثوابت متطابقة بايتًا ببايت
    // ------------------------------------------------------------------ //
    @Test fun `pairing code is identical in both directions`() {
        val seed = Crypto.secureRandom(32)
        val kotlinCode = Vault.encodePairingCode(seed, t0, 7200, 36000)
        val pythonCode = py.call("pairing_encode", "seed" to seed.toHex(), "start" to t0.epochSecond,
            "min" to 7200, "max" to 36000).getString("code")
        assertEquals(pythonCode, kotlinCode)
        val decoded = py.call("pairing_decode", "code" to kotlinCode.lowercase().replace("-", " "))
        assertEquals(seed.toHex(), decoded.getString("seed"))
        val back = Vault.decodePairingCode(pythonCode)
        assertEquals(t0, back.epochStart)
        assertFailsWith<VaultError> { Vault.decodePairingCode(pythonCode.dropLast(1) + "Q") }
    }

    @Test fun `secret schedule and vault keys match python`() {
        val seed = Crypto.secureRandom(32)
        val vault = Vault.fromSeed(seed, "A", t0, 7200, 36000)
        val changes = vault.upcomingChanges(6)
        val keys = changes.map { vault.release(it).key.toHex() }
        val reply = py.call("vault_keys", "seed" to seed.toHex(), "start" to t0.epochSecond,
            "min" to 7200, "max" to 36000, "count" to 6)
        assertEquals(changes.map { it.epochSecond }, List(6) { reply.getJSONArray("changes").getLong(it) })
        assertEquals(keys, List(6) { reply.getJSONArray("keys").getString(it) })
    }

    @Test fun `seed mixing and fingerprints match python`() {
        val device = Crypto.secureRandom(32)
        val dice = byteArrayOf(1, 6, 3, 4)
        val kotlinSeed = Vault.mixSeed(listOf("this-device" to device, "dice" to dice))
        val pythonSeed = py.call("mix_seed", "sources" to org.json.JSONArray(listOf(
            listOf("this-device", device.toHex()), listOf("dice", dice.toHex())))).getString("seed")
        assertEquals(pythonSeed, kotlinSeed.toHex())
        assertEquals(py.call("fingerprint", "secret" to device.toHex(), "purpose" to "pair").getString("fp"),
            Crypto.fingerprint(device, "pair"))
    }

    @Test fun `ml-kem interoperates in both directions`() {
        val (seed, public) = Crypto.mlkemKeyPair()
        assertEquals(py.call("mlkem_public", "seed" to seed.toHex()).getString("public"), public.toHex())
        val fromPython = py.call("mlkem_lock", "public" to public.toHex())
        assertEquals(fromPython.getString("secret"), Crypto.mlkemUnlock(seed, fromPython.getString("box").hexToBytes()).toHex())
        val (secret, box) = Crypto.mlkemLock(public)
        assertEquals(secret.toHex(), py.call("mlkem_unlock", "seed" to seed.toHex(), "box" to box.toHex()).getString("secret"))
    }

    @Test fun `epoch derivation and ratchet step match python`() {
        val r = { n: Int -> Crypto.secureRandom(n).toHex() }
        val args = arrayOf("vault_key" to r(32), "epoch" to 7, "dh" to r(32), "kem" to r(32), "pub_a" to r(32),
            "pub_b" to r(32), "kem_public_b" to r(1568), "kem_box" to r(1568))
        val m = args.toMap()
        val k = OnlineNode.deriveEpoch((m["vault_key"] as String).hexToBytes(), 7, (m["dh"] as String).hexToBytes(),
            (m["kem"] as String).hexToBytes(), (m["pub_a"] as String).hexToBytes(), (m["pub_b"] as String).hexToBytes(),
            (m["kem_public_b"] as String).hexToBytes(), (m["kem_box"] as String).hexToBytes())
        val p = py.call("derive_epoch", *args)
        assertEquals(p.getString("header_key"), k.headerKey.toHex())
        assertEquals(p.getString("root_key"), k.rootKey.toHex())
        assertEquals(p.getString("initial_chain_b"), k.initialChainB.toHex())
        assertEquals(p.getString("fingerprint"), k.fingerprint)
        val (rk, dh, kem) = Triple(r(32), r(32), r(32))
        val (krk, kck) = OnlineNode.kdfRoot(rk.hexToBytes(), dh.hexToBytes(), kem.hexToBytes())
        val pr = py.call("kdf_root", "rk" to rk, "dh" to dh, "kem" to kem)
        assertEquals(pr.getString("rk") + pr.getString("ck"), krk.toHex() + kck.toHex())
    }

    // ------------------------------------------------------------------ //
    // محادثة كاملة: بايثون (A) ↔ أندرويد (B)، بوقت محاكى
    // ------------------------------------------------------------------ //
    private fun pyRecv(packet: String, now: Instant) = py.call("receive", "packet" to packet, "now" to now.epochSecond)

    @Test fun `full conversation between python and kotlin across a secret change`() {
        val created = py.call("create", "now" to t0.epochSecond, "min_hours" to 2, "max_hours" to 10)
        val pair = Vault.decodePairingCode(created.getString("code"))
        val vault = Vault.fromSeed(pair.seed, "B", pair.epochStart, pair.minSeconds, pair.maxSeconds)
        assertEquals(created.getString("pair_id"), vault.pairId)
        val changes = vault.upcomingChanges(3)
        assertEquals(changes.map { it.epochSecond },
            py.call("changes", "count" to 3).getJSONArray("changes").let { a -> List(3) { a.getLong(it) } })

        val node = OnlineNode()
        fun handshakeAt(now: Instant) {
            py.call("release", "now" to now.epochSecond)
            node.importBundle(vault.release(now), now)
            // ثلاث خطوات: A بلا صندوق → B يرسل قفله → A يرسل الصندوق
            val first = node.receive(py.call("handshake", "now" to now.epochSecond).getString("packet"), now)
            assertTrue(first.waiting)
            pyRecv(node.myHandshake(now), now)
            node.receive(py.call("handshake", "now" to now.epochSecond).getString("packet"), now)
            assertEquals(py.call("fp", "now" to now.epochSecond).getString("fp"), node.keyFingerprint(now))
        }

        var now = changes[0]
        handshakeAt(now)
        now = now.plusSeconds(60)
        // B يبدأ الكلام (سلسلته الأولى)، ثم A، ثم عدة تبادلات (سقّاطة هجينة)
        assertEquals(listOf("مرحبًا من أندرويد"), pyRecv(node.send("مرحبًا من أندرويد", now), now).toTexts())
        val fromPy = py.call("send", "text" to "أهلًا من بايثون", "now" to now.epochSecond).getString("packet")
        assertEquals(listOf("أهلًا من بايثون"), node.receive(fromPy, now).texts)
        val halves = mutableSetOf<String>()
        repeat(4) { i ->
            assertEquals(listOf("K$i"), pyRecv(node.send("K$i", now), now).toTexts())
            assertEquals(listOf("P$i"), node.receive(py.call("send", "text" to "P$i", "now" to now.epochSecond)
                .getString("packet"), now).texts)
            halves += node.epochs[1]!!.dhsPublic!!.toHex()
        }
        assertEquals(4, halves.size)                         // نصف جديد مع كل تبادل

        // ترتيب مختلف، ووهمية، وإعادة إرسال
        val late = py.call("send", "text" to "متأخرة", "now" to now.epochSecond).getString("packet")
        val early = py.call("send", "text" to "سابقة", "now" to now.epochSecond).getString("packet")
        assertEquals(listOf("سابقة"), node.receive(early, now).texts)
        assertEquals(listOf("متأخرة"), node.receive(late, now).texts)
        assertFailsWith<ReplayRejected> { node.receive(late, now) }
        assertEquals("dummy", node.receive(py.call("dummy", "now" to now.epochSecond).getString("packet"), now).kind)
        assertEquals("dummy", pyRecv(node.sendDummy(now), now).getString("kind"))
        assertFailsWith<ReplayRejected> { node.receive(fromPy, now) }               // إعادة إرسال رسالة مقروءة
        assertEquals("MessageRejected", pyRecv(fromPy, now).getString("error"))  // حزمة بايثون أُعيدت إليها

        // تغيير سري: مفتاح جديد عند الطرفين دون تواصل، ومصافحة جديدة
        now = changes[1]
        val oldFp = node.keyFingerprint(now.minusSeconds(1))
        handshakeAt(now)
        assertNotEquals(oldFp, node.keyFingerprint(now))
        now = now.plusSeconds(30)
        assertEquals(listOf("بعد التغيير"), pyRecv(node.send("بعد التغيير", now), now).toTexts())

        // تعديل حرف واحد يُرفض
        val packet = node.send("سليمة", now).toCharArray()
        packet[4000] = if (packet[4000] == 'A') 'B' else 'A'
        assertEquals("MessageRejected", pyRecv(String(packet), now).getString("error"))
    }

    private fun JSONObject.toTexts(): List<String> {
        if (has("error")) throw AssertionError("بايثون رفضت: ${getString("error")}")
        val array = getJSONArray("texts")
        return List(array.length()) { array.getString(it) }
    }

    // ------------------------------------------------------------------ //
    // تطبيقان كاملان (حافلة + خادم ترحيل حقيقي): بايثون ↔ أندرويد
    // ------------------------------------------------------------------ //
    @Test fun `kotlin engine and python messenger talk through the python relay server`() {
        val port = ServerSocket(0).use { it.localPort }
        val project = File(System.getProperty("python.project"))
        val relayProcess = ProcessBuilder("python3", "relay_server.py", "--port", port.toString())
            .directory(project).redirectErrorStream(true).start()
        try {
            val relayUrl = "http://127.0.0.1:$port"
            repeat(50) {
                try { HttpRelay(relayUrl).take("0".repeat(32)); return@repeat } catch (e: Exception) { Thread.sleep(100) }
            }
            val created = py.call("create", "now" to t0.epochSecond, "min_hours" to 2, "max_hours" to 10)
            val pair = Vault.decodePairingCode(created.getString("code"))
            val vault = Vault.fromSeed(pair.seed, "B", pair.epochStart, pair.minSeconds, pair.maxSeconds)
            val change = vault.upcomingChanges(1)[0]
            py.call("messenger_start", "relay" to relayUrl, "now" to change.epochSecond, "min_gap" to 2,
                "max_gap" to 6, "poll" to 1)
            val engine = MessengerEngine(OnlineNode(), HttpRelay(relayUrl), "android", Duration.ofSeconds(2),
                Duration.ofSeconds(6), Duration.ofSeconds(1), change)
            py.call("messenger_release", "now" to change.epochSecond)
            engine.deliverKey(vault.release(change), "system", change)

            var now = change
            fun run(seconds: Int) = repeat(seconds) {
                now = now.plusSeconds(1)
                engine.step(now)
                py.call("messenger_step", "now" to now.epochSecond)
            }
            run(60)
            val snap = engine.snapshot(0, now)
            assertTrue(snap.getBoolean("ready") && snap.getBoolean("confirmed"))
            assertEquals(py.call("messenger_texts", "now" to now.epochSecond).getString("fingerprint"),
                snap.getString("fingerprint"))

            engine.enqueue("من هاتف أندرويد")
            py.call("messenger_enqueue", "text" to "من حاسوب بايثون", "now" to now.epochSecond)
            run(30)
            assertEquals(listOf("من هاتف أندرويد"),
                py.call("messenger_texts", "now" to now.epochSecond).getJSONArray("texts").let { a -> List(a.length()) { a.getString(it) } })
            assertEquals(listOf("من حاسوب بايثون"),
                engine.log.filter { it.getString("who") == "peer" }.map { it.getString("text") })
            assertTrue(engine.stats["dummies_in"]!! > 3)         // الحافلة تعمل حتى في الصمت
        } finally {
            relayProcess.destroy()
        }
    }
}
