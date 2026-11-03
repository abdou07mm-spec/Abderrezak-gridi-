package org.syncedkeys.messenger

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import org.syncedkeys.core.HttpRelay
import org.syncedkeys.core.LocalRelay
import org.syncedkeys.core.OnlineNode
import org.syncedkeys.core.SocksRelay
import org.syncedkeys.core.Vault
import java.time.Instant
import java.time.temporal.ChronoUnit

/** الجهة الأونلاين داخل نظام أندرويد محاكى: استلام المفتاح من الخزنة، والإعداد. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class KeyReceiverTest {
    private val app get() = RuntimeEnvironment.getApplication() as MessengerApp

    private fun keyIntent(): Pair<Intent, Int> {
        val start = Instant.now().truncatedTo(ChronoUnit.MINUTES)
        val bundle = Vault.fromSeed(Vault.makeSeed(), "B", start, 7200, 36000).release(Instant.now())
        val intent = Intent("org.syncedkeys.action.VAULT_KEY")
            .putExtra("pair_id", bundle.pairId).putExtra("role", bundle.role).putExtra("epoch", bundle.epoch)
            .putExtra("valid_from", bundle.validFrom.epochSecond).putExtra("valid_until", bundle.validUntil.epochSecond)
            .putExtra("key", bundle.key).putExtra("isolation", "system")
        return intent to bundle.epoch
    }

    @Test fun `key from the offline side reaches the engine`() {
        val (intent, epoch) = keyIntent()
        KeyReceiver().onReceive(app, intent)
        assertTrue(app.engine.node.epochs.containsKey(epoch))
        val state = app.engine.snapshot(0)
        assertEquals("B", state.getString("role"))
        assertEquals("system", state.getJSONObject("offline").getString("isolation"))
        assertTrue(state.getJSONObject("offline").getBoolean("alive"))
        assertTrue(state.getJSONArray("messages").getJSONObject(0).getString("text").contains("وصل مفتاح الفترة"))
        // النبضة (المفتاح نفسه مرة أخرى) لا تكرر الإشعار
        KeyReceiver().onReceive(app, intent)
        assertEquals(1, app.engine.snapshot(0).getJSONArray("messages").length())
    }

    @Test fun `re-pairing in the vault is adopted instead of rejected`() {
        // ما حدث فعلًا على هاتف: اقتران أول، ثم اقتران جديد في الخزنة
        val (first, _) = keyIntent()
        KeyReceiver().onReceive(app, first)
        val oldPair = app.engine.node.pairId
        app.engine.enqueue("رسالة كُتبت قبل الاقتران الجديد")
        val (second, epoch) = keyIntent()
        KeyReceiver().onReceive(app, second)
        val newPair = second.getStringExtra("pair_id")
        assertTrue(oldPair != newPair)
        assertEquals(newPair, app.engine.node.pairId)
        assertEquals(setOf(epoch), app.engine.node.epochs.keys)
        val texts = (0 until app.engine.log.size).map { app.engine.log[it].getString("text") }
        assertTrue(texts.any { it.contains("اقتران جديد") })
        assertTrue(texts.none { it.contains("تعذّر") })                 // لا رسالة خطأ
        assertEquals(1, app.engine.bus.queue.size)                       // الرسالة المكتوبة لم تضِع
    }

    @Test fun `incomplete intents are ignored`() {
        KeyReceiver().onReceive(app, Intent("org.syncedkeys.action.VAULT_KEY").putExtra("epoch", 3))
        assertTrue(app.engine.node.epochs.isEmpty())
    }

    @Test fun `setup stores the relay and keeps the node`() {
        val (intent, epoch) = keyIntent()
        KeyReceiver().onReceive(app, intent)
        assertEquals(null, app.relayUrl)
        assertTrue(app.extraState().getBoolean("needs_setup"))
        app.configure("remote", "https://relay.example.org/", "سارة", fast = true)
        assertEquals("https://relay.example.org", app.relayUrl)
        assertTrue(app.fastMode)
        assertTrue(app.engine.node.epochs.containsKey(epoch))      // الإعداد لا يضيّع المفاتيح
        assertEquals("سارة", app.engine.snapshot(0).getString("name"))
        assertTrue(app.engine.relay is HttpRelay)
        assertEquals("off", app.extraState().getJSONObject("tor").getString("state"))   // لا Tor بلا حاجة
    }

    @Test fun `this phone can host the mailbox`() {
        val (intent, epoch) = keyIntent()
        KeyReceiver().onReceive(app, intent)
        app.configure("host", "", "المضيف", fast = false)
        val state = app.extraState()
        assertFalse(state.getBoolean("needs_setup"))
        assertEquals("host", state.getString("mode"))
        assertTrue(state.getJSONObject("tor").getBoolean("hosting"))
        assertTrue(app.engine.relay is LocalRelay)
        // صندوق البريد يعمل فعلًا، على هذا الجهاز فقط
        val server = app.server!!
        val local = HttpRelay("http://127.0.0.1:${server.port}")
        val box = OnlineNode.mailboxFor(app.engine.node.epochs[epoch]!!, "B")
        val packet = OnlineNode.randomFiller()
        local.put(box, packet)
        assertEquals(listOf(packet), app.engine.relay!!.take(box))      // المحرك يأخذ من الصناديق نفسها
        // الغرباء: حصة محدودة فقط، ولا تزاحم صناديق المحادثة
        var accepted = 0
        repeat(400) { i ->
            try { local.put("%032x".format(i % 4), packet); accepted++ } catch (e: Exception) { }
        }
        assertEquals(300, accepted)
        repeat(100) { i -> try { local.put("%032x".format(1000 + i), packet) } catch (e: Exception) { } }
        local.put(box, packet)                                          // صندوقنا ما زال يقبل
        // العودة إلى صندوق بعيد تُطفئ الصندوق المحلي
        app.configure("remote", "http://192.168.1.15:8000", "", fast = false)
        assertNull(app.server)
    }

    @Test fun `an onion address uses tor and bad addresses are refused`() {
        val onion = "a".repeat(52) + "bcd2.onion"
        app.configure("remote", "عنوان صندوق البريد:\nhttp://${onion.uppercase()}/", "", fast = false)
        assertEquals(onion, app.relayUrl)
        assertTrue(app.engine.relay is SocksRelay)
        val tor = app.extraState().getJSONObject("tor")
        assertTrue(tor.getString("state") != "off")
        assertFalse(tor.getBoolean("hosting"))
        assertThrows(IllegalArgumentException::class.java) { app.configure("remote", "abc.onion", "", false) }
        assertThrows(IllegalArgumentException::class.java) { app.configure("remote", "relay.example.org", "", false) }
        assertThrows(IllegalArgumentException::class.java) { app.configure("", "", "", false) }
        assertEquals(onion, app.relayUrl)                               // الإعداد الخاطئ لا يُحفظ
    }

    @Test fun `after a reboot the service comes back only when configured`() {
        val shadow = Shadows.shadowOf(app)
        StartupReceiver().onReceive(app, Intent(Intent.ACTION_BOOT_COMPLETED))
        assertNull(shadow.nextStartedService)                           // لم يُضبط بعد: لا شيء
        app.configure("host", "", "", fast = false)
        shadow.clearStartedServices()                                   // (تشغيل Tor نفسه)
        StartupReceiver().onReceive(app, Intent("android.intent.action.FAKE"))
        assertNull(shadow.nextStartedService)
        StartupReceiver().onReceive(app, Intent(Intent.ACTION_BOOT_COMPLETED))
        assertEquals(MessengerService::class.java.name, shadow.nextStartedService.component!!.className)
    }
}
