package org.syncedkeys.messenger

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
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

    @Test fun `incomplete intents are ignored`() {
        KeyReceiver().onReceive(app, Intent("org.syncedkeys.action.VAULT_KEY").putExtra("epoch", 3))
        assertTrue(app.engine.node.epochs.isEmpty())
    }

    @Test fun `setup stores the relay and keeps the node`() {
        val (intent, epoch) = keyIntent()
        KeyReceiver().onReceive(app, intent)
        assertEquals(null, app.relayUrl)
        app.configure("https://relay.example.org", "سارة", fast = true)
        assertEquals("https://relay.example.org", app.relayUrl)
        assertTrue(app.fastMode)
        assertTrue(app.engine.node.epochs.containsKey(epoch))      // الإعداد لا يضيّع المفاتيح
        assertEquals("سارة", app.engine.snapshot(0).getString("name"))
    }
}
