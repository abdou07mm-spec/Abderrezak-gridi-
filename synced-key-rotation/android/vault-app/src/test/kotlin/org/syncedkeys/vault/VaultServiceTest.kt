package org.syncedkeys.vault

import android.app.AlarmManager
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.syncedkeys.core.Vault
import java.time.Instant
import java.time.temporal.ChronoUnit

/** الجهة الأوفلاين داخل نظام أندرويد محاكى. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultServiceTest {
    private val context get() = RuntimeEnvironment.getApplication()

    private fun keyBroadcasts() = shadowOf(context).broadcastIntents.filter { it.action == VaultService.ACTION_KEY }

    private fun pairFast(minutesAgo: Long): Vault {
        val (min, max) = Vault.scheduleSeconds(2.0 / 60, 4.0 / 60)
        val start = Instant.now().truncatedTo(ChronoUnit.MINUTES).minus(minutesAgo, ChronoUnit.MINUTES)
        return Vault.fromSeed(Vault.makeSeed(), "A", start, min, max).also { VaultService.save(context, it) }
    }

    @Test fun `offline side is isolated by the system`() {
        assertEquals("system", VaultService.isolation(context))         // لا إذن إنترنت
    }

    @Test fun `tick pushes the current key one way and schedules the next secret change`() {
        pairFast(minutesAgo = 20)                                        // تأخرت: يجب أن تلحق وحدها
        val vault = VaultService.tick(context)!!
        assertTrue("تقدّمت عدة فترات وأتلفت ما قبلها", vault.epoch >= 4)
        val intent = keyBroadcasts().single()
        assertEquals(VaultService.MESSENGER_PACKAGE, intent.`package`)
        assertEquals(vault.epoch, intent.getIntExtra("epoch", -1))
        assertEquals(32, intent.getByteArrayExtra("key")!!.size)
        assertEquals("system", intent.getStringExtra("isolation"))
        val alarm = shadowOf(context.getSystemService(AlarmManager::class.java)).nextScheduledAlarm
        assertNotNull("المنبّه التالي مجدول", alarm)
        assertTrue(alarm!!.triggerAtTime <= vault.nextChange().toEpochMilli())
        assertTrue(alarm.triggerAtTime > System.currentTimeMillis() - 1000)
        // الحالة القديمة أُتلفت فعلًا على القرص
        assertEquals(vault.epoch, VaultService.load(context)!!.epoch)
    }

    @Test fun `boot receiver reacts only to the system`() {
        pairFast(minutesAgo = 0)
        BootReceiver().onReceive(context, Intent("org.evil.action"))
        assertTrue(keyBroadcasts().isEmpty())
        BootReceiver().onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
        assertEquals(1, keyBroadcasts().size)
    }

    @Test fun `nothing happens before pairing`() {
        assertNull(VaultService.tick(context))
        assertTrue(keyBroadcasts().isEmpty())
    }
}
