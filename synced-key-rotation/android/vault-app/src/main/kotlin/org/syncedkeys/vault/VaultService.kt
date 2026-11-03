package org.syncedkeys.vault

import android.Manifest
import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import org.json.JSONObject
import org.syncedkeys.core.Vault
import java.io.File
import java.time.Duration
import java.time.Instant

/**
 * قلب الجهة الأوفلاين على أندرويد:
 *  - تحفظ الخزنة في ملف خاص لا يُنسخ احتياطيًا ولا تقرؤه التطبيقات الأخرى.
 *  - عند كل موعد سري: تتقدّم، وتُتلف القديم، وتدفع مفتاح الفترة إلى تطبيق المراسلة
 *    في اتجاه واحد (بثّ موجّه، لا يستقبله إلا تطبيق بنفس التوقيع).
 *  - منبّه بلا أي إذن (setAndAllowWhileIdle): قد يتأخر دقائق قليلة حين ينام الهاتف،
 *    والنظام كله يتحمّل ذلك (الرسائل تنتظر الحافلة التالية).
 *  - كل 15 دقيقة تعيد دفع المفتاح الحالي (نبضة)، فلا يضيع مفتاح إن فات تطبيقَ المراسلة.
 */
object VaultService {
    const val ACTION_KEY = "org.syncedkeys.action.VAULT_KEY"
    const val PERMISSION = "org.syncedkeys.permission.KEYS"
    const val MESSENGER_PACKAGE = "org.syncedkeys.messenger"
    private val HEARTBEAT: Duration = Duration.ofMinutes(15)

    private fun file(context: Context) = File(context.noBackupFilesDir, "vault.json")

    @Synchronized
    fun load(context: Context): Vault? {
        val f = file(context)
        return if (f.exists()) Vault.fromJson(JSONObject(f.readText())) else null
    }

    @Synchronized
    fun save(context: Context, vault: Vault) {
        val f = file(context)
        val tmp = File(f.parentFile, "vault.json.tmp")
        tmp.writeText(vault.toJson().toString())
        if (!tmp.renameTo(f)) throw IllegalStateException("تعذّر حفظ الخزنة")
    }

    /** هل يمنع النظام هذا التطبيق من الشبكة؟ (نعم ما دام لا يملك إذن الإنترنت) */
    fun isolation(context: Context): String =
        if (context.checkSelfPermission(Manifest.permission.INTERNET) == PackageManager.PERMISSION_GRANTED) "software"
        else "system"

    /** دورة واحدة: المفتاح الحالي إلى تطبيق المراسلة، ثم جدولة الموعد التالي. */
    @Synchronized
    fun tick(context: Context): Vault? {
        val vault = load(context) ?: return null
        val now = Instant.now()
        val bundle = vault.release(now)
        save(context, vault)                                    // الحالة القديمة أُتلفت
        val intent = Intent(ACTION_KEY).setPackage(MESSENGER_PACKAGE)
            .putExtra("pair_id", bundle.pairId).putExtra("role", bundle.role)
            .putExtra("epoch", bundle.epoch)
            .putExtra("valid_from", bundle.validFrom.epochSecond)
            .putExtra("valid_until", bundle.validUntil.epochSecond)
            .putExtra("key", bundle.key)
            .putExtra("isolation", isolation(context))
        context.sendBroadcast(intent, PERMISSION)
        schedule(context, vault, now)
        return vault
    }

    private fun schedule(context: Context, vault: Vault, now: Instant) {
        val next = minOf(vault.nextChange(), now.plus(HEARTBEAT))
        val pending = PendingIntent.getBroadcast(context, 1, Intent(context, AlarmReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val alarms = context.getSystemService(AlarmManager::class.java)
        alarms.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, next.toEpochMilli(), pending)
    }
}

class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        VaultService.tick(context)
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // نقبل فقط رسائل النظام (إعادة التشغيل أو تحديث التطبيق)، لا أي تطبيق آخر
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            VaultService.tick(context)
        }
    }
}
