package org.syncedkeys.messenger

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager

/**
 * خدمة في المقدمة تُبقي الحافلة تعمل حين يكون التطبيق في الخلفية:
 * حزمة في مواعيد عشوائية، وتفقّد الصندوق، تكلمتَ أو صمتّ.
 * تُبقي المعالج مستيقظًا (والشاشة مطفأة): بدونه تتوقف الحافلة حين ينام الهاتف، ويختفي
 * صندوق البريد عن الطرف الآخر إذا كان هذا الهاتف هو المضيف.
 */
class MessengerService : Service() {
    @Volatile private var running = false
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val channel = NotificationChannel("bus", "الحافلة", NotificationManager.IMPORTANCE_MIN)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        val notification = Notification.Builder(this, "bus")
            .setContentTitle("المراسلة الآمنة تعمل")
            .setContentText("الحافلة تنطلق في مواعيد عشوائية")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
        if (!running) {
            running = true
            val lock = getSystemService(PowerManager::class.java)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "syncedkeys:bus")
                .apply { setReferenceCounted(false) }
            wakeLock = lock
            Thread {
                val app = application as MessengerApp
                var renewed = 0L
                while (running) {
                    val now = System.currentTimeMillis()
                    if (now - renewed > 60_000) { lock.acquire(WAKE_MS); renewed = now }   // يُجدَّد كل دقيقة
                    try { app.engine.step() } catch (e: Exception) { /* المحرك يسجّل أخطاءه بنفسه */ }
                    Thread.sleep(500)
                }
            }.apply { isDaemon = true; name = "bus" }.start()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        wakeLock?.let { if (it.isHeld) it.release() }
        super.onDestroy()
    }

    companion object {
        private const val WAKE_MS = 10 * 60_000L
    }
}
