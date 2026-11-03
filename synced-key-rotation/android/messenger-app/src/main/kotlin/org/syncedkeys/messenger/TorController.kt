package org.syncedkeys.messenger

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.os.IBinder
import android.os.SystemClock
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import net.freehaven.tor.control.TorControlCommands
import net.freehaven.tor.control.TorControlConnection
import org.json.JSONObject
import org.syncedkeys.core.SocksRelay
import org.torproject.jni.TorService
import java.io.File

/**
 * Tor داخل التطبيق (مكتبة Tor الرسمية لأندرويد)، يعمل فقط عند الحاجة:
 *  - الهاتف المضيف: ينشر صندوق البريد كخدمة ‎.onion. لا يحتاج عنوان IP عامًا ولا فتح منافذ
 *    في الراوتر: الهاتف هو من يتصل بشبكة Tor، والطرف الآخر يصل إليه من خلالها من أي مكان.
 *    مفتاح العنوان يُحفظ في هذا الهاتف فقط، فيبقى العنوان نفسه بعد إعادة التشغيل.
 *  - الهاتف البعيد: يفتح منفذ SOCKS محليًا ليصل إلى عنوان ‎.onion.
 */
class TorController(private val context: Context, private val keyFile: File, private val prefs: SharedPreferences) {
    @Volatile var socksPort = -1
        private set
    @Volatile private var progress = 0
    @Volatile private var reachable: Boolean? = null
    @Volatile private var error: String? = null
    @Volatile private var status: String? = null
    @Volatile private var wanted = false
    @Volatile private var hostPort: Int? = null
    @Volatile private var service: TorService? = null
    private var bound = false
    private var worker: Thread? = null
    private var publishedPort: Int? = null
    private var serviceId: String? = null
    private var publishedAt = 0L
    private var lastCheck = 0L
    private var lastRestart = 0L

    /** العنوان (يُحفظ ليظهر فورًا في المرات التالية، قبل اكتمال اتصال Tor). */
    val onion: String? get() = prefs.getString(ADDRESS_PREF, null)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            service = (binder as? TorService.LocalBinder)?.service
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            when (intent.action) {
                TorService.ACTION_STATUS -> status = intent.getStringExtra(TorService.EXTRA_STATUS)
                TorService.ACTION_ERROR -> error = intent.getStringExtra(Intent.EXTRA_TEXT) ?: "خطأ في Tor"
            }
        }
    }

    /** hostPort: منفذ صندوق البريد المحلي إذا كان هذا الهاتف هو المضيف، وإلا null. */
    @Synchronized
    fun start(hostPort: Int?) {
        if (hostPort != this.hostPort) reachable = null
        this.hostPort = hostPort
        wanted = true
        bind()
        if (worker == null) {
            LocalBroadcastManager.getInstance(context).registerReceiver(statusReceiver,
                IntentFilter().apply { addAction(TorService.ACTION_STATUS); addAction(TorService.ACTION_ERROR) })
            worker = Thread(::watch, "tor-watch").apply { isDaemon = true; start() }
        }
    }

    @Synchronized
    fun stop() {
        wanted = false
        hostPort = null
        unbind()
        progress = 0
        reachable = null
        error = null
    }

    private fun bind() {
        if (bound) return
        bound = try {
            context.bindService(Intent(context, TorService::class.java), connection, Context.BIND_AUTO_CREATE)
        } catch (e: Throwable) {                   // مثلًا: مكتبة Tor غير متوفرة لمعالج هذا الهاتف
            error = "تعذّر تشغيل Tor: ${e.message}"
            false
        }
    }

    private fun unbind() {
        if (bound) {
            try { context.unbindService(connection) } catch (e: Exception) { /* انفصل أصلًا */ }
            bound = false
        }
        service = null
        socksPort = -1
        publishedPort = null
        serviceId = null
    }

    private fun watch() {
        while (true) {
            try {
                tick()
            } catch (e: Exception) {
                error = e.message ?: e.toString()
            }
            Thread.sleep(2000)
        }
    }

    private fun tick() {
        if (!wanted) return
        val now = SystemClock.elapsedRealtime()
        // توقف Tor (خطأ أو انقطاع)؟ نعيد تشغيله بهدوء
        if ((status == TorService.STATUS_OFF || status == TorService.STATUS_STOPPING) && now - lastRestart > 60_000) {
            synchronized(this) {
                lastRestart = now
                status = null
                unbind()
                bind()
            }
            return
        }
        val svc = service ?: return
        val control = svc.torControlConnection ?: return
        socksPort = svc.socksPort
        progress = parseProgress(control.getInfo("status/bootstrap-phase"))
        if (progress < 100) return                  // ننشر بعد اكتمال الاتصال بشبكة Tor
        error = null
        val port = hostPort ?: return
        synchronized(this) { if (port != publishedPort) publish(control, port, now) }
        selfCheck(now)
    }

    /** ننشر صندوق البريد: المنفذ 80 في عنوان ‎.onion ← صندوق البريد على 127.0.0.1 في هذا الهاتف. */
    private fun publish(control: TorControlConnection, port: Int, now: Long) {
        serviceId?.let { try { control.delOnion(it) } catch (e: Exception) { /* لم يعد موجودًا */ } }
        val savedKey = keyFile.takeIf { it.exists() }?.readText()?.trim()?.takeIf { it.isNotEmpty() }
        val result = control.addOnion(savedKey ?: "NEW:ED25519-V3", mapOf(80 to "127.0.0.1:$port"), null)
        result[TorControlCommands.HS_PRIVKEY]?.let { key ->
            val tmp = File(keyFile.parentFile, keyFile.name + ".tmp")
            tmp.writeText(key)
            tmp.renameTo(keyFile)
        }
        val id = result[TorControlCommands.HS_ADDRESS] ?: throw IllegalStateException("لم يُعطِ Tor عنوانًا")
        serviceId = id
        prefs.edit().putString(ADDRESS_PREF, "$id.onion").apply()
        publishedPort = port
        publishedAt = now
        lastCheck = 0
        reachable = null
    }

    /** نتأكد من الخارج: نصل إلى صندوقنا عبر Tor كما سيصل إليه الطرف الآخر. */
    private fun selfCheck(now: Long) {
        val address = onion ?: return
        val every = if (reachable == true) 10 * 60_000L else 30_000L
        if (now - lastCheck < every) return
        lastCheck = now
        val ok = SocksRelay(address, socksPort = { socksPort }).health()
        reachable = when {
            ok -> true
            now - publishedAt > 4 * 60_000L -> false       // النشر يأخذ عادة دقيقة إلى ثلاث
            else -> null
        }
    }

    fun state(): JSONObject = JSONObject()
        .put("state", when {
            !wanted -> "off"
            progress >= 100 -> "on"
            error != null -> "error"
            else -> "starting"
        })
        .put("progress", progress)
        .put("hosting", hostPort != null)
        .put("onion", if (hostPort != null) onion ?: JSONObject.NULL else JSONObject.NULL)
        .put("reachable", reachable ?: JSONObject.NULL)
        .put("error", error ?: JSONObject.NULL)

    companion object {
        private const val ADDRESS_PREF = "onion_address"
        private val PROGRESS = Regex("PROGRESS=(\\d+)")

        fun parseProgress(phase: String?): Int =
            phase?.let { PROGRESS.find(it)?.groupValues?.get(1)?.toIntOrNull() } ?: 0
    }
}
