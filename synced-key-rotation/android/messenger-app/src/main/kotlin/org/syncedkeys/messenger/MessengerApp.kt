package org.syncedkeys.messenger

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import org.syncedkeys.core.Bus
import org.syncedkeys.core.HttpRelay
import org.syncedkeys.core.KeyBundle
import org.syncedkeys.core.LocalRelay
import org.syncedkeys.core.MailboxStore
import org.syncedkeys.core.MessengerEngine
import org.syncedkeys.core.OnlineNode
import org.syncedkeys.core.Relay
import org.syncedkeys.core.RelayAddress
import org.syncedkeys.core.RelayServer
import org.syncedkeys.core.SocksRelay
import java.io.File
import java.time.Duration
import java.time.Instant

/**
 * يحمل محرك المراسلة طوال حياة التطبيق.
 *
 * وضعان:
 *  - host: هذا الهاتف هو صندوق البريد (في ذاكرته)، منشور على Tor بعنوان ‎.onion.
 *  - remote: صندوق البريد عند الطرف الآخر (عنوان ‎.onion عبر Tor) أو على خادم (http/https).
 */
class MessengerApp : Application() {
    lateinit var engine: MessengerEngine
        private set
    lateinit var tor: TorController
        private set

    private val prefs by lazy { getSharedPreferences("settings", Context.MODE_PRIVATE) }
    val relayUrl: String? get() = prefs.getString("relay", null)
    val fastMode: Boolean get() = prefs.getBoolean("fast", false)
    val mode: String? get() = prefs.getString("mode", null) ?: relayUrl?.let { MODE_REMOTE }
    val configured: Boolean get() = mode == MODE_HOST || relayUrl != null

    /**
     * صناديق الهاتف المضيف. حدود تناسب ذاكرة هاتف: صناديق محادثتنا تُقبل دائمًا،
     * وما لا نعرفه (من يعرف العنوان دون المفاتيح) لا يتجاوز 300 حزمة (~2.5 ميغابايت).
     */
    val store = MailboxStore(maxPacketsPerBox = 1000, maxBoxes = 64, maxStrangerPackets = 300,
        isKnown = { box -> box in engine.knownMailboxes() })
    @Volatile var server: RelayServer? = null
        private set

    override fun onCreate() {
        super.onCreate()
        tor = TorController(this, File(noBackupFilesDir, "onion_key"), prefs)
        engine = buildEngine(loadNode())
        applyNetwork()
    }

    private fun nodeFile() = File(noBackupFilesDir, "node.json")

    private fun loadNode(): OnlineNode {
        val f = nodeFile()
        return if (f.exists()) OnlineNode.fromJson(JSONObject(f.readText())) else OnlineNode()
    }

    @Synchronized
    private fun saveNode(node: OnlineNode) {
        val f = nodeFile()
        val tmp = File(f.parentFile, "node.json.tmp")
        tmp.writeText(node.toJson().toString())
        tmp.renameTo(f)
    }

    private fun relay(): Relay? = when (mode) {
        MODE_HOST -> LocalRelay(store)
        else -> relayUrl?.let {
            when (val address = runCatching { RelayAddress.parse(it) }.getOrNull()) {
                is RelayAddress.Onion -> SocksRelay(address.host, socksPort = { tor.socksPort })
                is RelayAddress.Web -> HttpRelay(address.url)
                null -> null
            }
        }
    }

    private fun buildEngine(node: OnlineNode): MessengerEngine {
        val (min, max, poll) = if (fastMode) Triple(Duration.ofSeconds(3), Duration.ofSeconds(8), Duration.ofSeconds(2))
        else Triple(Bus.MIN_GAP, Bus.MAX_GAP, Duration.ofSeconds(20))
        return MessengerEngine(node, relay(), prefs.getString("name", "") ?: "",
            min, max, poll, Instant.now(), offlineStale = Duration.ofMinutes(45), persist = ::saveNode)
    }

    /** يشغّل ما يلزم فقط: صندوق البريد المحلي و/أو Tor. */
    @Synchronized
    private fun applyNetwork() {
        val onionRemote = mode == MODE_REMOTE &&
            relayUrl?.let { runCatching { RelayAddress.parse(it) }.getOrNull() } is RelayAddress.Onion
        when {
            mode == MODE_HOST -> {
                val local = server ?: RelayServer(store).also { server = it }      // على 127.0.0.1 فقط
                tor.start(hostPort = local.port)
            }
            onionRemote -> { closeServer(); tor.start(hostPort = null) }
            else -> { closeServer(); tor.stop() }
        }
    }

    private fun closeServer() {
        server?.close()
        server = null
    }

    /** يتحقق من الإعداد ويحفظه. يرمي IllegalArgumentException برسالة للمستخدم إن كان خاطئًا. */
    fun configure(mode: String, address: String, name: String, fast: Boolean) {
        val relay = when (mode) {
            MODE_HOST -> null
            MODE_REMOTE -> when (val parsed = RelayAddress.parse(address)) {
                is RelayAddress.Onion -> parsed.host
                is RelayAddress.Web -> parsed.url
            }
            else -> throw IllegalArgumentException("اختر أحد الخيارين")
        }
        prefs.edit().putString("mode", mode).putString("relay", relay)
            .putString("name", name.trim()).putBoolean("fast", fast).apply()
        engine = buildEngine(engine.node)
        applyNetwork()
    }

    /** ما يُضاف إلى حالة الواجهة في أندرويد. */
    fun extraState(): JSONObject = JSONObject()
        .put("needs_setup", !configured)
        .put("mode", mode ?: JSONObject.NULL)
        .put("address", relayUrl ?: JSONObject.NULL)
        .put("fast", fastMode)
        .put("tor", tor.state())

    companion object {
        const val MODE_HOST = "host"
        const val MODE_REMOTE = "remote"
    }
}

/** يستلم مفتاح كل فترة من الخزنة الأوفلاين (في اتجاه واحد). */
class KeyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val key = intent.getByteArrayExtra("key") ?: return
        val bundle = KeyBundle(
            intent.getStringExtra("pair_id") ?: return, intent.getStringExtra("role") ?: return,
            intent.getIntExtra("epoch", -1), Instant.ofEpochSecond(intent.getLongExtra("valid_from", 0)),
            Instant.ofEpochSecond(intent.getLongExtra("valid_until", 0)), key)
        val app = context.applicationContext as MessengerApp
        // المرسل موثوق: لا يصل إلى هنا إلا تطبيق يحمل الإذن الخاص (أي خزنتنا بالتوقيع نفسه)
        app.engine.deliverKey(bundle, intent.getStringExtra("isolation") ?: "software", Instant.now(),
            adoptNewPairing = true)
    }
}

/** بعد إعادة تشغيل الهاتف: يعود صندوق البريد والحافلة وحدهما (مهم للهاتف المضيف). */
class StartupReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val app = context.applicationContext as MessengerApp
        if (!app.configured) return
        try {
            context.startForegroundService(Intent(context, MessengerService::class.java))
        } catch (e: Exception) {
            // النظام منع التشغيل في الخلفية: سيعمل عند فتح التطبيق
        }
    }
}
