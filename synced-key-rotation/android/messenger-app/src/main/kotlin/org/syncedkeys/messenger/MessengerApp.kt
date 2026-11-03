package org.syncedkeys.messenger

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import org.syncedkeys.core.Bus
import org.syncedkeys.core.HttpRelay
import org.syncedkeys.core.KeyBundle
import org.syncedkeys.core.MessengerEngine
import org.syncedkeys.core.OnlineNode
import java.io.File
import java.time.Duration
import java.time.Instant

/** يحمل محرك المراسلة طوال حياة التطبيق. */
class MessengerApp : Application() {
    lateinit var engine: MessengerEngine
        private set

    private val prefs by lazy { getSharedPreferences("settings", Context.MODE_PRIVATE) }
    val relayUrl: String? get() = prefs.getString("relay", null)
    val fastMode: Boolean get() = prefs.getBoolean("fast", false)

    override fun onCreate() {
        super.onCreate()
        engine = buildEngine(loadNode())
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

    private fun buildEngine(node: OnlineNode): MessengerEngine {
        val (min, max, poll) = if (fastMode) Triple(Duration.ofSeconds(3), Duration.ofSeconds(8), Duration.ofSeconds(2))
        else Triple(Bus.MIN_GAP, Bus.MAX_GAP, Duration.ofSeconds(20))
        return MessengerEngine(node, relayUrl?.let { HttpRelay(it) }, prefs.getString("name", "") ?: "",
            min, max, poll, Instant.now(), offlineStale = Duration.ofMinutes(45), persist = ::saveNode)
    }

    fun configure(relay: String, name: String, fast: Boolean) {
        prefs.edit().putString("relay", relay.trim()).putString("name", name.trim()).putBoolean("fast", fast).apply()
        engine = buildEngine(engine.node)
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
