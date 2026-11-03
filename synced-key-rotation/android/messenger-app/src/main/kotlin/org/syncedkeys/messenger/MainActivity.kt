package org.syncedkeys.messenger

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONObject
import org.syncedkeys.core.NodeError

/** واجهة المحادثة: نفس messenger_ui.html، تتحدث مع المحرك عبر جسر بدل الشبكة. */
class MainActivity : Activity() {
    private val app get() = application as MessengerApp

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startForegroundService(Intent(this, MessengerService::class.java))
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.webViewClient = object : WebViewClient() {
            // الصفحة المحلية فقط: لا تنقّل إلى أي موقع
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest) = true
        }
        web.addJavascriptInterface(Bridge(), "AndroidBridge")
        web.loadUrl("file:///android_asset/messenger_ui.html")
        setContentView(web)
    }

    inner class Bridge {
        @JavascriptInterface
        fun state(after: Int): String {
            val state = app.engine.snapshot(after)
            val extra = app.extraState()
            extra.keys().forEach { state.put(it, extra.get(it)) }
            return state.toString()
        }

        @JavascriptInterface
        fun send(text: String): String = try {
            if (text.isBlank()) throw NodeError("الرسالة فارغة")
            app.engine.enqueue(text)
            JSONObject().put("ok", true).toString()
        } catch (e: NodeError) {
            JSONObject().put("ok", false).put("error", e.message).toString()
        }

        @JavascriptInterface
        fun configure(mode: String, address: String, name: String, fast: Boolean): String = try {
            app.configure(mode, address, name, fast)
            JSONObject().put("ok", true).toString()
        } catch (e: IllegalArgumentException) {
            JSONObject().put("ok", false).put("error", e.message).toString()
        }

        /** نسخ عنوان صندوق البريد (للصقه في أي تطبيق مراسلة). */
        @JavascriptInterface
        fun copyAddress() {
            val address = app.tor.onion ?: return
            runOnUiThread {
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("عنوان صندوق البريد", address))
            }
        }

        @JavascriptInterface
        fun shareAddress() {
            val address = app.tor.onion ?: return
            val text = "عنوان صندوق البريد للمراسلة الآمنة (الصقه في الإعداد ← «صندوق البريد عند الطرف الآخر»):\n$address"
            runOnUiThread {
                startActivity(Intent.createChooser(
                    Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), "أرسل العنوان"))
            }
        }

        /** الهاتف المضيف يجب ألا يوقفه توفير البطارية. */
        @JavascriptInterface
        fun openBatterySettings() {
            runOnUiThread {
                try {
                    startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                } catch (e: Exception) {
                    startActivity(Intent(Settings.ACTION_SETTINGS))
                }
            }
        }
    }
}
