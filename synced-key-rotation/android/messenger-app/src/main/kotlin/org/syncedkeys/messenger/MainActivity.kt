package org.syncedkeys.messenger

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.os.Bundle
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
        fun state(after: Int): String =
            app.engine.snapshot(after).put("needs_setup", app.relayUrl == null).toString()

        @JavascriptInterface
        fun send(text: String): String = try {
            if (text.isBlank()) throw NodeError("الرسالة فارغة")
            app.engine.enqueue(text)
            JSONObject().put("ok", true).toString()
        } catch (e: NodeError) {
            JSONObject().put("ok", false).put("error", e.message).toString()
        }

        @JavascriptInterface
        fun configure(relay: String, name: String, fast: Boolean): String {
            if (!relay.startsWith("http://") && !relay.startsWith("https://")) {
                return JSONObject().put("ok", false).put("error", "عنوان الخادم يجب أن يبدأ بـ https://").toString()
            }
            app.configure(relay, name, fast)
            return JSONObject().put("ok", true).toString()
        }
    }
}
