package org.syncedkeys.vault

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.syncedkeys.core.Vault
import org.syncedkeys.core.VaultError
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * شاشة الجهة الأوفلاين: الاقتران مرة واحدة، ثم صفحة حالة فقط.
 * بعد الاقتران تعمل الخزنة وحدها (منبّهات النظام)، حتى لو لم تُفتح هذه الشاشة أبدًا.
 */
class VaultActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var root: LinearLayout
    private val time = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // لا لقطات شاشة ولا معاينة في قائمة التطبيقات: رمز الاقتران سرّ كامل
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 48, 48, 48) }
        setContentView(ScrollView(this).apply { addView(root) })
        render()
    }

    override fun onResume() {
        super.onResume()
        handler.post(object : Runnable {
            override fun run() { if (VaultService.load(this@VaultActivity) != null) render(); handler.postDelayed(this, 5000) }
        })
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacksAndMessages(null)
    }

    private fun text(value: String, size: Float = 16f, bold: Boolean = false) = TextView(this).apply {
        text = value; textSize = size; setPadding(0, 12, 0, 12)
        textDirection = View.TEXT_DIRECTION_RTL; gravity = Gravity.START
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun render() {
        root.removeAllViews()
        val vault = VaultService.load(this)
        if (vault == null) renderPairing() else renderStatus(vault)
    }

    // ------------------------------------------------------------------ //
    private fun renderPairing() {
        root.addView(text("الخزنة الأوفلاين", 24f, true))
        root.addView(text("هذا التطبيق لا يملك إذن الإنترنت: نظام أندرويد نفسه يمنعه من الشبكة. " +
            "بعد الاقتران يغيّر المفاتيح وحده في مواعيد سرية، دون أن يسألك شيئًا."))
        root.addView(text("الاقتران مرة واحدة مع الطرف الآخر:", 18f, true))

        val fast = CheckBox(this).apply { text = "وضع التجربة السريع (تغيير كل 2 إلى 4 دقائق)" }
        val dice = EditText(this).apply { hint = "رميات نرد حقيقية (اختياري): 3 6 1 2 5 …"; inputType = InputType.TYPE_CLASS_PHONE }
        root.addView(dice)
        root.addView(fast)
        root.addView(Button(this).apply {
            text = "إنشاء اقتران جديد (أنت تعطي الرمز)"
            setOnClickListener { create(dice.text.toString(), fast.isChecked) }
        })
        val code = EditText(this).apply { hint = "رمز الاقتران من الطرف الآخر"; isSingleLine = false }
        root.addView(code)
        root.addView(Button(this).apply {
            text = "الانضمام بالرمز (أنت تكتب الرمز)"
            setOnClickListener { join(code.text.toString()) }
        })
    }

    private fun create(dice: String, fast: Boolean) {
        try {
            val (min, max) = if (fast) Vault.scheduleSeconds(2.0 / 60, 4.0 / 60) else Vault.scheduleSeconds(2.0, 10.0)
            val seed = Vault.makeSeed(dice = dice)
            val start = Instant.now().truncatedTo(ChronoUnit.MINUTES)
            val vault = Vault.fromSeed(seed, "A", start, min, max)
            val code = Vault.encodePairingCode(seed, start, min, max)
            VaultService.save(this, vault)
            VaultService.tick(this)                       // تبدأ العمل فورًا
            AlertDialog.Builder(this)
                .setTitle("رمز الاقتران")
                .setMessage("أعطِ هذا الرمز للطرف الآخر يدًا بيد أو بصوت منخفض، ولا ترسله عبر أي تطبيق: " +
                    "هذا الرمز هو السرّ كله، ولن يُعرض مرة أخرى.\n\n$code\n\nبصمة الزوج: ${vault.pairId}")
                .setPositiveButton("تم") { _, _ -> render() }
                .setCancelable(false)
                .show()
        } catch (e: VaultError) {
            error(e.message)
        }
    }

    private fun join(code: String) {
        try {
            val pairing = Vault.decodePairingCode(code)
            val vault = Vault.fromSeed(pairing.seed, "B", pairing.epochStart, pairing.minSeconds, pairing.maxSeconds)
            VaultService.save(this, vault)
            VaultService.tick(this)
            AlertDialog.Builder(this).setTitle("تم الانضمام")
                .setMessage("بصمة الزوج: ${vault.pairId}\nقارناها: يجب أن تتطابق عند الطرفين.")
                .setPositiveButton("تم") { _, _ -> render() }.show()
        } catch (e: VaultError) {
            error(e.message)
        }
    }

    private fun error(message: String?) {
        AlertDialog.Builder(this).setTitle("خطأ").setMessage(message).setPositiveButton("حسنًا", null).show()
    }

    // ------------------------------------------------------------------ //
    private fun renderStatus(vault: Vault) {
        root.addView(text("الخزنة الأوفلاين تعمل ✓", 22f, true))
        root.addView(text(if (VaultService.isolation(this) == "system")
            "معزولة عن الشبكة بفرض النظام ✓ (لا تملك إذن الإنترنت)" else "تحذير: العزل برمجي فقط"))
        root.addView(text("بصمة الزوج: ${vault.pairId}   الدور: ${vault.role}"))
        root.addView(text("الفترة الحالية: ${vault.epoch} (بدأت ${time.format(vault.epochStart)})"))
        root.addView(text("التغيير السري القادم: ${time.format(vault.nextChange())}"))
        root.addView(text("تدفع الخزنة مفتاح كل فترة إلى تطبيق المراسلة وحدها، في اتجاه واحد، " +
            "وتعيد دفعه كل 15 دقيقة احتياطًا. لا تحتاج إلى فتح هذه الشاشة بعد الآن."))
        root.addView(Button(this).apply {
            text = "دفع المفتاح الحالي الآن"
            setOnClickListener { VaultService.tick(this@VaultActivity); render() }
        })
    }
}
