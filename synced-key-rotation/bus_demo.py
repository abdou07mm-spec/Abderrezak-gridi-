#!/usr/bin/env python3
"""
محاكاة الجزء الثاني: الحافلة والحزم الوهمية
============================================
6 ساعات محاكاة (الوقت محاكى، تنتهي في ثوانٍ):
  - عند كل طرف حافلة تنطلق في مواعيد عشوائية (حزمة كل 5 دقائق في المتوسط).
  - محادثتان حقيقيتان، وتغيير سري للمفاتيح على الأقل.
  - سرقة نسخة من هاتف سارة في وقت هادئ لا يكتب فيه أحد.

نعرض:
  1. ما يراه المراقب بدون حافلة ومعها.
  2. كم انتظرت الرسائل الحقيقية.
  3. متى فقد السارق القدرة على القراءة، رغم أن أحدًا لم يكتب شيئًا.

التشغيل:  python bus_demo.py
"""
from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bus import MAX_GAP, MIN_GAP, Bus
from common import use_utf8_console
from offline_vault import OfflineVault
from online_node import PACKET_BYTES, MessageRejected, OnlineNode

HOURS = 6
SLOT = timedelta(minutes=10)
STEP = timedelta(seconds=10)

DIALOGUE_1 = [
    ("A", "مرحبًا، هل أنتِ متاحة؟"), ("B", "نعم، تفضل"), ("A", "سأرسل لك العنوان"),
    ("A", "شارع النخيل، رقم 12"), ("B", "وصلني، شكرًا"), ("A", "إلى اللقاء"),
]
DIALOGUE_2 = [
    ("B", "هل تم كل شيء؟"), ("A", "نعم، كما اتفقنا"), ("B", "ممتاز"), ("B", "أراك غدًا"),
]


def hm(moment: datetime) -> str:
    return moment.strftime("%H:%M")


def minutes_ar(value: float) -> str:
    """عدد الدقائق بصيغة عربية سليمة."""
    count = round(value)
    if count < 1:
        return "أقل من دقيقة"
    if count == 1:
        return "دقيقة واحدة"
    if count == 2:
        return "دقيقتين"
    return f"{count} دقائق" if count <= 10 else f"{count} دقيقة"


@dataclass
class Dialogue:
    start: datetime
    lines: list[tuple[str, str]]
    index: int = 0
    next_time: datetime | None = None
    waiting_for: str | None = None   # النص الذي ننتظر وصوله قبل كتابة السطر التالي
    typed_times: list[datetime] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.next_time = self.start


def main() -> None:
    use_utf8_console()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        t0 = datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc)
        # لتسريع المحاكاة: الفترات هنا بين ساعتين و4 ساعات
        vault_a, vault_b = OfflineVault.create_pair(
            tmp / "a" / "vault.json", tmp / "b" / "vault.json", min_hours=2, max_hours=4, now=t0)
        changes = vault_a.upcoming_changes(6)
        start = changes[0]
        end = start + timedelta(hours=HOURS)
        nodes = {"A": OnlineNode.open(tmp / "a" / "node.json"),
                 "B": OnlineNode.open(tmp / "b" / "node.json")}
        vaults = {"A": vault_a, "B": vault_b}
        names = {"A": "أحمد", "B": "سارة"}

        # التغييرات السرية داخل النافذة: سارة تستورد مفتاحها بعد 40 ثانية من أحمد
        key_changes = [c for c in changes if start <= c < end]
        imports = sorted([(c, "A") for c in key_changes] +
                         [(c + timedelta(seconds=40), "B") for c in key_changes])
        buses = {who: Bus.start(nodes[who], start) for who in "AB"}
        dialogues = [Dialogue(start + timedelta(minutes=60), DIALOGUE_1),
                     Dialogue(start + timedelta(minutes=240), DIALOGUE_2)]
        # السرقة في وقت هادئ: بعيدًا عن المحادثات وعن أي تغيير سري، لكي نقيس
        # الشفاء بالحزم الوهمية وحدها (لا بتغيير الفترة)
        theft_time = next(
            (start + timedelta(minutes=m) for m in range(110, 221, 5)
             if not any(timedelta(minutes=-20) <= c - (start + timedelta(minutes=m))
                        <= timedelta(minutes=60) for c in key_changes)),
            start + timedelta(minutes=150))
        thief: OnlineNode | None = None
        thief_log: list[tuple[datetime, str]] = []

        observer: list[tuple[datetime, str]] = []
        kinds = {"message": 0, "dummy": 0, "handshake": 0, "noise": 0}
        delivered = {"A": [], "B": []}
        typed = {"A": [], "B": []}
        unopened = 0

        def flush(limit: datetime) -> None:
            """يُطلق كل الحافلات حتى اللحظة limit ويوصلها، بترتيبها الزمني الدقيق."""
            nonlocal thief, unopened
            batch = [(d, who) for who in "AB" for d in buses[who].departures_until(limit)]
            for departure, who in sorted(batch, key=lambda item: item[0].time):
                if thief is None and departure.time >= theft_time:
                    stolen = tmp / "thief.json"
                    shutil.copy(nodes["B"].path, stolen)
                    thief = OnlineNode.open(stolen)
                observer.append((departure.time, who))
                kinds[departure.kind] += 1
                other = "B" if who == "A" else "A"
                try:
                    result = nodes[other].receive(departure.packet, departure.time)
                except MessageRejected:
                    unopened += 1
                    continue
                delivered[other].extend(result.texts)
                for dialogue in dialogues:
                    if dialogue.waiting_for in result.texts:
                        dialogue.waiting_for = None
                        dialogue.index += 1
                        if dialogue.index < len(dialogue.lines):
                            dialogue.next_time = departure.time + timedelta(minutes=1)
                if thief is not None and who == "A":
                    try:
                        stolen_result = thief.receive(departure.packet, departure.time)
                        thief_log.append((departure.time, stolen_result.kind))
                    except MessageRejected:
                        thief_log.append((departure.time, "fail"))

        now = start
        while now < end:
            now += STEP
            while imports and imports[0][0] <= now:
                when, who = imports.pop(0)
                flush(when - timedelta(microseconds=1))
                nodes[who].import_bundle(vaults[who].release_key(when), when)
            for dialogue in dialogues:
                if dialogue.next_time is not None and dialogue.next_time <= now:
                    flush(dialogue.next_time - timedelta(microseconds=1))
                    who, text = dialogue.lines[dialogue.index]
                    buses[who].enqueue(text, dialogue.next_time)
                    typed[who].append(text)
                    dialogue.typed_times.append(dialogue.next_time)
                    dialogue.waiting_for, dialogue.next_time = text, None
            flush(now)

        # ------------------------------------------------------------------
        print("=" * 74)
        print(f"الحافلة: {HOURS} ساعات محاكاة، حزمة كل {MIN_GAP.total_seconds() / 60:g} إلى "
              f"{MAX_GAP.total_seconds() / 60:g} دقيقة (5 في المتوسط) من كل طرف")
        print("=" * 74)
        print(f"  من {hm(start)} إلى {hm(end)}، والتغييرات السرية للمفاتيح عند: "
              + "، ".join(hm(c) for c in key_changes[1:]) + " (التغيير الأول عند البداية)")
        total = len(observer)
        print(f"  انطلقت {total} حزمة: {kinds['message']} تحمل رسائل حقيقية، "
              f"{kinds['dummy']} وهمية، {kinds['handshake']} مصافحات، {kinds['noise']} ضجيج.")
        print("  المراقب لا يميّز بينها: كلها 1024 بايت ومشفّرة بالكامل.")

        # ما يراه المراقب ---------------------------------------------------
        slots = int(timedelta(hours=HOURS) / SLOT)

        def row(times: list[datetime]) -> str:
            counts = [0] * slots
            for moment in times:
                index = int((moment - start) / SLOT)
                if 0 <= index < slots:
                    counts[index] += 1
            return "".join("·" if c == 0 else str(min(c, 9)) for c in counts)

        typed_times = [t for d in dialogues for t in d.typed_times]
        handshake_times = [c for c, _ in sorted([(c, "A") for c in key_changes] +
                                                [(c + timedelta(seconds=40), "B") for c in key_changes])]
        without_bus = sorted(typed_times + handshake_times)
        marks = []
        for i in range(slots):
            low, high = start + i * SLOT, start + (i + 1) * SLOT
            if any(low <= c < high for c in key_changes):
                marks.append("K")
            elif low <= theft_time < high:
                marks.append("!")
            elif any(low <= t < high for t in typed_times):
                marks.append("C")
            else:
                marks.append("·")

        print()
        print("=" * 74)
        print("ما يراه المراقب: عدد الحزم في كل 10 دقائق (كل رمز = 10 دقائق)")
        print("=" * 74)
        print("  ما حدث فعلًا (C = محادثة، K = تغيير سري للمفاتيح، ! = سرقة الهاتف):")
        print("    " + "".join(marks))
        print("  بدون حافلة (كل رسالة تنطلق فورًا):")
        print("    " + row(without_bus))
        print("  مع الحافلة:")
        print("    " + row([t for t, _ in observer]))

        def averages(times: list[datetime]) -> tuple[float, float]:
            busy, quiet = [], []
            counts = [0] * slots
            for moment in times:
                index = int((moment - start) / SLOT)
                if 0 <= index < slots:
                    counts[index] += 1
            for i, count in enumerate(counts):
                (busy if marks[i] in "CK" else quiet).append(count)
            return sum(busy) / max(len(busy), 1), sum(quiet) / max(len(quiet), 1)

        nb_busy, nb_quiet = averages(without_bus)
        b_busy, b_quiet = averages([t for t, _ in observer])
        print(f"  بدون حافلة: {nb_busy:.1f} حزمة لكل 10 دقائق وقت النشاط، مقابل {nb_quiet:.1f} وقت الصمت"
              " ← المحادثات ولحظات التغيير مكشوفة.")
        print(f"  مع الحافلة: {b_busy:.1f} وقت النشاط، مقابل {b_quiet:.1f} وقت الصمت"
              " ← التدفق نفسه تقريبًا: لا شيء يُرى.")

        # الانتظار ----------------------------------------------------------
        waits = [w.total_seconds() / 60 for who in "AB" for w in buses[who].waits]
        print()
        print("=" * 74)
        print("ثمن الإخفاء: انتظار الرسائل الحقيقية للحافلة")
        print("=" * 74)
        print(f"  الرسائل الحقيقية: {len(waits)}؛ متوسط الانتظار {sum(waits) / len(waits):.1f} دقيقة، "
              f"وأطوله {max(waits):.1f} دقيقة.")
        print("  (بعد كل تغيير سري للمفاتيح قد يطول الانتظار قليلًا حتى تكتمل المصافحة.)")
        print(f"  كل الرسائل وصلت كاملة وبالترتيب: "
              f"{'نعم ✓' if delivered['B'] == typed['A'] and delivered['A'] == typed['B'] else 'لا ✗'}")
        per_day = PACKET_BYTES * 4 / 3 * (total / 2) * 24 / HOURS / 1e6
        print(f"  حجم البيانات: حوالي {per_day:.2f} ميغابايت في اليوم لكل اتجاه.")
        if unopened:
            print(f"  (حزم لم تُفتح عند وصولها: {unopened}. هي ضجيج، أو مصافحة وصلت قبل أن")
            print("   يستورد الطرف الآخر مفتاحه، فأُعيد إرسالها في الحافلة التالية.)")

        # الشفاء ------------------------------------------------------------
        print()
        print("=" * 74)
        print(f"سرقة هاتف سارة عند {hm(theft_time)}، في وقت لا يكتب فيه أحد")
        print("=" * 74)
        print("  السارق يحاول فتح كل حزمة يرسلها أحمد بعد السرقة:")
        print("    " + "  ".join(
            f"{hm(t)} {'✓' if k != 'fail' else '✗'}" for t, k in thief_log[:12]))
        successes = [t for t, k in thief_log if k != "fail"]
        real_read = sum(1 for _, k in thief_log if k == "message")
        if successes:
            last = max(successes)
            after = [k for t, k in thief_log if t > last]
            minutes_after = (last - theft_time).total_seconds() / 60
            print(f"  آخر حزمة استطاع فتحها كانت بعد {minutes_ar(minutes_after)} من السرقة، "
                  f"ثم فشل في كل ما بعدها (عدد الحزم: {len(after)}).")
            if any(theft_time < c <= last + timedelta(minutes=10) for c in key_changes):
                print("  (ساعد في ذلك أيضًا تغيير سري للمفاتيح وقع في تلك الدقائق.)")
        else:
            print("  لم يفتح أي حزمة.")
        print(f"  رسائل حقيقية قرأها: {real_read} (كل ما فتحه كان حزمًا وهمية)."
              if real_read == 0 else f"  رسائل حقيقية قرأها: {real_read}.")
        print("  ← الحزم الوهمية تحمل أنصافًا عشوائية جديدة، فتتجدد المفاتيح حتى في الصمت،")
        print("    ويفقد المسروق قيمته خلال دقائق بدل ساعات. (لو تكلمتما في تلك الدقائق")
        print("    لقرأ ما كُتب فيها فقط.)")
        print()


if __name__ == "__main__":
    main()
