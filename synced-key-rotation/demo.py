#!/usr/bin/env python3
"""
محاكاة كاملة للفكرة على مدى 6 أيام:
  - أحمد (المرسل) وسارة (المستقبل)، لكل منهما نظام 1 (أوفلاين) ونظام 2 (أونلاين).
  - "المخترق" يسجّل كل ما يمر عبر الإنترنت، ثم يخترق الأجهزة لاحقًا.
  - الوقت محاكى (لا داعي للانتظار حتى الساعة 8 صباحًا).

التشغيل:  python demo.py
"""
from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from common import stamp, use_utf8_console
from offline_vault import OfflineVault, VaultError, export_bundle, key_fingerprint
from online_node import NodeError, OnlineNode, message_epoch


def at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)


def title(text: str) -> None:
    print()
    print("=" * 70)
    print(text)
    print("=" * 70)


def short(token: str) -> str:
    return token if len(token) <= 48 else token[:48] + "..."


class Person:
    def __init__(self, name: str, vault: OfflineVault, home: Path):
        self.name = name
        self.vault = vault
        self.node = OnlineNode.open(home / "online_node.json")
        self.usb = home / "usb_transfer"   # منطقة النقل في اتجاه واحد

    def rotate(self, now: datetime) -> str:
        """موعد التغيير: الخزنة تتصل لحظة، تُخرج مفتاح اليوم، ثم تنفصل."""
        bundle = self.vault.release_key(now)
        export_bundle(bundle, self.usb)
        self.node.import_from_folder(self.usb, now)
        fp = key_fingerprint(bytes.fromhex(bundle["key"]))
        print(f"  [{stamp(now)}] {self.name}: الخزنة أخرجت مفتاح الحقبة "
              f"{bundle['epoch']} ثم انفصلت. بصمته: {fp}")
        return fp


def main() -> None:
    use_utf8_console()
    internet: list[tuple[str, str]] = []   # كل ما يمر عبر الشبكة (المخترق يراه كله)

    def send(sender: Person, text: str, now: datetime) -> str:
        token = sender.node.encrypt(text, now)
        internet.append((stamp(now), token))
        print(f"  [{stamp(now)}] {sender.name} يرسل: «{text}»")
        print(f"      ما يمر عبر الإنترنت (الحقبة {message_epoch(token)}): {short(token)}")
        return token

    def receive(receiver: Person, token: str, now: datetime) -> None:
        try:
            text = receiver.node.decrypt(token, now)
            print(f"  [{stamp(now)}] {receiver.name} تستلم وتفك التشفير: «{text}»  ✓")
        except NodeError as error:
            print(f"  [{stamp(now)}] {receiver.name}: ✗ {error}")

    def attack(node: OnlineNode, token: str, label: str, now: datetime) -> None:
        try:
            text = node.decrypt(token, now)
            print(f"      المخترق يقرأ {label}: «{text}»  ← نجح")
        except NodeError:
            print(f"      المخترق يحاول قراءة {label}: فشل ✗")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        # ------------------------------------------------------------------
        title("المرحلة 0 — اللقاء الأول (مرة واحدة فقط)")
        now = at(2, 20)
        vault_a, vault_s = OfflineVault.create_pair(
            tmp / "ahmed" / "offline_vault.json",
            tmp / "sara" / "offline_vault.json",
            rotation_hour_utc=8, now=now,
        )
        print(f"  [{stamp(now)}] أحمد وسارة التقيا شخصيًا وأنشآ بذرة سرية عشوائية (256 بت).")
        print(f"      بصمة الزوج عند أحمد: {vault_a.pair_id}")
        print(f"      بصمة الزوج عند سارة: {vault_s.pair_id}")
        print("      البذرة لن تمر عبر الإنترنت أبدًا، ولن تخرج من الجهازين الأوفلاين.")
        ahmed = Person("أحمد", vault_a, tmp / "ahmed")
        sara = Person("سارة", vault_s, tmp / "sara")

        # ------------------------------------------------------------------
        title("اليوم 1 — الساعة 08:00: أول تغيير آلي (كل طرف وحده، بلا أي تواصل)")
        fp_a = ahmed.rotate(at(3, 8))
        fp_s = sara.rotate(at(3, 8))
        print(f"  المفتاحان متطابقان؟ {'نعم ✓' if fp_a == fp_s else 'لا ✗'}"
              " — رغم أن أحدًا منهما لم يرسل مفتاحًا للآخر.")
        m1 = send(ahmed, "الاجتماع غدًا في المكان المعتاد", at(3, 9, 30))
        receive(sara, m1, at(3, 9, 31))

        # ------------------------------------------------------------------
        title("اليوم 2 — رسالة أُرسلت قبل التغيير بدقيقة ووصلت بعده")
        late = send(ahmed, "تأكيد: الساعة الثالثة", at(4, 7, 59))
        fp_a2 = ahmed.rotate(at(4, 8))
        sara.rotate(at(4, 8))
        print(f"  مفتاح اليوم مختلف كليًا عن الأمس؟ {'نعم ✓' if fp_a2 != fp_a else 'لا ✗'}")
        receive(sara, late, at(4, 8, 1))
        print("      (نُبقي مفتاح الأمس فقط كفترة سماح حتى لا تضيع رسائل الطريق)")
        m2 = send(ahmed, "أحضر الوثائق معك", at(4, 10))
        receive(sara, m2, at(4, 10, 5))

        # ------------------------------------------------------------------
        title("اليوم 3 — المخترق يخترق جهاز أحمد المتصل (النظام 2) ويسرق كل ما فيه")
        ahmed.rotate(at(5, 8))
        sara.rotate(at(5, 8))
        m3 = send(ahmed, "تم تغيير الخطة", at(5, 11))
        receive(sara, m3, at(5, 11, 2))

        stolen_node = tmp / "attacker" / "stolen_online_node.json"
        stolen_node.parent.mkdir()
        shutil.copy(ahmed.node.path, stolen_node)
        eve = OnlineNode.open(stolen_node)
        print(f"  [{stamp(at(5, 15))}] المخترق سرق ملف النظام المتصل. يحتوي مفاتيح الحقب: "
              f"{sorted(eve.keys)} فقط")
        print(f"      ومعه تسجيل لكل الرسائل ({len(internet)}) التي مرت عبر الإنترنت:")
        attack(eve, m1, "رسالة اليوم 1", at(5, 15))
        attack(eve, m2, "رسالة اليوم 2", at(5, 15))
        attack(eve, m3, "رسالة اليوم 3", at(5, 15))
        print("      ← الضرر محصور في نافذة صغيرة: الماضي الأبعد محمي.")

        # ------------------------------------------------------------------
        title("اليوم 4 — بعد التغيير التالي، ما سرقه المخترق أصبح بلا قيمة")
        ahmed.rotate(at(6, 8))
        sara.rotate(at(6, 8))
        m4 = send(ahmed, "الموعد الجديد يوم الجمعة", at(6, 9))
        receive(sara, m4, at(6, 9, 3))
        attack(eve, m4, "رسالة اليوم 4 بالمفاتيح المسروقة", at(6, 9, 3))

        print("  المخترق يعدّل حرفًا واحدًا في الرسالة ويمررها لسارة:")
        raw = bytearray(m4.encode())
        raw[-5] = ord("A") if raw[-5] != ord("A") else ord("B")
        receive(sara, raw.decode(), at(6, 9, 4))

        # ------------------------------------------------------------------
        title("اليوم 5 — أحمد نسي استيراد مفتاح اليوم")
        sara.rotate(at(7, 8))
        try:
            ahmed.node.encrypt("رسالة بمفتاح قديم؟", at(7, 9))
        except NodeError as error:
            print(f"  [{stamp(at(7, 9))}] أحمد يحاول الإرسال: ✗ {error}")
        ahmed.rotate(at(7, 9, 1))
        m5 = send(ahmed, "آسف على التأخير", at(7, 9, 2))
        receive(sara, m5, at(7, 9, 3))

        # ------------------------------------------------------------------
        title("اليوم 5 — أسوأ حالة: المخترق سرق الخزنة الأوفلاين نفسها (النظام 1)")
        stolen_vault = tmp / "attacker" / "stolen_offline_vault.json"
        shutil.copy(ahmed.vault.path, stolen_vault)
        thief = OfflineVault.load(stolen_vault)
        print(f"  الخزنة المسروقة حالتها عند الحقبة {thief.epoch}.")
        try:
            thief.release_key(at(3, 9, 30))
        except VaultError as error:
            print(f"  المخترق يطلب مفتاح اليوم 1: ✗ {error}")
        print("  ← رسائل الماضي تبقى محمية لأن السلسلة لا ترجع إلى الخلف.")
        print("  ⚠ لكنه يستطيع حساب مفاتيح المستقبل: لذلك يجب حماية الخزنة ماديًا،")
        print("    وعند سرقتها يلتقي الطرفان لإنشاء بذرة جديدة (أو نضيف تبادل")
        print("    Diffie-Hellman — انظر «الخطوات التالية» في README).")

        # ------------------------------------------------------------------
        title("الخلاصة")
        print("  ✓ المفتاح يتغير آليًا عند الموعد، عند الطرفين، دون أي تواصل بينهما.")
        print("  ✓ المفاتيح تبدو عشوائية تمامًا لمن لا يملك البذرة.")
        print("  ✓ تسجيل الرسائل وحده لا يفيد المخترق بشيء.")
        print("  ✓ اختراق الجهاز المتصل يكشف نافذة يومين فقط، وينتهي أثره بالتغيير التالي.")
        print("  ✓ سرقة الخزنة لا تكشف الماضي.")
        print("  ✓ أي تعديل على الرسالة يُكتشف ويُرفض.")
        print()


if __name__ == "__main__":
    main()
