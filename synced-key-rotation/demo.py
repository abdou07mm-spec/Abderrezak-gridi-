#!/usr/bin/env python3
"""
محاكاة كاملة للفكرة على مدى 6 أيام:
  - أحمد (المرسل) وسارة (المستقبلة)، لكل منهما نظام 1 (أوفلاين) ونظام 2 (أونلاين).
  - "المخترق" يسجّل كل ما يمر عبر الإنترنت، ثم يخترق الأجهزة ويسرقها لاحقًا.
  - الوقت محاكى (لا داعي للانتظار حتى الساعة 8 صباحًا).

التشغيل:  python demo.py
"""
from __future__ import annotations

import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from common import stamp, use_utf8_console
from offline_vault import OfflineVault, VaultError, export_bundle, key_fingerprint
from online_node import (
    NodeError,
    OnlineNode,
    X25519PrivateKey,
    handshake_public,
    message_epoch,
    sign_handshake,
)


def at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)


def title(text: str) -> None:
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


def short(token: str) -> str:
    return token if len(token) <= 44 else token[:44] + "..."


internet: list[str] = []   # كل ما يمر عبر الشبكة (المخترق يسجّله كله)


class Person:
    def __init__(self, name: str, vault: OfflineVault, home: Path):
        self.name = name
        self.vault = vault
        self.node = OnlineNode.open(home / "online_node.json")
        self.usb = home / "usb_transfer"   # منطقة النقل في اتجاه واحد

    def rotate(self, now: datetime) -> str:
        """موعد التغيير: الخزنة تُخرج مفتاحها ثم تنفصل، والنظام المتصل يولّد سرًا جديدًا."""
        bundle = self.vault.release_key(now)
        export_bundle(bundle, self.usb)
        self.node.import_from_folder(self.usb, now)
        handshake = self.node.my_handshake(now)
        internet.append(handshake)
        print(f"  [{stamp(now)}] {self.name}: مفتاح الخزنة للحقبة {bundle['epoch']} "
              f"(بصمته {key_fingerprint(bytes.fromhex(bundle['key']))})")
        print(f"      + سرّ عشوائي جديد؛ نصفه العام أُرسل عبر الإنترنت: "
              f"{handshake_public(handshake).hex()[:24]}...")
        return handshake


def complete(a: Person, hs_a: str, b: Person, hs_b: str, now: datetime) -> None:
    """كل طرف يقبل مصافحة الآخر ويحسب مفتاح اليوم النهائي."""
    b.node.accept_handshake(hs_a, now)
    a.node.accept_handshake(hs_b, now)
    fa, fb = a.node.key_fingerprint(now), b.node.key_fingerprint(now)
    print(f"      مفتاح اليوم النهائي: عند {a.name} {fa} | عند {b.name} {fb} "
          f"→ {'متطابقان ✓' if fa == fb else 'مختلفان ✗'}")


def new_day(a: Person, b: Person, now: datetime) -> None:
    complete(a, a.rotate(now), b, b.rotate(now), now)


def send(sender: Person, text: str, now: datetime) -> str:
    token = sender.node.encrypt(text, now)
    internet.append(token)
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


def main() -> None:
    use_utf8_console()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        lair = tmp / "attacker"
        lair.mkdir()

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
        ahmed = Person("أحمد", vault_a, tmp / "ahmed")
        sara = Person("سارة", vault_s, tmp / "sara")

        # ------------------------------------------------------------------
        title("اليوم 1 — الساعة 08:00: أول تغيير آلي + أول مصافحة Diffie-Hellman")
        hs_a = ahmed.rotate(at(3, 8))
        hs_s = sara.rotate(at(3, 8))
        print("  مفتاحا الخزنتين متطابقان، أما النصفان العامان فمختلفان ومكشوفان للجميع.")

        print("  المخترق يحاول التسلل في المنتصف بإرسال نصفه هو إلى سارة باسم أحمد:")
        fake_public = X25519PrivateKey.generate().public_key().public_bytes_raw()
        fake = sign_handshake(secrets.token_bytes(32), "A", 1, fake_public)
        try:
            sara.node.accept_handshake(fake, at(3, 8))
        except NodeError as error:
            print(f"      ✗ {error}")

        complete(ahmed, hs_a, sara, hs_s, at(3, 8))
        print("      ← السرّ المشترك لم يمر عبر الإنترنت أبدًا، ومع ذلك حصل عليه الطرفان.")
        m1 = send(ahmed, "الاجتماع غدًا في المكان المعتاد", at(3, 9, 30))
        receive(sara, m1, at(3, 9, 31))

        # ------------------------------------------------------------------
        title("اليوم 2 — رسالة أُرسلت قبل التغيير بدقيقة ووصلت بعده")
        late = send(ahmed, "تأكيد: الساعة الثالثة", at(4, 7, 59))
        new_day(ahmed, sara, at(4, 8))
        receive(sara, late, at(4, 8, 1))
        print("      (نُبقي مفتاح الأمس فقط كفترة سماح حتى لا تضيع رسائل الطريق)")
        m2 = send(ahmed, "أحضر الوثائق معك", at(4, 10))
        receive(sara, m2, at(4, 10, 5))

        # ------------------------------------------------------------------
        title("اليوم 3 — أسوأ حالة: المخترق يسرق جهازَي أحمد معًا (المتصل والأوفلاين)")
        new_day(ahmed, sara, at(5, 8))
        m3 = send(ahmed, "تم تغيير الخطة", at(5, 11))
        receive(sara, m3, at(5, 11, 2))

        shutil.copy(ahmed.node.path, lair / "stolen_node.json")
        shutil.copy(ahmed.vault.path, lair / "stolen_vault.json")
        stolen_node = OnlineNode.open(lair / "stolen_node.json")
        stolen_vault = OfflineVault.load(lair / "stolen_vault.json")
        print(f"  [{stamp(at(5, 15))}] المخترق نسخ ملفات الجهازين، ومعه تسجيل لكل ما "
              f"مر عبر الإنترنت ({len(internet)} عنصرًا).")
        attack(stolen_node, m1, "رسالة اليوم 1", at(5, 15))
        attack(stolen_node, m2, "رسالة اليوم 2", at(5, 15))
        attack(stolen_node, m3, "رسالة اليوم 3", at(5, 15))
        try:
            stolen_vault.release_key(at(3, 9, 30))
        except VaultError:
            print("      المخترق يطلب من الخزنة المسروقة مفتاح اليوم 1: فشل ✗ (أُتلف نهائيًا)")
        print("      ← الضرر محصور في نافذة يومين؛ الماضي الأبعد محمي.")

        # ------------------------------------------------------------------
        title("اليوم 4 — المصافحة الجديدة تطرد المخترق رغم أنه يملك الخزنة")
        new_day(ahmed, sara, at(6, 8))
        m4 = send(ahmed, "الموعد الجديد يوم الجمعة", at(6, 9))
        receive(sara, m4, at(6, 9, 3))

        attack(stolen_node, m4, "رسالة اليوم 4 بالنظام المتصل المسروق", at(6, 9, 3))

        bundle = stolen_vault.release_key(at(6, 8))
        print(f"      المخترق يحسب من الخزنة المسروقة مفتاح خزنة اليوم 4: "
              f"{key_fingerprint(bytes.fromhex(bundle['key']))} (صحيح!)")
        eve = OnlineNode.open(lair / "eve_node.json")
        eve.import_bundle(bundle, at(6, 8))
        eve.accept_handshake(sara.node.epochs[4].handshake, at(6, 8))
        print("      ويملك أيضًا النصفين العامين لليوم 4 (سجّلهما من الإنترنت)...")
        attack(eve, m4, "رسالة اليوم 4 بمفتاح الخزنة + النصفين العامين", at(6, 9, 3))
        print("      ← ينقصه السرّ العشوائي الخاص الذي ولّده جهاز أحمد اليوم بعد السرقة،")
        print("        وهذا السرّ لم يغادر الجهاز أبدًا. بدون Diffie-Hellman كان المخترق")
        print("        سيقرأ كل رسائل المستقبل؛ الآن طُرد عند أول مصافحة جديدة.")
        print("      ⚠ لكن بما أنه يملك الخزنة، يستطيع توقيع مصافحات مزيفة إذا تحكّم")
        print("        في الشبكة نفسها (انتحال نشط). لذلك: بعد أي سرقة يُعاد الاقتران،")
        print("        ويمكن للطرفين مقارنة بصمة مفتاح اليوم بالهاتف لكشف أي انتحال.")

        print("  المخترق يعدّل حرفًا واحدًا في رسالة اليوم 4 ويمررها لسارة:")
        raw = bytearray(m4.encode())
        raw[-5] = ord("A") if raw[-5] != ord("A") else ord("B")
        receive(sara, raw.decode(), at(6, 9, 4))

        # ------------------------------------------------------------------
        title("اليوم 5 — هاتف سارة مطفأ صباحًا: المصافحة تنتظرها")
        hs_a = ahmed.rotate(at(7, 8))
        try:
            ahmed.node.encrypt("صباح الخير", at(7, 9))
        except NodeError as error:
            print(f"  [{stamp(at(7, 9))}] أحمد يحاول الإرسال: ✗ {error}")
        print(f"  [{stamp(at(7, 12))}] سارة تشغّل هاتفها:")
        hs_s = sara.rotate(at(7, 12))
        complete(ahmed, hs_a, sara, hs_s, at(7, 12))
        m5 = send(ahmed, "صباح الخير، هل أنتِ متاحة اليوم؟", at(7, 12, 5))
        receive(sara, m5, at(7, 12, 6))

        # ------------------------------------------------------------------
        title("الخلاصة")
        print("  ✓ المفتاح يتغير عند الموعد، ومفتاح اليوم = مفتاح الخزنة + سرّ عشوائي جديد.")
        print("  ✓ السرّ العشوائي يتفق عليه الطرفان دون أن يمر عبر الإنترنت (Diffie-Hellman).")
        print("  ✓ تسجيل كل ما يمر عبر الإنترنت لا يفيد المخترق بشيء.")
        print("  ✓ محاولة التسلل بنصف مزيف تُرفض لأنها غير موقّعة بمفتاح الخزنة.")
        print("  ✓ اختراق الأجهزة يكشف نافذة يومين فقط، والماضي الأبعد محمي.")
        print("  ✓ حتى سرقة الخزنة لا تسمح بقراءة رسائل ما بعد المصافحة التالية.")
        print("  ✓ أي تعديل على الرسالة يُكتشف ويُرفض.")
        print()


if __name__ == "__main__":
    main()
