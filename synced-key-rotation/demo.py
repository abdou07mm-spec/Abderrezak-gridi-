#!/usr/bin/env python3
"""
محاكاة كاملة للنظام:
  - أحمد وسارة، لكل منهما نظام 1 (أوفلاين) ونظام 2 (أونلاين).
  - "المخترق" يسجّل كل ما يمر عبر الإنترنت، ويحاول التزوير وإعادة الإرسال،
    ثم يسرق الأجهزة، بل ويتخيّل أنه كسر إحدى خوارزميتي التشفير.
  - مواعيد التغيير سرية وعشوائية، والوقت محاكى (لا داعي للانتظار).

التشغيل:  python demo.py
"""
from __future__ import annotations

import secrets
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from common import FORMAT_VERSION, secure_random, stamp, use_utf8_console
from offline_vault import OfflineVault, VaultError, dice_bits, export_bundle, key_fingerprint
from online_node import (
    BODY_OFFSET,
    HEADER,
    EpochState,
    LENGTH,
    NONCE_BYTES,
    NodeError,
    OnlineNode,
    chain_message_key,
    decode_packet,
    derive_epoch,
    layer_keys,
    read_handshake,
)

internet: list[str] = []   # كل ما يمر عبر الشبكة (المخترق يسجّله كله)


def title(text: str) -> None:
    print()
    print("=" * 74)
    print(text)
    print("=" * 74)


def short(packet: str) -> str:
    return f"{packet[:28]}... ({len(packet)} حرفًا)"


def clip(text: str) -> str:
    return text if len(text) <= 40 else text[:40] + "..."


def minutes(moment: datetime, count: int) -> datetime:
    return moment + timedelta(minutes=count)


class Person:
    def __init__(self, name: str, vault: OfflineVault, home: Path):
        self.name = name
        self.vault = vault
        self.node = OnlineNode.open(home / "online_node.json")
        self.usb = home / "usb_transfer"   # منطقة النقل في اتجاه واحد

    def rotate(self, now: datetime) -> str:
        """الخزنة تُخرج مفتاحها ثم تنفصل، والنظام المتصل يولّد سرًا جديدًا ويُرسل مصافحته."""
        bundle = self.vault.release_key(now)
        export_bundle(bundle, self.usb)
        self.node.import_from_folder(self.usb, now)
        handshake = self.node.my_handshake(now)
        internet.append(handshake)
        print(f"  [{stamp(now)}] {self.name}: مفتاح خزنة الفترة {bundle['epoch']} "
              f"(بصمته {key_fingerprint(bytes.fromhex(bundle['key']))}) + سرّ عشوائي جديد")
        return handshake

    def send(self, text: str, now: datetime) -> str:
        packet = self.node.send(text, now)
        internet.append(packet)
        print(f"  [{stamp(now)}] {self.name} يرسل: «{clip(text)}» "
              f"({len(text.encode('utf-8'))} بايت)")
        print(f"      على الإنترنت: {short(packet)}")
        return packet

    def receive(self, packet: str, now: datetime, label: str = "") -> None:
        try:
            result = self.node.receive(packet, now)
            if result.kind == "message":
                print(f"  [{stamp(now)}] {self.name} {label}تقرأ: «{clip(result.text)}»  ✓")
        except NodeError as error:
            print(f"  [{stamp(now)}] {self.name} {label}: ✗ {error}")


def handshake(a: Person, hs_a: str, b: Person, hs_b: str, now: datetime) -> None:
    b.node.receive(hs_a, now)
    a.node.receive(hs_b, now)
    fa, fb = a.node.key_fingerprint(now), b.node.key_fingerprint(now)
    print(f"      المصافحة اكتملت. مفتاح الفترة: عند {a.name} {fa} | عند {b.name} {fb} "
          f"→ {'متطابقان ✓' if fa == fb else 'مختلفان ✗'}")


def change(a: Person, b: Person, now: datetime) -> None:
    handshake(a, a.rotate(now), b, b.rotate(now), now)


def attack(node: OnlineNode, packet: str, label: str, now: datetime) -> None:
    try:
        result = node.receive(packet, now)
        print(f"      المخترق يقرأ {label}: «{clip(result.text)}»  ← نجح")
    except NodeError:
        print(f"      المخترق يحاول قراءة {label}: فشل ✗")


def main() -> None:
    use_utf8_console()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        lair = tmp / "attacker"
        lair.mkdir()

        # ------------------------------------------------------------------
        title("المرحلة 0 — طقس البذرة: اللقاء الأول (مرة واحدة فقط)")
        t0 = datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc)
        sara_randomness = secure_random(32)
        dice = " ".join(str(secrets.randbelow(6) + 1) for _ in range(100))
        vault_a, vault_s = OfflineVault.create_pair(
            tmp / "ahmed" / "offline_vault.json", tmp / "sara" / "offline_vault.json",
            min_hours=2, max_hours=10, peer_randomness=sara_randomness, dice=dice, now=t0)
        print(f"  [{stamp(t0)}] البذرة مزيج من ثلاثة مصادر مستقلة:")
        print("      - عشوائية جهاز أحمد (256 بت)")
        print("      - عشوائية جهاز سارة (256 بت)")
        print(f"      - 100 رمية نرد حقيقية ({dice_bits(100):.0f} بت): {dice[:29]}...")
        print("      يكفي أن يكون مصدر واحد منها سليمًا لتكون البذرة غير متوقعة.")
        print(f"      بصمة الزوج: عند أحمد {vault_a.pair_id} | عند سارة {vault_s.pair_id}")
        ahmed = Person("أحمد", vault_a, tmp / "ahmed")
        sara = Person("سارة", vault_s, tmp / "sara")

        # ------------------------------------------------------------------
        title("مواعيد التغيير: سرية، غير منتظمة، ومتطابقة عند الطرفين")
        changes = vault_a.upcoming_changes(5)
        previous = t0
        for i, (when, when_s) in enumerate(zip(changes, vault_s.upcoming_changes(5)), 1):
            gap = (when - previous).total_seconds() / 3600
            print(f"  التغيير {i}: {stamp(when)} (بعد {gap:.2f} ساعة)"
                  f"  {'✓ نفس الموعد عند سارة' if when == when_s else '✗'}")
            previous = when
        print("  ← لا أحد غيرهما يعرف هذه المواعيد، ولا يمكن توقّعها: كل مدة تُحسب من السلسلة السرية.")
        c1, c2, c3, c4, _ = changes

        # ------------------------------------------------------------------
        title("التغيير 1 — مصافحة، ومحاولة تسلل، وإخفاء الآثار")
        hs_a = ahmed.rotate(c1)
        hs_s = sara.rotate(c1)
        print("  المخترق يرسل لسارة حزمة مزوّرة (بمفتاح خزنة مخمَّن) ليتسلل في المنتصف:")
        fake_vault, _ = OfflineVault.create_pair(lair / "fake_a.json", lair / "fake_b.json", now=t0)
        fake_node = OnlineNode.open(lair / "fake_node.json")
        fake_node.import_bundle(fake_vault.release_key(c1), c1)
        sara.receive(fake_node.my_handshake(c1), c1, "تستقبل الحزمة المزوّرة")
        handshake(ahmed, hs_a, sara, hs_s, c1)

        m1 = ahmed.send("الاجتماع غدًا في المكان المعتاد", minutes(c1, 5))
        sara.receive(m1, minutes(c1, 6))
        long_text = ahmed.send("تقرير طويل: " + "تفاصيل كثيرة " * 20, minutes(c1, 7))
        sara.receive(long_text, minutes(c1, 8))
        print("  ما يراه المخترق: كل الحزم بالطول نفسه تمامًا (المصافحة، والرسالة القصيرة،")
        print("  والتقرير الطويل)، وكلها تبدو عشوائية. لا يعرف أيها مصافحة، ولا طول النص،")
        print("  ولا رقم الرسالة أو الفترة. الطول الثابت لكل الحزم:",
              {len(p) for p in (hs_a, hs_s, m1, long_text)})

        # ------------------------------------------------------------------
        title("مفتاح لكل رسالة: ترتيب مختلف، وإعادة إرسال، وسرقة الجهاز")
        m2 = ahmed.send("أحضر الوثائق معك", minutes(c1, 20))
        m3 = ahmed.send("ولا تنسَ الختم", minutes(c1, 21))
        print("  الشبكة توصل الرسالة الثانية قبل الأولى:")
        sara.receive(m3, minutes(c1, 22))
        sara.receive(m2, minutes(c1, 23))
        print("  المخترق يعيد إرسال رسالة سجّلها لسارة:")
        sara.receive(m2, minutes(c1, 24), "تستقبل النسخة المكررة")

        shutil.copy(sara.node.path, lair / "stolen_sara_node.json")
        stolen = OnlineNode.open(lair / "stolen_sara_node.json")
        print(f"  [{stamp(minutes(c1, 40))}] المخترق يسرق نسخة من هاتف سارة المتصل، "
              "ومعه تسجيل كل ما مر عبر الإنترنت:")
        for label, packet in (("رسالة 1", m1), ("رسالة 2", m2), ("رسالة 3", m3)):
            attack(stolen, packet, label, minutes(c1, 41))
        print("      ← الرسائل المقروءة لا يمكن قراءتها: مفتاح كل رسالة أُتلف لحظة قراءتها.")
        m4 = ahmed.send("سأتأخر قليلًا", minutes(c1, 50))
        sara.receive(m4, minutes(c1, 51))
        attack(stolen, m4, "رسالة جديدة في الفترة نفسها", minutes(c1, 51))
        print("      ← هذه هي النافذة الوحيدة المكشوفة: من لحظة السرقة حتى التغيير التالي.")

        # ------------------------------------------------------------------
        title("التغيير 2 — في موعد سري: المفتاح المسروق يفقد قيمته")
        change(ahmed, sara, c2)
        m5 = ahmed.send("الموعد الجديد يوم الجمعة", minutes(c2, 10))
        sara.receive(m5, minutes(c2, 11))
        attack(stolen, m5, "رسالة الفترة الجديدة بالجهاز المسروق", minutes(c2, 11))

        # ------------------------------------------------------------------
        title("تجربة خيالية: المخترق كسر خوارزمية ChaCha20 بالكامل")
        epoch = max(ahmed.node.epochs)
        state = ahmed.node.epochs[epoch]
        chain_before, counter = state.send_chain, state.send_counter
        m6 = ahmed.send("كلمة السر للخزانة: 7391", minutes(c2, 20))
        sara.receive(m6, minutes(c2, 21))
        k_aes, k_chacha = layer_keys(chain_message_key(chain_before))   # محاكاة فقط
        raw = decode_packet(m6)
        header = HEADER.pack(b"M", FORMAT_VERSION, epoch, b"A", counter)
        inner = ChaCha20Poly1305(k_chacha).decrypt(raw[:NONCE_BYTES], raw[BODY_OFFSET:], header)
        print(f"  بعد نزع طبقة ChaCha20 يجد المخترق: {inner[:20].hex()}... (طبقة AES ما زالت تحميها)")
        plain = AESGCM(k_aes).decrypt(raw[:NONCE_BYTES], inner, header)
        (length,) = LENGTH.unpack(plain[:LENGTH.size])
        text = plain[LENGTH.size:LENGTH.size + length].decode("utf-8")
        print(f"  فقط لو كسر AES أيضًا في الوقت نفسه لقرأ: «{text}»")
        print("  ← طبقتان بخوارزميتين مختلفتين: يجب كسر الاثنتين معًا.")

        # ------------------------------------------------------------------
        title("أسوأ حالة: المخترق يسرق الخزنة الأوفلاين نفسها")
        shutil.copy(ahmed.vault.path, lair / "stolen_vault.json")
        stolen_vault = OfflineVault.load(lair / "stolen_vault.json")
        try:
            stolen_vault.release_key(minutes(c1, 5))
        except VaultError:
            print("  المخترق يطلب من الخزنة المسروقة مفتاح الفترة 1: فشل ✗ (أُتلف نهائيًا)")
        print(f"  ويعرف الآن موعد التغيير القادم: {stamp(stolen_vault.next_change())}")
        hs_a = ahmed.rotate(c3)
        hs_s = sara.rotate(c3)
        handshake(ahmed, hs_a, sara, hs_s, c3)
        m7 = ahmed.send("تم نقل الوثائق", minutes(c3, 15))
        sara.receive(m7, minutes(c3, 16))

        vault_key = bytes.fromhex(stolen_vault.release_key(c3)["key"])
        print(f"      المخترق يحسب مفتاح خزنة الفترة الجديدة: {key_fingerprint(vault_key)} (صحيح!)")
        epoch, _, pub_a = read_handshake(vault_key, hs_a)
        _, _, pub_s = read_handshake(vault_key, hs_s)
        print("      ويفتح المصافحتين اللتين سجّلهما، فيحصل على النصفين العامين الحقيقيين.")
        guess = X25519PrivateKey.from_private_bytes(secure_random(32)).exchange(
            X25519PublicKey.from_public_bytes(pub_s))
        best = derive_epoch(vault_key, epoch, guess, pub_a, pub_s)
        print(f"      أفضل مفتاح يستطيع حسابه: {best.fingerprint} ≠ الحقيقي {sara.node.key_fingerprint(c3)}")
        eve = OnlineNode(lair / "eve_node.json", role="B", epochs={epoch: EpochState(
            valid_from=c3, valid_until=c4, hs_key=bytes(32), handshake="", my_public=b"",
            header_key=best.header_key, recv_chain=best.chains["A"])})
        attack(eve, m7, "رسالة ما بعد السرقة بهذا المفتاح", minutes(c3, 16))
        print("      ← ينقصه السرّ العشوائي الخاص الذي وُلد على جهاز أحمد بعد السرقة ولم يغادره.")
        print("      ⚠ لكنه بالخزنة يستطيع انتحال شخصية أحمد إذا تحكّم في الشبكة نفسها؛")
        print("        لذلك بعد أي سرقة يُعاد الاقتران، ويمكن مقارنة بصمة المفتاح بالهاتف.")

        print("  المخترق يعدّل حرفًا واحدًا في رسالة جديدة قبل وصولها:")
        m8 = ahmed.send("أراك هناك", minutes(c3, 30))
        tampered = bytearray(m8.encode())
        tampered[700] = ord("A") if tampered[700] != ord("A") else ord("B")
        sara.receive(tampered.decode(), minutes(c3, 31), "تستقبل النسخة المعدّلة")
        sara.receive(m8, minutes(c3, 32), "تستقبل النسخة الأصلية ثم ")

        # ------------------------------------------------------------------
        title("التغيير 4 — هاتف سارة مطفأ: المصافحة تنتظرها")
        hs_a = ahmed.rotate(c4)
        try:
            ahmed.node.send("مرحبًا", minutes(c4, 5))
        except NodeError as error:
            print(f"  [{stamp(minutes(c4, 5))}] أحمد يحاول الإرسال: ✗ {error}")
        print(f"  [{stamp(minutes(c4, 60))}] سارة تشغّل هاتفها:")
        hs_s = sara.rotate(minutes(c4, 60))
        handshake(ahmed, hs_a, sara, hs_s, minutes(c4, 60))
        m9 = ahmed.send("مرحبًا، هل أنتِ متاحة اليوم؟", minutes(c4, 61))
        sara.receive(m9, minutes(c4, 62))

        # ------------------------------------------------------------------
        title("الخلاصة")
        for line in (
            "البذرة من ثلاثة مصادر عشوائية مستقلة (جهازان + نرد).",
            "مواعيد التغيير سرية وغير منتظمة، ومتطابقة عند الطرفين دون تواصل.",
            "كل تغيير يضيف عشوائية جديدة (Diffie-Hellman): المفتاح المسروق يموت عند التغيير التالي.",
            "مفتاح جديد لكل رسالة يُتلف عند قراءتها: سرقة الجهاز لا تكشف الرسائل المقروءة.",
            "إعادة إرسال رسالة مسجّلة تُرفض، والرسائل التي تصل بغير ترتيب تُقرأ عادي.",
            "طبقتان بخوارزميتين مختلفتين: كسر إحداهما لا يكفي.",
            "كل الحزم بطول ثابت ومشفّرة بالكامل: لا نوع، ولا طول، ولا رقم ظاهر.",
            "التزوير والتعديل يُكشفان ويُرفضان.",
        ):
            print(f"  ✓ {line}")
        print()


if __name__ == "__main__":
    main()
