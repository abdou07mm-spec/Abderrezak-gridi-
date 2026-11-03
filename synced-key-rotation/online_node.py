#!/usr/bin/env python3
"""
النظام رقم 2 — النظام المتصل (Online Node)
==========================================

هو التطبيق الذي يرسل ويستقبل الرسائل عبر الإنترنت. لا يملك البذرة السرية أبدًا.

ما يحدث عند كل موعد تغيير (مثلًا 08:00):
  1. يستلم "مفتاح الخزنة" لليوم من النظام 1 (في اتجاه واحد).
  2. يولّد سرًا عشوائيًا جديدًا تمامًا (مفتاح X25519 خاص) لا يغادر الجهاز أبدًا،
     ويحسب منه "نصفًا عامًا" يرسله إلى الطرف الآخر عبر الإنترنت.
     هذه هي "المصافحة" (handshake)، وهي موقّعة بمفتاح الخزنة حتى لا يستطيع
     أحد انتحالها.
  3. عندما تصله مصافحة الطرف الآخر، يحسب الطرفان السرّ المشترك نفسه
     (تبادل Diffie-Hellman)، رغم أن هذا السرّ لم يمر عبر الإنترنت أبدًا.
  4. مفتاح اليوم النهائي = مزج (مفتاح الخزنة + سرّ Diffie-Hellman).
     ثم يُتلف السرّ الخاص ومفتاح الخزنة فورًا؛ يبقى المفتاح النهائي فقط.

لماذا المزج؟ لقراءة رسائل يوم ما يحتاج المخترق إلى الاثنين معًا:
  - من سرق الخزنة يملك مفاتيح الخزنة، لكنه لا يملك الأسرار العشوائية اليومية
    التي تولد على الأجهزة بعد السرقة، فيُطرد عند المصافحة التالية.
  - من يستطيع كسر Diffie-Hellman يومًا ما (مثلًا بحاسوب كمّي) لا يملك
    مفتاح الخزنة.

التشفير نفسه بخوارزمية AES-256-GCM (المعيار العالمي) التي تُخفي المحتوى
وتكشف أي تعديل على الرسالة ولو حرفًا واحدًا.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import os
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import (
    FORMAT_VERSION,
    ROLES,
    Schedule,
    fingerprint,
    read_json,
    stamp,
    to_utc,
    use_utf8_console,
    utc_now,
    wipe_file,
    write_private_json,
)

KEY_BYTES = 32
DH_BYTES = 32       # طول المفتاح العام والخاص في X25519
NONCE_BYTES = 12
TAG_BYTES = 16

# رأس الرسالة المشفرة:  [الإصدار][النوع M][رقم الحقبة]
MESSAGE_HEADER = struct.Struct(">BcI")
# رأس المصافحة:        [الإصدار][النوع H][رقم الحقبة][دور المرسل A/B]
HANDSHAKE_HEADER = struct.Struct(">BcIc")
HANDSHAKE_SIZE = HANDSHAKE_HEADER.size + DH_BYTES + 32  # + النصف العام + التوقيع

# كم حقبة سابقة نحتفظ بمفتاحها؟ 1 = مفتاح الأمس فقط، لكي لا تضيع رسالة
# أُرسلت 07:59 ووصلت 08:01. كلما صغر الرقم صغر الضرر عند الاختراق.
KEEP_PREVIOUS_EPOCHS = 1


class NodeError(Exception):
    """خطأ في النظام المتصل."""


class KeyUnavailable(NodeError):
    """لا يوجد مفتاح جاهز للحقبة المطلوبة."""


class HandshakePending(KeyUnavailable):
    """مفتاح الخزنة موجود، لكن النصف العشوائي من الطرف الآخر لم يصل بعد."""


class MessageRejected(NodeError):
    """الرسالة أو المصافحة تالفة أو معدّلة أو مزوّرة."""


# ---------------------------------------------------------------------- #
# أدوات
# ---------------------------------------------------------------------- #
def _sub_key(vault_key: bytes, label: bytes) -> bytes:
    """نشتق من مفتاح الخزنة مفتاحًا مستقلًا لكل استعمال (توقيع / مزج)."""
    return hmac.new(vault_key, label, hashlib.sha256).digest()


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode(token: str, min_size: int) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(token.strip().encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise MessageRejected("النص ليس بالصيغة الصحيحة") from None
    if len(raw) < min_size:
        raise MessageRejected("النص قصير جدًا أو مبتور")
    return raw


def sign_handshake(vault_key: bytes, role: str, epoch: int, public: bytes) -> str:
    """يبني مصافحة: النصف العام + توقيع بمفتاح الخزنة يثبت أنها من الطرف المقترن."""
    header = HANDSHAKE_HEADER.pack(FORMAT_VERSION, b"H", epoch, role.encode("ascii"))
    tag = hmac.new(_sub_key(vault_key, b"handshake-auth"),
                   header + public, hashlib.sha256).digest()
    return _encode(header + public + tag)


def message_epoch(token: str) -> int:
    """يقرأ رقم الحقبة المكتوب في رأس الرسالة (دون فك تشفيرها)."""
    raw = _decode(token, MESSAGE_HEADER.size)
    return MESSAGE_HEADER.unpack(raw[:MESSAGE_HEADER.size])[2]


def handshake_public(token: str) -> bytes:
    """يقرأ النصف العام من مصافحة (للعرض فقط؛ هو معلن أصلًا)."""
    raw = _decode(token, HANDSHAKE_SIZE)
    return raw[HANDSHAKE_HEADER.size:HANDSHAKE_HEADER.size + DH_BYTES]


def _hex(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def _unhex(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


@dataclass
class EpochState:
    """كل ما يخص حقبة واحدة على النظام المتصل."""

    my_public: bytes                   # نصفي العام (معلن)
    handshake: str                     # مصافحتي الموقّعة، لإرسالها للطرف الآخر
    vault_key: bytes | None = None     # يُتلف بعد اكتمال المصافحة
    my_private: bytes | None = None    # سرّي العشوائي؛ يُتلف بعد اكتمال المصافحة
    peer_public: bytes | None = None   # النصف العام للطرف الآخر
    key: bytes | None = None           # مفتاح الحقبة النهائي

    @property
    def ready(self) -> bool:
        return self.key is not None

    def to_dict(self) -> dict:
        return {
            "my_public": _hex(self.my_public),
            "handshake": self.handshake,
            "vault_key": _hex(self.vault_key),
            "my_private": _hex(self.my_private),
            "peer_public": _hex(self.peer_public),
            "key": _hex(self.key),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EpochState":
        return cls(
            my_public=bytes.fromhex(data["my_public"]),
            handshake=data["handshake"],
            vault_key=_unhex(data.get("vault_key")),
            my_private=_unhex(data.get("my_private")),
            peer_public=_unhex(data.get("peer_public")),
            key=_unhex(data.get("key")),
        )


class OnlineNode:
    """النظام المتصل: يحفظ حالة الحقبة الحالية والسابقة فقط."""

    def __init__(self, path: Path, schedule: Schedule | None = None,
                 pair_id: str | None = None, role: str | None = None,
                 epochs: dict[int, EpochState] | None = None):
        self.path = Path(path)
        self.schedule = schedule
        self.pair_id = pair_id
        self.role = role
        self.epochs: dict[int, EpochState] = dict(epochs or {})

    @classmethod
    def open(cls, path: Path) -> "OnlineNode":
        """يفتح ملف النظام إن وُجد، وإلا ينشئ نظامًا جديدًا فارغًا."""
        path = Path(path)
        if not path.exists():
            return cls(path)
        data = read_json(path)
        if data.get("format") != "online-node" or data.get("version") != FORMAT_VERSION:
            raise NodeError(f"هذا الملف ليس ملف نظام متصل صالح: {path} "
                            "(إذا أُنشئ بإصدار سابق من البرنامج فاحذفه وأعد الاستيراد)")
        return cls(
            path,
            Schedule.from_dict(data["schedule"]),
            data["pair_id"],
            data["role"],
            {int(e): EpochState.from_dict(s) for e, s in data["epochs"].items()},
        )

    def save(self) -> None:
        write_private_json(self.path, {
            "format": "online-node",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "role": self.role,
            "schedule": self.schedule.to_dict() if self.schedule else None,
            "epochs": {str(e): s.to_dict() for e, s in sorted(self.epochs.items())},
        })

    def _require_paired(self) -> Schedule:
        if self.schedule is None:
            raise KeyUnavailable("هذا النظام لم يستلم أي مفتاح من الخزنة بعد")
        return self.schedule

    def current_epoch(self, now: datetime | None = None) -> int:
        return self._require_paired().epoch_at(utc_now() if now is None else to_utc(now))

    def _purge(self, now: datetime | None, save: bool = True) -> int:
        """يُتلف كل ما هو أقدم من نافذة السماح. يعيد رقم الحقبة الحالية."""
        current = self.current_epoch(now)
        expired = [e for e in self.epochs if e < current - KEEP_PREVIOUS_EPOCHS]
        for epoch in expired:
            del self.epochs[epoch]
        if expired and save:
            self.save()
        return current

    # ------------------------------------------------------------------ #
    # 1) استلام مفتاح الخزنة + توليد السرّ العشوائي لليوم
    # ------------------------------------------------------------------ #
    def import_bundle(self, bundle: dict, now: datetime | None = None) -> int:
        if bundle.get("format") != "key-bundle" or bundle.get("version") != FORMAT_VERSION:
            raise NodeError("هذه ليست حزمة مفتاح صالحة (أو أنها من إصدار سابق)")
        role = bundle.get("role")
        if role not in ROLES:
            raise NodeError("دور غير معروف في حزمة المفتاح")
        if self.pair_id is None:
            # أول مفتاح: نتعرف على الخزنة المقترنة وجدولها الزمني ودورنا
            self.pair_id = bundle["pair_id"]
            self.role = role
            self.schedule = Schedule.from_dict(bundle["schedule"])
        elif bundle["pair_id"] != self.pair_id:
            raise NodeError("هذا المفتاح صادر من خزنة أخرى غير مقترنة بهذا النظام — رُفض")
        elif role != self.role:
            raise NodeError("هذا المفتاح صادر من خزنة الطرف الآخر، لا من خزنتك — رُفض")

        vault_key = bytes.fromhex(bundle["key"])
        if len(vault_key) != KEY_BYTES:
            raise NodeError("طول المفتاح غير صحيح")
        epoch = int(bundle["epoch"])
        current = self._purge(now, save=False)
        if epoch < current - KEEP_PREVIOUS_EPOCHS:
            raise NodeError(f"مفتاح الحقبة {epoch} منتهي الصلاحية")

        state = self.epochs.get(epoch)
        if state is None:
            private = X25519PrivateKey.generate()          # عشوائية جديدة تمامًا
            public = private.public_key().public_bytes_raw()
            self.epochs[epoch] = EpochState(
                my_public=public,
                handshake=sign_handshake(vault_key, role, epoch, public),
                vault_key=vault_key,
                my_private=private.private_bytes_raw(),
            )
        elif not state.ready and not hmac.compare_digest(state.vault_key, vault_key):
            raise NodeError("مفتاح خزنة مختلف لحقبة استُورد مفتاحها سابقًا — رُفض")
        self.save()
        return epoch

    def import_from_folder(self, folder: Path, now: datetime | None = None) -> list[int]:
        """يأخذ كل حزم المفاتيح من مجلد النقل ثم يمسحها منه."""
        epochs = []
        for path in sorted(Path(folder).glob("key_epoch_*.json")):
            epochs.append(self.import_bundle(read_json(path), now))
            wipe_file(path)
        if not epochs:
            raise NodeError(f"لا توجد مفاتيح في مجلد النقل: {folder}")
        return epochs

    # ------------------------------------------------------------------ #
    # 2) المصافحة: تبادل الأنصاف العامة عبر الإنترنت
    # ------------------------------------------------------------------ #
    def my_handshake(self, now: datetime | None = None) -> str:
        """مصافحتي لهذه الحقبة: تُرسل للطرف الآخر عبر الإنترنت (نشرها آمن)."""
        epoch = self._purge(now)
        state = self.epochs.get(epoch)
        if state is None:
            raise KeyUnavailable(
                f"لم يُستورد مفتاح الخزنة للحقبة الحالية ({epoch}) بعد")
        return state.handshake

    def accept_handshake(self, token: str, now: datetime | None = None) -> int:
        """يستقبل نصف الطرف الآخر، يتحقق من توقيعه، ويحسب مفتاح الحقبة النهائي."""
        raw = _decode(token, HANDSHAKE_HEADER.size)
        version, kind, epoch, role_raw = HANDSHAKE_HEADER.unpack(raw[:HANDSHAKE_HEADER.size])
        if kind != b"H":
            raise MessageRejected("هذه رسالة مشفرة وليست مصافحة (استعمل فك التشفير)")
        if version != FORMAT_VERSION or len(raw) != HANDSHAKE_SIZE:
            raise MessageRejected("مصافحة بصيغة غير معروفة")
        self._require_paired()
        sender_role = role_raw.decode("ascii", "replace")
        if sender_role not in ROLES:
            raise MessageRejected("دور غير معروف في المصافحة")
        if sender_role == self.role:
            raise MessageRejected("هذه مصافحتك أنت أُعيدت إليك، لا مصافحة الطرف الآخر — رُفضت")

        self._purge(now)
        state = self.epochs.get(epoch)
        if state is None:
            raise KeyUnavailable(
                f"لا توجد حالة للحقبة {epoch}: استورد مفتاح الخزنة لهذه الحقبة أولًا "
                "ثم أعد قبول المصافحة (أو أنها قديمة جدًا).")

        public = raw[HANDSHAKE_HEADER.size:HANDSHAKE_HEADER.size + DH_BYTES]
        tag = raw[HANDSHAKE_HEADER.size + DH_BYTES:]
        if state.ready:
            if hmac.compare_digest(public, state.peer_public):
                return epoch  # نسخة مكررة من مصافحة قُبلت سابقًا
            raise MessageRejected("مصافحة مختلفة لحقبة اكتملت مصافحتها — رُفضت")

        expected = hmac.new(_sub_key(state.vault_key, b"handshake-auth"),
                            raw[:HANDSHAKE_HEADER.size] + public, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise MessageRejected(
                "توقيع المصافحة غير صحيح: ليست من الطرف المقترن "
                "(ربما محاولة انتحال) — رُفضت.")

        try:
            shared = X25519PrivateKey.from_private_bytes(state.my_private).exchange(
                X25519PublicKey.from_public_bytes(public))
        except ValueError:
            raise MessageRejected("النصف العام في المصافحة غير صالح — رُفضت") from None

        pub_a, pub_b = ((state.my_public, public) if self.role == "A"
                        else (public, state.my_public))
        state.key = HKDF(
            algorithm=SHA256(),
            length=KEY_BYTES,
            salt=_sub_key(state.vault_key, b"epoch-mix"),
            info=b"epoch-key|" + struct.pack(">I", epoch) + pub_a + pub_b,
        ).derive(shared)  # المزج: مفتاح الخزنة + سرّ Diffie-Hellman
        state.peer_public = public
        state.vault_key = None    # لم نعد نحتاجهما: نتلفهما
        state.my_private = None
        self.save()
        return epoch

    def key_fingerprint(self, now: datetime | None = None) -> str | None:
        """
        بصمة مفتاح اليوم النهائي. يمكن للطرفين قراءتها لبعضهما بالهاتف:
        إذا تطابقت فلا يوجد أي انتحال في المنتصف.
        """
        state = self.epochs.get(self._purge(now))
        return fingerprint(state.key, "epoch-key") if state and state.ready else None

    # ------------------------------------------------------------------ #
    # 3) التشفير وفك التشفير
    # ------------------------------------------------------------------ #
    def _ready_key(self, epoch: int) -> bytes:
        state = self.epochs.get(epoch)
        if state is None:
            raise KeyUnavailable(
                f"لا يوجد مفتاح للحقبة {epoch}: إما أنها قديمة وأُتلف مفتاحها، "
                "أو أن مفتاح الخزنة لها لم يُستورد بعد.")
        if not state.ready:
            raise HandshakePending(
                f"مفتاح الحقبة {epoch} غير مكتمل: بانتظار وصول النصف العشوائي "
                "من الطرف الآخر (مصافحته). تأكد أيضًا أنه استلم مصافحتك.")
        return state.key

    def encrypt(self, text: str, now: datetime | None = None) -> str:
        epoch = self._purge(now)
        if epoch not in self.epochs:
            raise KeyUnavailable(
                f"مفتاح الحقبة الحالية ({epoch}) غير موجود. "
                "يجب استيراده من الخزنة غير المتصلة أولًا — "
                "النظام يرفض الاستمرار بمفتاح قديم.")
        key = self._ready_key(epoch)
        header = MESSAGE_HEADER.pack(FORMAT_VERSION, b"M", epoch)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), header)
        return _encode(header + nonce + ciphertext)

    def decrypt(self, token: str, now: datetime | None = None) -> str:
        raw = _decode(token, MESSAGE_HEADER.size + NONCE_BYTES + TAG_BYTES)
        version, kind, epoch = MESSAGE_HEADER.unpack(raw[:MESSAGE_HEADER.size])
        if kind == b"H":
            raise MessageRejected("هذه مصافحة وليست رسالة (استعمل قبول المصافحة)")
        if version != FORMAT_VERSION or kind != b"M":
            raise MessageRejected("رسالة بصيغة غير معروفة")
        self._purge(now)
        key = self._ready_key(epoch)
        header = raw[:MESSAGE_HEADER.size]
        nonce = raw[MESSAGE_HEADER.size:MESSAGE_HEADER.size + NONCE_BYTES]
        try:
            plaintext = AESGCM(key).decrypt(
                nonce, raw[MESSAGE_HEADER.size + NONCE_BYTES:], header)
        except InvalidTag:
            raise MessageRejected(
                "فشل التحقق: الرسالة مُعدّلة أو مزوّرة أو ليست من الطرف المقترن — رُفضت."
            ) from None
        return plaintext.decode("utf-8")


# ---------------------------------------------------------------------- #
# واجهة سطر الأوامر
# ---------------------------------------------------------------------- #
def _cmd_import(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    epochs = node.import_from_folder(args.source)
    print(f"تم استيراد مفتاح الخزنة للحقبة {', '.join(map(str, epochs))} ومسحه من مجلد النقل.")
    print("وتم توليد سرّ عشوائي جديد لليوم. أرسل هذه المصافحة إلى الطرف الآخر")
    print("(نشرها آمن تمامًا، يمكن إرسالها بأي وسيلة):")
    print()
    print(node.my_handshake())


def _cmd_handshake(args: argparse.Namespace) -> None:
    print(OnlineNode.open(args.node).my_handshake())


def _cmd_accept(args: argparse.Namespace) -> None:
    token = args.token if args.token is not None else sys.stdin.read()
    node = OnlineNode.open(args.node)
    epoch = node.accept_handshake(token)
    print(f"اكتملت المصافحة للحقبة {epoch}. مفتاح اليوم جاهز.")
    fp = node.key_fingerprint()
    if fp:
        print(f"بصمة مفتاح اليوم: {fp}  (يمكنكما مقارنتها بالهاتف لكشف أي انتحال)")


def _cmd_encrypt(args: argparse.Namespace) -> None:
    text = args.text if args.text is not None else sys.stdin.read()
    print(OnlineNode.open(args.node).encrypt(text))


def _cmd_decrypt(args: argparse.Namespace) -> None:
    token = args.token if args.token is not None else sys.stdin.read()
    print(OnlineNode.open(args.node).decrypt(token))


def _cmd_status(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    if node.schedule is None:
        print("النظام غير مقترن بعد (لم يُستورد أي مفتاح).")
        return
    current = node.current_epoch()
    print(f"بصمة الزوج:  {node.pair_id}   الدور: {node.role}")
    print(f"الحقبة الآن: {current} (التغيير القادم: "
          f"{stamp(node.schedule.start_of(current + 1))})")
    for epoch, state in sorted(node.epochs.items()):
        status = ("جاهز، بصمة المفتاح " + fingerprint(state.key, "epoch-key")
                  if state.ready else "بانتظار مصافحة الطرف الآخر")
        print(f"  الحقبة {epoch}: {status}")


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="النظام 2: النظام المتصل")
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="استيراد مفتاح الخزنة لليوم وتوليد المصافحة")
    imp.add_argument("--node", required=True, type=Path)
    imp.add_argument("--from", dest="source", required=True, type=Path)
    imp.set_defaults(func=_cmd_import)

    hs = sub.add_parser("handshake", help="إعادة عرض مصافحتي لهذا اليوم")
    hs.add_argument("--node", required=True, type=Path)
    hs.set_defaults(func=_cmd_handshake)

    acc = sub.add_parser("accept", help="قبول مصافحة الطرف الآخر")
    acc.add_argument("--node", required=True, type=Path)
    acc.add_argument("token", nargs="?", help="المصافحة (أو تُقرأ من الإدخال القياسي)")
    acc.set_defaults(func=_cmd_accept)

    enc = sub.add_parser("encrypt", help="تشفير رسالة")
    enc.add_argument("--node", required=True, type=Path)
    enc.add_argument("text", nargs="?", help="النص (أو يُقرأ من الإدخال القياسي)")
    enc.set_defaults(func=_cmd_encrypt)

    dec = sub.add_parser("decrypt", help="فك تشفير رسالة")
    dec.add_argument("--node", required=True, type=Path)
    dec.add_argument("token", nargs="?", help="الرسالة المشفرة (أو تُقرأ من الإدخال القياسي)")
    dec.set_defaults(func=_cmd_decrypt)

    status = sub.add_parser("status", help="عرض حالة النظام")
    status.add_argument("--node", required=True, type=Path)
    status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (NodeError, ValueError, OSError) as error:
        print(f"خطأ: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
