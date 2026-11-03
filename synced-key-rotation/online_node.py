#!/usr/bin/env python3
"""
النظام رقم 2 — النظام المتصل (Online Node)
==========================================

هو التطبيق الذي يرسل ويستقبل الرسائل عبر الإنترنت.

- لا يملك البذرة السرية أبدًا؛ يملك فقط مفتاح اليوم (ومفتاح الأمس لفترة سماح).
- يستلم مفتاح اليوم من النظام 1 عند موعد التغيير، ويتلف المفاتيح القديمة.
- يشفّر بخوارزمية AES-256-GCM (المعيار العالمي)، التي:
    * تُخفي محتوى الرسالة،
    * وتكشف أي تعديل عليها ولو حرفًا واحدًا (فتُرفض الرسالة).

شكل الرسالة المشفرة:
    [الإصدار 1 بايت][رقم الحقبة 4 بايت][رقم عشوائي 12 بايت][النص المشفر + ختم التحقق]

رقم الحقبة مكتوب بشكل ظاهر حتى يعرف المستقبل أي مفتاح يستعمل؛
هذا لا يكشف شيئًا عن المفتاح نفسه، وأي تلاعب به يُكتشف.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import os
import struct
import sys
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import (
    FORMAT_VERSION,
    Schedule,
    read_json,
    stamp,
    to_utc,
    use_utf8_console,
    utc_now,
    wipe_file,
    write_private_json,
)

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER = struct.Struct(">BI")  # الإصدار + رقم الحقبة

# كم حقبة سابقة نحتفظ بمفتاحها؟ 1 = مفتاح الأمس فقط، لكي لا تضيع رسالة
# أُرسلت 07:59 ووصلت 08:01. كلما صغر الرقم صغر الضرر عند الاختراق.
KEEP_PREVIOUS_EPOCHS = 1


class NodeError(Exception):
    """خطأ في النظام المتصل."""


class KeyUnavailable(NodeError):
    """لا يوجد مفتاح للحقبة المطلوبة."""


class MessageRejected(NodeError):
    """الرسالة تالفة أو معدّلة أو مزوّرة."""


def message_epoch(token: str) -> int:
    """يقرأ رقم الحقبة المكتوب في رأس الرسالة (دون فك تشفيرها)."""
    return HEADER.unpack(_decode(token)[:HEADER.size])[1]


def _decode(token: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(token.strip().encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise MessageRejected("الرسالة ليست بالصيغة الصحيحة") from None
    if len(raw) < HEADER.size + NONCE_BYTES + TAG_BYTES:
        raise MessageRejected("الرسالة قصيرة جدًا أو مبتورة")
    return raw


class OnlineNode:
    """النظام المتصل: يحفظ مفاتيح الحقبة الحالية والسابقة فقط."""

    def __init__(self, path: Path, schedule: Schedule | None = None,
                 pair_id: str | None = None, keys: dict[int, bytes] | None = None):
        self.path = Path(path)
        self.schedule = schedule
        self.pair_id = pair_id
        self.keys: dict[int, bytes] = dict(keys or {})

    @classmethod
    def open(cls, path: Path) -> "OnlineNode":
        """يفتح ملف النظام إن وُجد، وإلا ينشئ نظامًا جديدًا فارغًا."""
        path = Path(path)
        if not path.exists():
            return cls(path)
        data = read_json(path)
        if data.get("format") != "online-node" or data.get("version") != FORMAT_VERSION:
            raise NodeError(f"هذا الملف ليس ملف نظام متصل صالح: {path}")
        return cls(
            path,
            Schedule.from_dict(data["schedule"]),
            data["pair_id"],
            {int(epoch): bytes.fromhex(key) for epoch, key in data["keys"].items()},
        )

    def save(self) -> None:
        write_private_json(self.path, {
            "format": "online-node",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "schedule": self.schedule.to_dict() if self.schedule else None,
            "keys": {str(epoch): key.hex() for epoch, key in sorted(self.keys.items())},
        })

    # ------------------------------------------------------------------ #
    # استلام المفاتيح من النظام 1
    # ------------------------------------------------------------------ #
    def import_bundle(self, bundle: dict, now: datetime | None = None) -> int:
        if bundle.get("format") != "key-bundle" or bundle.get("version") != FORMAT_VERSION:
            raise NodeError("هذه ليست حزمة مفتاح صالحة")
        if self.pair_id is None:
            # أول مفتاح: نتعرف على الخزنة المقترنة وجدولها الزمني
            self.pair_id = bundle["pair_id"]
            self.schedule = Schedule.from_dict(bundle["schedule"])
        elif bundle["pair_id"] != self.pair_id:
            raise NodeError("هذا المفتاح صادر من خزنة أخرى غير مقترنة بهذا النظام — رُفض")

        key = bytes.fromhex(bundle["key"])
        if len(key) != KEY_BYTES:
            raise NodeError("طول المفتاح غير صحيح")
        epoch = int(bundle["epoch"])
        self.keys[epoch] = key
        self._purge(now, save=False)
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

    def _require_paired(self) -> Schedule:
        if self.schedule is None:
            raise KeyUnavailable("هذا النظام لم يستلم أي مفتاح من الخزنة بعد")
        return self.schedule

    def _purge(self, now: datetime | None, save: bool = True) -> int:
        """يُتلف كل مفتاح أقدم من نافذة السماح. يعيد رقم الحقبة الحالية."""
        schedule = self._require_paired()
        current = schedule.epoch_at(utc_now() if now is None else to_utc(now))
        expired = [e for e in self.keys if e < current - KEEP_PREVIOUS_EPOCHS]
        for epoch in expired:
            del self.keys[epoch]
        if expired and save:
            self.save()
        return current

    # ------------------------------------------------------------------ #
    # التشفير وفك التشفير
    # ------------------------------------------------------------------ #
    def encrypt(self, text: str, now: datetime | None = None) -> str:
        epoch = self._purge(now)
        key = self.keys.get(epoch)
        if key is None:
            raise KeyUnavailable(
                f"مفتاح الحقبة الحالية ({epoch}) غير موجود. "
                "يجب استيراده من الخزنة غير المتصلة أولًا — "
                "النظام يرفض الاستمرار بمفتاح قديم."
            )
        header = HEADER.pack(FORMAT_VERSION, epoch)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), header)
        return base64.urlsafe_b64encode(header + nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str, now: datetime | None = None) -> str:
        raw = _decode(token)
        version, epoch = HEADER.unpack(raw[:HEADER.size])
        if version != FORMAT_VERSION:
            raise MessageRejected(f"إصدار غير معروف: {version}")
        self._purge(now)
        key = self.keys.get(epoch)
        if key is None:
            raise KeyUnavailable(
                f"لا يوجد مفتاح للحقبة {epoch}: "
                "إما أنها قديمة وأُتلف مفتاحها، أو أن مفتاحها لم يُستورد بعد."
            )
        header = raw[:HEADER.size]
        nonce = raw[HEADER.size:HEADER.size + NONCE_BYTES]
        try:
            plaintext = AESGCM(key).decrypt(nonce, raw[HEADER.size + NONCE_BYTES:], header)
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
    print(f"تم استيراد مفتاح الحقبة {', '.join(map(str, epochs))} ومسحه من مجلد النقل.")
    print(f"المفاتيح الموجودة الآن: الحقب {sorted(node.keys)}")


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
    current = node.schedule.epoch_at(utc_now())
    print(f"بصمة الزوج:   {node.pair_id}")
    print(f"الحقبة الآن:  {current} (التغيير القادم: "
          f"{stamp(node.schedule.start_of(current + 1))})")
    print(f"المفاتيح:     الحقب {sorted(node.keys)}")


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="النظام 2: النظام المتصل")
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="استيراد مفتاح اليوم من مجلد النقل")
    imp.add_argument("--node", required=True, type=Path)
    imp.add_argument("--from", dest="source", required=True, type=Path)
    imp.set_defaults(func=_cmd_import)

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
