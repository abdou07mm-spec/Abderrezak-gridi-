#!/usr/bin/env python3
"""
النظام رقم 2 — النظام المتصل (Online Node)
==========================================

هو التطبيق الذي يرسل ويستقبل عبر الإنترنت. لا يملك البذرة السرية أبدًا.

عند كل تغيير (في موعد سري وغير منتظم):
  1. يستلم "مفتاح الخزنة" للفترة من النظام 1 (في اتجاه واحد).
  2. يولّد سرًا عشوائيًا جديدًا (X25519) لا يغادر الجهاز، ويرسل نصفه العام
     إلى الطرف الآخر داخل "مصافحة" مشفرة بمفاتيح مشتقة من مفتاح الخزنة.
  3. عند وصول مصافحة الطرف الآخر يحسب الطرفان السرّ المشترك نفسه
     (Diffie-Hellman) دون أن يمر عبر الإنترنت، ثم:
        مفتاح الفترة = مزج(مفتاح الخزنة + سرّ Diffie-Hellman)
     ويُتلف السرّ الخاص ومفتاح الخزنة ومفتاح الفترة نفسه فورًا، ولا يبقى
     إلا بداية "سلسلة الرسائل".

مفتاح جديد لكل رسالة (سلسلة الرسائل):
     سلسلة ──► سلسلة ──► سلسلة ──► ...
       │         │         │
     رسالة 0   رسالة 1   رسالة 2     (لكل اتجاه سلسلته الخاصة)
  - مفتاح كل رسالة يُتلف لحظة إرسالها/قراءتها، فمن يسرق الجهاز لاحقًا
    لا يستطيع قراءة أي رسالة سابقة.
  - الرسالة المكررة (إعادة إرسال رسالة مسجّلة) تُرفض لأن مفتاحها لم يعد موجودًا.

طبقتا تشفير بخوارزميتين مختلفتين، لكل منهما مفتاحها:
     النص ──► AES-256-GCM ──► ChaCha20-Poly1305 ──► الإنترنت
  لو انكسرت إحدى الخوارزميتين يومًا، تبقى الأخرى تحمي الرسالة.

إخفاء الآثار:
  كل حزمة طولها ثابت (1024 بايت) ومشفّرة بالكامل، بما فيها رأسها. المراقب
  لا يستطيع أن يعرف: هل هي مصافحة أم رسالة؟ ما طول النص؟ ما رقم الرسالة
  أو الفترة؟ من المرسل؟

شكل الحزمة:
  [رقم عشوائي 12][الرأس المشفر 27][الجسم المشفر بطبقتين 985]
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import (
    FORMAT_VERSION,
    ROLES,
    fingerprint,
    one_way,
    parse_time,
    read_json,
    secure_random,
    stamp,
    to_utc,
    use_utf8_console,
    utc_now,
    wipe_file,
    write_private_json,
)

KEY_BYTES = 32
DH_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16

PACKET_BYTES = 1024                                            # طول كل حزمة (ثابت)
HEADER = struct.Struct(">cBIcI")                               # النوع، الإصدار، الفترة، الدور، رقم الرسالة
SEALED_HEADER_BYTES = HEADER.size + TAG_BYTES
BODY_OFFSET = NONCE_BYTES + SEALED_HEADER_BYTES
BODY_PLAIN_BYTES = PACKET_BYTES - BODY_OFFSET - 2 * TAG_BYTES  # طبقتان = ختمان
LENGTH = struct.Struct(">H")
MAX_TEXT_BYTES = BODY_PLAIN_BYTES - LENGTH.size                # 951 بايت

# الرسائل المتأخرة: تُقبل رسالة من فترة انتهت إذا وصلت خلال هذه المدة.
# (مفاتيح الرسائل المقروءة تُتلف فورًا، فهذه المهلة لا تكشف أي رسالة سبقت قراءتها.)
GRACE_PERIOD = timedelta(hours=12)
# أقصى عدد من الرسائل التي يمكن أن تصل بغير ترتيبها (حماية من الإغراق).
MAX_SKIP = 1000


class NodeError(Exception):
    """خطأ في النظام المتصل."""


class KeyUnavailable(NodeError):
    """لا يوجد مفتاح جاهز للوقت المطلوب."""


class HandshakePending(KeyUnavailable):
    """مفتاح الخزنة موجود، لكن مصافحة الطرف الآخر لم تصل بعد."""


class MessageRejected(NodeError):
    """الحزمة تالفة أو معدّلة أو مزوّرة أو ليست لنا."""


class ReplayRejected(MessageRejected):
    """رسالة قُرئت من قبل: مفتاحها أُتلف."""


# ---------------------------------------------------------------------- #
# المفاتيح المشتقة
# ---------------------------------------------------------------------- #
def chain_message_key(chain: bytes) -> bytes:
    """مفتاح الرسالة الحالية في السلسلة."""
    return one_way(chain, b"msg:key")


def chain_next(chain: bytes) -> bytes:
    """الخطوة التالية في سلسلة الرسائل (لا رجوع)."""
    return one_way(chain, b"msg:next")


def layer_keys(key: bytes) -> tuple[bytes, bytes]:
    """مفتاحان مستقلان للطبقتين: (AES، ChaCha20)."""
    return one_way(key, b"layer:aes"), one_way(key, b"layer:chacha")


def _handshake_keys(hs_key: bytes) -> tuple[bytes, bytes]:
    """(مفتاح رأس المصافحة، مفتاح جسمها)، مشتقان من مفتاح الخزنة."""
    return one_way(hs_key, b"hs:header"), one_way(hs_key, b"hs:body")


@dataclass(frozen=True)
class EpochSecrets:
    header_key: bytes
    chains: dict[str, bytes]    # بداية سلسلة الرسائل لكل دور
    fingerprint: str


def derive_epoch(vault_key: bytes, epoch: int, shared: bytes,
                 pub_a: bytes, pub_b: bytes) -> EpochSecrets:
    """
    مفتاح الفترة = مزج (مفتاح الخزنة + سرّ Diffie-Hellman + النصفين العامين).
    من يملك مفتاح الخزنة والنصفين العامين (وهما معلنان) لا يزال ينقصه السرّ
    المشترك shared، ولا يُحسب إلا بمفتاح خاص لم يغادر جهاز صاحبه.
    مفتاح الفترة نفسه لا يُحفظ: نشتق منه ما نحتاجه ثم يُنسى.
    """
    epoch_key = HKDF(
        algorithm=SHA256(), length=KEY_BYTES,
        salt=one_way(vault_key, b"epoch-mix"),
        info=b"epoch-key|" + struct.pack(">I", epoch) + pub_a + pub_b,
    ).derive(shared)
    return EpochSecrets(
        header_key=one_way(epoch_key, b"header"),
        chains={role: one_way(epoch_key, b"chain:" + role.encode()) for role in ROLES},
        fingerprint=fingerprint(epoch_key, "epoch-key"),
    )


# ---------------------------------------------------------------------- #
# ختم الحزم وفتحها
# ---------------------------------------------------------------------- #
def _seal(header_key: bytes, body_key: bytes, header: bytes, data: bytes) -> str:
    if len(data) > MAX_TEXT_BYTES:
        raise NodeError(f"النص أطول من الحد المسموح ({MAX_TEXT_BYTES} بايت)؛ قسّمه إلى عدة رسائل")
    nonce = secure_random(NONCE_BYTES)
    body = LENGTH.pack(len(data)) + data
    body += bytes(BODY_PLAIN_BYTES - len(body))              # حشو حتى الطول الثابت
    k_aes, k_chacha = layer_keys(body_key)
    inner = AESGCM(k_aes).encrypt(nonce, body, header)                   # الطبقة 1
    outer = ChaCha20Poly1305(k_chacha).encrypt(nonce, inner, header)     # الطبقة 2
    sealed_header = AESGCM(header_key).encrypt(nonce, header, None)      # إخفاء الرأس
    return base64.urlsafe_b64encode(nonce + sealed_header + outer).decode("ascii")


def decode_packet(packet: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(packet.strip().encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise MessageRejected("النص ليس حزمة صالحة") from None
    if len(raw) != PACKET_BYTES:
        raise MessageRejected("طول الحزمة غير صحيح (مبتورة أو ليست من هذا النظام)")
    return raw


def _open_header(header_key: bytes, raw: bytes) -> bytes | None:
    try:
        return AESGCM(header_key).decrypt(
            raw[:NONCE_BYTES], raw[NONCE_BYTES:BODY_OFFSET], None)
    except InvalidTag:
        return None


def read_handshake(vault_key: bytes, packet: str) -> tuple[int, str, bytes]:
    """
    يفتح مصافحة بمفتاح الخزنة: (رقم الفترة، الدور، النصف العام).
    النصف العام ليس سرًا؛ وجوده داخل حزمة مشفرة هدفه فقط إخفاء الآثار.
    """
    raw = decode_packet(packet)
    header_key, body_key = _handshake_keys(one_way(vault_key, b"handshake"))
    header = _open_header(header_key, raw)
    if header is None:
        raise MessageRejected("ليست مصافحة صادرة بمفتاح الخزنة هذا")
    kind, _, epoch, role, _ = HEADER.unpack(header)
    if kind != b"H":
        raise MessageRejected("ليست مصافحة")
    return epoch, role.decode("ascii", "replace"), _open_body(body_key, raw, header)


def _open_body(body_key: bytes, raw: bytes, header: bytes) -> bytes:
    nonce = raw[:NONCE_BYTES]
    k_aes, k_chacha = layer_keys(body_key)
    try:
        inner = ChaCha20Poly1305(k_chacha).decrypt(nonce, raw[BODY_OFFSET:], header)
        body = AESGCM(k_aes).decrypt(nonce, inner, header)
    except InvalidTag:
        raise MessageRejected(
            "فشل التحقق: الحزمة مُعدّلة أو مزوّرة — رُفضت.") from None
    (length,) = LENGTH.unpack(body[:LENGTH.size])
    if length > MAX_TEXT_BYTES:
        raise MessageRejected("محتوى الحزمة غير متّسق — رُفضت.")
    return body[LENGTH.size:LENGTH.size + length]


# ---------------------------------------------------------------------- #
# حالة كل فترة
# ---------------------------------------------------------------------- #
def _hex(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def _unhex(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


@dataclass
class EpochState:
    valid_from: datetime
    valid_until: datetime
    hs_key: bytes                       # مفتاح المصافحات (مشتق باتجاه واحد من مفتاح الخزنة)
    handshake: str                      # حزمة مصافحتي، جاهزة للإرسال أو لإعادة الإرسال
    my_public: bytes
    vault_key: bytes | None = None      # يُتلف بعد اكتمال المصافحة
    my_private: bytes | None = None     # يُتلف بعد اكتمال المصافحة
    peer_public: bytes | None = None
    key_fp: str | None = None           # بصمة مفتاح الفترة (للمقارنة بالهاتف)
    header_key: bytes | None = None     # مفتاح إخفاء رؤوس الرسائل
    send_chain: bytes | None = None     # سلسلة رسائلي الصادرة
    send_counter: int = 0
    recv_chain: bytes | None = None     # سلسلة رسائل الطرف الآخر
    recv_counter: int = 0
    skipped: dict[int, bytes] = field(default_factory=dict)  # رسائل لم تصل بعد (ترتيب مختلف)

    @property
    def ready(self) -> bool:
        return self.header_key is not None

    def to_dict(self) -> dict:
        return {
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "hs_key": _hex(self.hs_key),
            "handshake": self.handshake,
            "my_public": _hex(self.my_public),
            "vault_key": _hex(self.vault_key),
            "my_private": _hex(self.my_private),
            "peer_public": _hex(self.peer_public),
            "key_fp": self.key_fp,
            "header_key": _hex(self.header_key),
            "send_chain": _hex(self.send_chain),
            "send_counter": self.send_counter,
            "recv_chain": _hex(self.recv_chain),
            "recv_counter": self.recv_counter,
            "skipped": {str(i): k.hex() for i, k in sorted(self.skipped.items())},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EpochState":
        return cls(
            valid_from=parse_time(data["valid_from"]),
            valid_until=parse_time(data["valid_until"]),
            hs_key=bytes.fromhex(data["hs_key"]),
            handshake=data["handshake"],
            my_public=bytes.fromhex(data["my_public"]),
            vault_key=_unhex(data.get("vault_key")),
            my_private=_unhex(data.get("my_private")),
            peer_public=_unhex(data.get("peer_public")),
            key_fp=data.get("key_fp"),
            header_key=_unhex(data.get("header_key")),
            send_chain=_unhex(data.get("send_chain")),
            send_counter=int(data.get("send_counter", 0)),
            recv_chain=_unhex(data.get("recv_chain")),
            recv_counter=int(data.get("recv_counter", 0)),
            skipped={int(i): bytes.fromhex(k) for i, k in data.get("skipped", {}).items()},
        )


@dataclass(frozen=True)
class Received:
    """نتيجة استقبال حزمة."""
    kind: str                 # "handshake" أو "message"
    epoch: int
    text: str | None = None
    duplicate: bool = False


class OnlineNode:
    """النظام المتصل."""

    def __init__(self, path: Path, pair_id: str | None = None, role: str | None = None,
                 epochs: dict[int, EpochState] | None = None):
        self.path = Path(path)
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
        return cls(path, data["pair_id"], data["role"],
                   {int(e): EpochState.from_dict(s) for e, s in data["epochs"].items()})

    def save(self) -> None:
        write_private_json(self.path, {
            "format": "online-node",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "role": self.role,
            "epochs": {str(e): s.to_dict() for e, s in sorted(self.epochs.items())},
        })

    # ------------------------------------------------------------------ #
    # أدوات داخلية
    # ------------------------------------------------------------------ #
    @staticmethod
    def _now(now: datetime | None) -> datetime:
        return utc_now() if now is None else to_utc(now)

    def _purge(self, now: datetime, save: bool = True) -> None:
        """يُتلف ما انتهت صلاحيته."""
        changed = False
        for epoch, state in list(self.epochs.items()):
            if now >= state.valid_until + GRACE_PERIOD:
                del self.epochs[epoch]                 # الفترة انتهت مع مهلتها: نتلف كل شيء
                changed = True
            elif now >= state.valid_until and state.send_chain is not None:
                state.send_chain = None                # الفترة انتهت: لا إرسال بها بعد الآن
                changed = True
        if changed and save:
            self.save()

    def _current(self, now: datetime) -> tuple[int, EpochState]:
        for epoch, state in self.epochs.items():
            if state.valid_from <= now < state.valid_until:
                return epoch, state
        raise KeyUnavailable(
            "لا يوجد مفتاح للوقت الحالي: حان موعد تغيير جديد (أو لم يُستورد أي مفتاح بعد). "
            "استورد مفتاح الخزنة أولًا — النظام يرفض الاستمرار بمفتاح قديم.")

    def _check_header(self, header: bytes, kind: bytes, epoch: int) -> int:
        h_kind, version, h_epoch, role_raw, counter = HEADER.unpack(header)
        if h_kind != kind or version != FORMAT_VERSION or h_epoch != epoch:
            raise MessageRejected("رأس الحزمة غير متّسق — رُفضت")
        role = role_raw.decode("ascii", "replace")
        if role not in ROLES:
            raise MessageRejected("دور غير معروف في الحزمة — رُفضت")
        if role == self.role:
            raise MessageRejected("هذه حزمة صادرة منك أنت أُعيدت إليك — رُفضت")
        return counter

    # ------------------------------------------------------------------ #
    # 1) استلام مفتاح الخزنة + توليد السرّ العشوائي
    # ------------------------------------------------------------------ #
    def import_bundle(self, bundle: dict, now: datetime | None = None) -> int:
        if bundle.get("format") != "key-bundle" or bundle.get("version") != FORMAT_VERSION:
            raise NodeError("هذه ليست حزمة مفتاح صالحة (أو أنها من إصدار سابق)")
        role = bundle.get("role")
        if role not in ROLES:
            raise NodeError("دور غير معروف في حزمة المفتاح")
        if self.pair_id is None:
            self.pair_id, self.role = bundle["pair_id"], role
        elif bundle["pair_id"] != self.pair_id:
            raise NodeError("هذا المفتاح صادر من خزنة أخرى غير مقترنة بهذا النظام — رُفض")
        elif role != self.role:
            raise NodeError("هذا المفتاح صادر من خزنة الطرف الآخر، لا من خزنتك — رُفض")

        vault_key = bytes.fromhex(bundle["key"])
        if len(vault_key) != KEY_BYTES:
            raise NodeError("طول المفتاح غير صحيح")
        epoch = int(bundle["epoch"])
        valid_from, valid_until = parse_time(bundle["valid_from"]), parse_time(bundle["valid_until"])
        if valid_until <= valid_from:
            raise NodeError("مدة صلاحية المفتاح غير صحيحة")
        now = self._now(now)
        self._purge(now, save=False)
        if now >= valid_until + GRACE_PERIOD:
            raise NodeError(f"مفتاح الفترة {epoch} منتهي الصلاحية")

        state = self.epochs.get(epoch)
        if state is None:
            private = X25519PrivateKey.from_private_bytes(secure_random(DH_BYTES))
            public = private.public_key().public_bytes_raw()
            hs_key = one_way(vault_key, b"handshake")
            header = HEADER.pack(b"H", FORMAT_VERSION, epoch, role.encode("ascii"), 0)
            self.epochs[epoch] = EpochState(
                valid_from=valid_from, valid_until=valid_until, hs_key=hs_key,
                handshake=_seal(*_handshake_keys(hs_key), header, public),
                my_public=public, vault_key=vault_key,
                my_private=private.private_bytes_raw())
        elif not state.ready and not hmac.compare_digest(state.vault_key, vault_key):
            raise NodeError("مفتاح خزنة مختلف لفترة استُورد مفتاحها سابقًا — رُفض")
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
    # 2) الإرسال
    # ------------------------------------------------------------------ #
    def my_handshake(self, now: datetime | None = None) -> str:
        """مصافحتي للفترة الحالية (لإرسالها أو إعادة إرسالها للطرف الآخر)."""
        return self._current(self._now(now))[1].handshake

    def send(self, text: str, now: datetime | None = None) -> str:
        now = self._now(now)
        self._purge(now, save=False)
        epoch, state = self._current(now)
        if not state.ready:
            raise HandshakePending(
                "مفتاح هذه الفترة غير مكتمل: بانتظار مصافحة الطرف الآخر. "
                "تأكد أيضًا أنه استلم مصافحتك.")
        data = text.encode("utf-8")
        if len(data) > MAX_TEXT_BYTES:
            raise NodeError(f"النص أطول من الحد المسموح ({MAX_TEXT_BYTES} بايت)؛ قسّمه إلى عدة رسائل")
        message_key = chain_message_key(state.send_chain)
        counter = state.send_counter
        state.send_chain = chain_next(state.send_chain)   # المفتاح القديم لم يعد قابلًا للحساب
        state.send_counter += 1
        self.save()   # نحفظ التقدّم قبل الإرسال: لا يُستعمل أي مفتاح مرتين أبدًا
        header = HEADER.pack(b"M", FORMAT_VERSION, epoch, self.role.encode("ascii"), counter)
        return _seal(state.header_key, message_key, header, data)

    # ------------------------------------------------------------------ #
    # 3) الاستقبال (مصافحة أو رسالة، لا فرق في الشكل)
    # ------------------------------------------------------------------ #
    def receive(self, packet: str, now: datetime | None = None) -> Received:
        raw = decode_packet(packet)
        if self.role is None:
            raise KeyUnavailable("هذا النظام لم يستلم أي مفتاح من الخزنة بعد")
        self._purge(self._now(now))
        for epoch, state in sorted(self.epochs.items(), reverse=True):
            if state.ready:
                header = _open_header(state.header_key, raw)
                if header is not None:
                    return self._receive_message(epoch, state, header, raw)
            header = _open_header(_handshake_keys(state.hs_key)[0], raw)
            if header is not None:
                return self._receive_handshake(epoch, state, header, raw)
        raise MessageRejected(
            "تعذّر فتح الحزمة بأي مفتاح متاح: إما أنها مزوّرة أو مُعدّلة، أو ليست من "
            "الطرف المقترن، أو أنها لفترة لم يُستورد مفتاحها بعد، أو قديمة أُتلفت مفاتيحها.")

    def _receive_handshake(self, epoch: int, state: EpochState,
                           header: bytes, raw: bytes) -> Received:
        self._check_header(header, b"H", epoch)
        public = _open_body(_handshake_keys(state.hs_key)[1], raw, header)
        if len(public) != DH_BYTES:
            raise MessageRejected("مصافحة غير صالحة — رُفضت")
        if state.ready:
            if hmac.compare_digest(public, state.peer_public):
                return Received("handshake", epoch, duplicate=True)
            raise MessageRejected("مصافحة مختلفة لفترة اكتملت مصافحتها — رُفضت")
        try:
            shared = X25519PrivateKey.from_private_bytes(state.my_private).exchange(
                X25519PublicKey.from_public_bytes(public))
        except ValueError:
            raise MessageRejected("النصف العام في المصافحة غير صالح — رُفضت") from None

        pub_a, pub_b = ((state.my_public, public) if self.role == "A"
                        else (public, state.my_public))
        secrets = derive_epoch(state.vault_key, epoch, shared, pub_a, pub_b)
        peer_role = ROLES[1] if self.role == ROLES[0] else ROLES[0]
        state.header_key = secrets.header_key
        state.send_chain, state.recv_chain = secrets.chains[self.role], secrets.chains[peer_role]
        state.key_fp = secrets.fingerprint
        state.peer_public = public
        state.vault_key = None       # نُتلف كل ما لم نعد نحتاجه.
        state.my_private = None
        self.save()
        return Received("handshake", epoch)

    def _receive_message(self, epoch: int, state: EpochState,
                         header: bytes, raw: bytes) -> Received:
        counter = self._check_header(header, b"M", epoch)
        new_skipped: dict[int, bytes] = {}
        if counter < state.recv_counter:
            message_key = state.skipped.get(counter)
            if message_key is None:
                raise ReplayRejected(
                    "هذه الرسالة قُرئت من قبل، أو أنها إعادة إرسال لرسالة مسجّلة: "
                    "مفتاحها أُتلف لحظة قراءتها — رُفضت.")
        else:
            if counter - state.recv_counter > MAX_SKIP:
                raise MessageRejected("رقم الرسالة بعيد جدًا عن المتوقع — رُفضت")
            chain = state.recv_chain
            for index in range(state.recv_counter, counter):
                new_skipped[index] = chain_message_key(chain)
                chain = chain_next(chain)
            message_key = chain_message_key(chain)
        data = _open_body(message_key, raw, header)       # لا نغيّر الحالة إلا بعد نجاح التحقق
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise MessageRejected("محتوى الرسالة غير صالح — رُفضت") from None

        if counter < state.recv_counter:
            del state.skipped[counter]
        else:
            state.recv_chain = chain_next(chain)
            state.recv_counter = counter + 1
            state.skipped.update(new_skipped)
            while len(state.skipped) > MAX_SKIP:
                del state.skipped[min(state.skipped)]
        self.save()
        return Received("message", epoch, text=text)

    # ------------------------------------------------------------------ #
    # معلومات
    # ------------------------------------------------------------------ #
    def key_fingerprint(self, now: datetime | None = None) -> str | None:
        """
        بصمة مفتاح الفترة الحالية. إذا قرأها الطرفان لبعضهما بالهاتف وتطابقت،
        فلا يوجد أي انتحال في المنتصف.
        """
        try:
            return self._current(self._now(now))[1].key_fp
        except KeyUnavailable:
            return None


# ---------------------------------------------------------------------- #
# واجهة سطر الأوامر
# ---------------------------------------------------------------------- #
def _read_arg(value: str | None) -> str:
    return value if value is not None else sys.stdin.read()


def _cmd_import(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    epochs = node.import_from_folder(args.source)
    print(f"تم استيراد مفتاح الخزنة للفترة {', '.join(map(str, epochs))} ومسحه من مجلد النقل.")
    print("وتم توليد سرّ عشوائي جديد. أرسل هذه المصافحة إلى الطرف الآخر")
    print("(شكلها مثل أي رسالة مشفرة، ونشرها آمن):")
    print()
    print(node.epochs[epochs[-1]].handshake)


def _cmd_handshake(args: argparse.Namespace) -> None:
    print(OnlineNode.open(args.node).my_handshake())


def _cmd_send(args: argparse.Namespace) -> None:
    print(OnlineNode.open(args.node).send(_read_arg(args.text)))


def _cmd_receive(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    result = node.receive(_read_arg(args.packet))
    if result.kind == "message":
        print(result.text)
    elif result.duplicate:
        print("مصافحة مكررة وصلت من قبل؛ لا شيء جديد.")
    else:
        print(f"اكتملت المصافحة. بصمة مفتاح الفترة: {node.epochs[result.epoch].key_fp}")
        print("(يمكنكما مقارنتها بالهاتف لكشف أي انتحال)")


def _cmd_status(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    if node.role is None:
        print("النظام غير مقترن بعد (لم يُستورد أي مفتاح).")
        return
    print(f"بصمة الزوج: {node.pair_id}   الدور: {node.role}")
    now = utc_now()
    for epoch, state in sorted(node.epochs.items()):
        current = " ← الحالية" if state.valid_from <= now < state.valid_until else ""
        status = (f"جاهزة، بصمة المفتاح {state.key_fp}، أُرسلت {state.send_counter} "
                  f"واستُقبلت {state.recv_counter}" if state.ready
                  else "بانتظار مصافحة الطرف الآخر")
        print(f"  الفترة {epoch} [{stamp(state.valid_from)} → {stamp(state.valid_until)}]: "
              f"{status}{current}")


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="النظام 2: النظام المتصل")
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="استيراد مفتاح الخزنة وتوليد المصافحة")
    imp.add_argument("--node", required=True, type=Path)
    imp.add_argument("--from", dest="source", required=True, type=Path)
    imp.set_defaults(func=_cmd_import)

    hs = sub.add_parser("handshake", help="إعادة عرض مصافحتي للفترة الحالية")
    hs.add_argument("--node", required=True, type=Path)
    hs.set_defaults(func=_cmd_handshake)

    send = sub.add_parser("send", help="تشفير رسالة")
    send.add_argument("--node", required=True, type=Path)
    send.add_argument("text", nargs="?", help="النص (أو يُقرأ من الإدخال القياسي)")
    send.set_defaults(func=_cmd_send)

    receive = sub.add_parser("receive", help="استقبال حزمة (مصافحة أو رسالة)")
    receive.add_argument("--node", required=True, type=Path)
    receive.add_argument("packet", nargs="?", help="الحزمة (أو تُقرأ من الإدخال القياسي)")
    receive.set_defaults(func=_cmd_receive)

    status = sub.add_parser("status", help="عرض حالة النظام")
    status.add_argument("--node", required=True, type=Path)
    status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as error:  # نعرض رسالة واضحة بدل تفاصيل تقنية
        print(f"خطأ: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
