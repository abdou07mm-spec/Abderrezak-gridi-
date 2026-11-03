#!/usr/bin/env python3
"""
النظام رقم 2 — النظام المتصل (Online Node)
==========================================

هو التطبيق الذي يرسل ويستقبل عبر الإنترنت. لا يملك البذرة السرية أبدًا.

عند كل تغيير (في موعد سري وغير منتظم) — "المصافحة الهجينة":
  1. يستلم "مفتاح الخزنة" للفترة من النظام 1 (في اتجاه واحد).
  2. يولّد سرًا عشوائيًا (X25519)، والطرف B يولّد أيضًا "قفلًا" مقاومًا
     للحاسوب الكمّي (ML-KEM-1024) ويرسله مفتوحًا.
  3. الطرف A يضع سرًا عشوائيًا في "صندوق" يقفله بقفل B ويرسله.
  4. مفتاح الفترة = مزج (مفتاح الخزنة + سرّ X25519 + سرّ ML-KEM):
     ثلاثة أقفال، يجب كسرها كلها. ثم يُتلف مفتاح الخزنة والأسرار الخاصة.

داخل الفترة — "السقّاطة المزدوجة الهجينة" (Double Ratchet كما في Signal،
مع ML-KEM في كل خطوة كما في Apple PQ3 و Signal SPQR):
  - كل حزمة تحمل نصف المرسل الحالي (X25519)، وقفله الحالي (ML-KEM)،
    وصندوقًا مقفلًا بآخر قفل وصله من الطرف الآخر.
  - كلما وصل نصف جديد: سرّ X25519 جديد + سرّ ML-KEM جديد يُمزجان في الجذر.
  - بين الخطوات: مفتاح لكل رسالة يُتلف لحظة إرسالها أو قراءتها.
  النتيجة: الهاتف المسروق يفقد قيمته بعد تبادل أو تبادلين، حتى لو امتلك
  السارق حاسوبًا كمّيًا يكسر X25519، لأن قفل ML-KEM الجديد وُلد بعد السرقة.

طبقتا تشفير بخوارزميتين مختلفتين:
     الحمولة ──► AES-256-GCM ──► ChaCha20-Poly1305 ──► الإنترنت

إخفاء الآثار:
  كل حزمة طولها ثابت (6144 بايت) ومشفرة بالكامل، بما فيها رأسها.
  الحزمة الوهمية (bus.py) لا تختلف عن الحقيقية، وعلامة "وهمية" مخفية داخل
  الجزء المشفر بمفتاح الرسالة الذي يُتلف بعد القراءة.

شكل الحزمة:
  [رقم عشوائي 12][الرأس المشفر 3199: الأنصاف والقفل والصندوق][الجسم بطبقتين 2933]
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import hmac
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
)
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
KEM_SEED_BYTES = 64          # مفتاح ML-KEM الخاص يُبنى من 64 بايت عشوائية (مفحوصة)
KEM_PUBLIC_BYTES = 1568      # القفل المفتوح (ML-KEM-1024)
KEM_CT_BYTES = 1568          # الصندوق المقفل
NO_KEM_CT = bytes(KEM_CT_BYTES)
NO_KEM_PUBLIC = bytes(KEM_PUBLIC_BYTES)
NONCE_BYTES = 12
TAG_BYTES = 16

PACKET_BYTES = 6144                                            # طول كل حزمة (ثابت)
# الرأس: النوع، الإصدار، الفترة، الدور، النصف العام، طول السلسلة السابقة، رقم الرسالة،
#        الصندوق المقفل (ML-KEM)، القفل المفتوح الحالي (ML-KEM)
HEADER = struct.Struct(f">cBIc{DH_BYTES}sII{KEM_CT_BYTES}s{KEM_PUBLIC_BYTES}s")
SEALED_HEADER_BYTES = HEADER.size + TAG_BYTES
BODY_OFFSET = NONCE_BYTES + SEALED_HEADER_BYTES
BODY_PLAIN_BYTES = PACKET_BYTES - BODY_OFFSET - 2 * TAG_BYTES  # طبقتان = ختمان
LENGTH = struct.Struct(">H")
MAX_TEXT_BYTES = BODY_PLAIN_BYTES - 1 - LENGTH.size            # 2898 بايت لرسالة واحدة

# الرسائل المتأخرة: تُقبل رسالة من فترة انتهت إذا وصلت خلال هذه المدة.
GRACE_PERIOD = timedelta(hours=12)
MAX_SKIP = 1000              # أقصى عدد من الرسائل المفقودة/المتأخرة في سلسلة واحدة
MAX_STORED_SKIPPED = 2000    # أقصى عدد من مفاتيح الرسائل المنتظَرة المحفوظة
MAX_OLD_HALVES = 64          # أنصاف الطرف الآخر القديمة (لكشف إعادة الإرسال)


class NodeError(Exception):
    """خطأ في النظام المتصل."""


class KeyUnavailable(NodeError):
    """لا يوجد مفتاح جاهز للوقت المطلوب."""


class HandshakePending(KeyUnavailable):
    """مفتاح الخزنة موجود، لكن المصافحة لم تكتمل بعد."""


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


def kdf_root(root_key: bytes, dh_output: bytes, kem_output: bytes) -> tuple[bytes, bytes]:
    """خطوة السقّاطة: (مفتاح جذر جديد، بداية سلسلة جديدة) من سرّ X25519 + سرّ ML-KEM."""
    out = HKDF(algorithm=SHA256(), length=2 * KEY_BYTES, salt=root_key,
               info=b"ratchet:root:hybrid").derive(dh_output + kem_output)
    return out[:KEY_BYTES], out[KEY_BYTES:]


def new_key_pair() -> tuple[bytes, bytes]:
    """سرّ X25519 عشوائي جديد (مفحوص) ونصفه العام."""
    private = X25519PrivateKey.from_private_bytes(secure_random(DH_BYTES))
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def new_kem_pair() -> tuple[bytes, bytes]:
    """قفل ML-KEM جديد: (البذرة الخاصة 64 بايت مفحوصة، القفل المفتوح)."""
    seed = secure_random(KEM_SEED_BYTES)
    return seed, MLKEM1024PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()


def kem_lock(public: bytes) -> tuple[bytes, bytes]:
    """يضع سرًا عشوائيًا في صندوق مقفل بالقفل public: (السرّ، الصندوق)."""
    if hmac.compare_digest(public, NO_KEM_PUBLIC):
        raise MessageRejected("قفل ML-KEM مفقود — رُفض")
    try:
        return MLKEM1024PublicKey.from_public_bytes(public).encapsulate()
    except ValueError:
        raise MessageRejected("قفل ML-KEM غير صالح — رُفض") from None


def kem_unlock(private_seed: bytes, box: bytes) -> bytes:
    """يفتح الصندوق بالمفتاح الخاص. (صندوق معدّل يعطي سرًا خاطئًا، فتُرفض الحزمة لاحقًا.)"""
    return MLKEM1024PrivateKey.from_seed_bytes(private_seed).decapsulate(box)


def _dh(private: bytes, public: bytes) -> bytes:
    try:
        return X25519PrivateKey.from_private_bytes(private).exchange(
            X25519PublicKey.from_public_bytes(public))
    except ValueError:
        raise MessageRejected("نصف عام غير صالح — رُفض") from None


def _handshake_keys(hs_key: bytes) -> tuple[bytes, bytes]:
    """(مفتاح رأس المصافحة، مفتاح جسمها)، مشتقان من مفتاح الخزنة."""
    return one_way(hs_key, b"hs:header"), one_way(hs_key, b"hs:body")


@dataclass(frozen=True)
class EpochSecrets:
    header_key: bytes
    root_key: bytes
    initial_chain_b: bytes      # سلسلة أولى للطرف B كي يستطيع الإرسال قبل أن يصله شيء
    fingerprint: str


def derive_epoch(vault_key: bytes, epoch: int, dh_shared: bytes, kem_shared: bytes,
                 pub_a: bytes, pub_b: bytes, kem_public_b: bytes, kem_box: bytes) -> EpochSecrets:
    """
    مفتاح الفترة = مزج ثلاثة أقفال مستقلة:
      - مفتاح الخزنة (لم يمر عبر الإنترنت أبدًا)،
      - سرّ X25519 (يُكسر بحاسوب كمّي كبير)،
      - سرّ ML-KEM-1024 (لا يُعرف أي حاسوب، كمّي أو عادي، يكسره).
    مع ربط كل ما تبادله الطرفان (الأنصاف والقفل والصندوق).
    مفتاح الفترة نفسه لا يُحفظ: نشتق منه ما نحتاجه ثم يُنسى.
    """
    transcript = (struct.pack(">I", epoch) + pub_a + pub_b
                  + hashlib.sha256(kem_public_b).digest() + hashlib.sha256(kem_box).digest())
    epoch_key = HKDF(
        algorithm=SHA256(), length=KEY_BYTES,
        salt=one_way(vault_key, b"epoch-mix"),
        info=b"epoch-key:hybrid|" + transcript,
    ).derive(dh_shared + kem_shared)
    return EpochSecrets(
        header_key=one_way(epoch_key, b"header"),
        root_key=one_way(epoch_key, b"root"),
        initial_chain_b=one_way(epoch_key, b"chain:B:initial"),
        fingerprint=fingerprint(epoch_key, "epoch-key"),
    )


# ---------------------------------------------------------------------- #
# الحمولة: صفر رسالة (حزمة وهمية) أو رسالة أو عدة رسائل قصيرة معًا
# ---------------------------------------------------------------------- #
def encode_passengers(texts: list[str] | tuple[str, ...]) -> bytes:
    if len(texts) > 255:
        raise NodeError("عدد الرسائل في الحزمة كبير جدًا")
    payload = bytearray([len(texts)])
    for text in texts:
        data = text.encode("utf-8")
        payload += LENGTH.pack(len(data)) + data
    if len(payload) > BODY_PLAIN_BYTES:
        raise NodeError(f"النص أطول من الحد المسموح ({MAX_TEXT_BYTES} بايت)؛ قسّمه إلى عدة رسائل")
    return bytes(payload)


def passengers_fit(texts: list[str]) -> bool:
    return 1 + sum(LENGTH.size + len(t.encode("utf-8")) for t in texts) <= BODY_PLAIN_BYTES


def _decode_passengers(body: bytes) -> tuple[str, ...]:
    try:
        count, position, texts = body[0], 1, []
        for _ in range(count):
            (size,) = LENGTH.unpack(body[position:position + LENGTH.size])
            position += LENGTH.size
            if position + size > len(body):
                raise ValueError
            texts.append(body[position:position + size].decode("utf-8"))
            position += size
        return tuple(texts)
    except (ValueError, struct.error):
        raise MessageRejected("محتوى الحزمة غير متّسق — رُفضت.") from None


# ---------------------------------------------------------------------- #
# ختم الحزم وفتحها
# ---------------------------------------------------------------------- #
def _seal(header_key: bytes, body_key: bytes, header: bytes, payload: bytes) -> str:
    nonce = secure_random(NONCE_BYTES)
    body = payload + bytes(BODY_PLAIN_BYTES - len(payload))          # حشو حتى الطول الثابت
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


def random_filler() -> str:
    """حزمة من ضجيج عشوائي خالص، بالشكل نفسه تمامًا (تُستعمل حين لا يتوفر مفتاح)."""
    return base64.urlsafe_b64encode(secure_random(PACKET_BYTES)).decode("ascii")


def _open_header(header_key: bytes, raw: bytes) -> bytes | None:
    try:
        return AESGCM(header_key).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:BODY_OFFSET], None)
    except InvalidTag:
        return None


def _open_body(body_key: bytes, raw: bytes, header: bytes) -> bytes:
    nonce = raw[:NONCE_BYTES]
    k_aes, k_chacha = layer_keys(body_key)
    try:
        inner = ChaCha20Poly1305(k_chacha).decrypt(nonce, raw[BODY_OFFSET:], header)
        return AESGCM(k_aes).decrypt(nonce, inner, header)
    except InvalidTag:
        raise MessageRejected("فشل التحقق: الحزمة مُعدّلة أو مزوّرة — رُفضت.") from None


@dataclass(frozen=True)
class HandshakeView:
    """ما تحمله مصافحة: كله معلن أو مقفل (ليس سرًا بحد ذاته)."""
    epoch: int
    role: str
    half: bytes          # نصف X25519
    kem_box: bytes       # صندوق ML-KEM (من الطرف A)، أو أصفار
    kem_public: bytes    # قفل ML-KEM (من الطرف B)، أو أصفار


def read_handshake(vault_key: bytes, packet: str) -> HandshakeView:
    """يفتح مصافحة بمفتاح الخزنة (للتجارب: هكذا يراها من يملك الخزنة)."""
    raw = decode_packet(packet)
    header_key, _ = _handshake_keys(one_way(vault_key, b"handshake"))
    header = _open_header(header_key, raw)
    if header is None:
        raise MessageRejected("ليست مصافحة صادرة بمفتاح الخزنة هذا")
    kind, _, epoch, role, half, _, _, box, public = HEADER.unpack(header)
    if kind != b"H":
        raise MessageRejected("ليست مصافحة")
    return HandshakeView(epoch, role.decode("ascii", "replace"), half, box, public)


# ---------------------------------------------------------------------- #
# حالة كل فترة
# ---------------------------------------------------------------------- #
def _hex(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def _unhex(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


_BYTES_FIELDS = (
    "hs_key", "hs_public", "hs_private", "vault_key", "hs_kem_private", "hs_kem_public",
    "hs_kem_box", "peer_hs_public", "peer_hs_kem_public", "header_key",
    "dhs_private", "dhs_public", "dhr", "kem_s_private", "kem_s_public", "kem_box_out",
    "rk", "cks", "ckr",
)


@dataclass
class EpochState:
    valid_from: datetime
    valid_until: datetime
    hs_key: bytes                       # مفتاح المصافحات (مشتق باتجاه واحد من مفتاح الخزنة)
    hs_public: bytes                    # نصف مصافحتي (X25519)
    hs_private: bytes | None = None     # يُتلف بعد اكتمال المصافحة
    vault_key: bytes | None = None      # يُتلف بعد اكتمال المصافحة
    hs_kem_private: bytes | None = None  # قفل مصافحتي الخاص (الطرف B)؛ يصبح قفله الأول في السقّاطة
    hs_kem_public: bytes | None = None   # قفل مصافحتي المفتوح (الطرف B)
    hs_kem_box: bytes | None = None      # صندوق المصافحة (يرسله A ويستلمه B)
    peer_hs_public: bytes | None = None
    peer_hs_kem_public: bytes | None = None
    key_fp: str | None = None           # بصمة مفتاح الفترة (للمقارنة بالهاتف)
    header_key: bytes | None = None     # مفتاح إخفاء رؤوس الحزم
    peer_confirmed: bool = False        # هل تأكدنا أن الطرف الآخر أكمل المصافحة؟
    # السقّاطة المزدوجة الهجينة (بأسماء المواصفات: DHs, DHr, RK, CKs, CKr, Ns, Nr, PN)
    dhs_private: bytes | None = None
    dhs_public: bytes | None = None
    dhr: bytes | None = None
    kem_s_private: bytes | None = None  # قفلي الحالي (الخاص): يفتح صناديق الطرف الآخر
    kem_s_public: bytes | None = None   # قفلي الحالي (المفتوح): يُرسل في كل حزمة
    kem_box_out: bytes | None = None    # صندوق سلسلة إرسالي الحالية (يُرسل في كل حزمة منها)
    rk: bytes | None = None
    cks: bytes | None = None
    ckr: bytes | None = None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    old_halves: list[bytes] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.header_key is not None

    def to_dict(self) -> dict:
        data = {name: _hex(getattr(self, name)) for name in _BYTES_FIELDS}
        data.update({
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "key_fp": self.key_fp,
            "peer_confirmed": self.peer_confirmed,
            "ns": self.ns, "nr": self.nr, "pn": self.pn,
            "skipped": {f"{dh.hex()}:{n}": key.hex() for (dh, n), key in self.skipped.items()},
            "old_halves": [half.hex() for half in self.old_halves],
        })
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "EpochState":
        skipped = {}
        for name, key in data.get("skipped", {}).items():
            dh, n = name.split(":")
            skipped[(bytes.fromhex(dh), int(n))] = bytes.fromhex(key)
        return cls(
            valid_from=parse_time(data["valid_from"]),
            valid_until=parse_time(data["valid_until"]),
            key_fp=data.get("key_fp"),
            peer_confirmed=bool(data.get("peer_confirmed", False)),
            ns=int(data.get("ns", 0)), nr=int(data.get("nr", 0)), pn=int(data.get("pn", 0)),
            skipped=skipped,
            old_halves=[bytes.fromhex(h) for h in data.get("old_halves", [])],
            **{name: _unhex(data.get(name)) for name in _BYTES_FIELDS},
        )


@dataclass(frozen=True)
class Received:
    """نتيجة استقبال حزمة."""
    kind: str                       # "handshake" أو "message" أو "dummy"
    epoch: int
    texts: tuple[str, ...] = ()
    duplicate: bool = False
    waiting: bool = False           # مصافحة وصلت قبل أن يحمل الطرف الآخر الصندوق

    @property
    def text(self) -> str | None:
        return "\n".join(self.texts) if self.texts else None


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
            elif now >= state.valid_until and state.cks is not None:
                state.cks = None                       # الفترة انتهت: لا إرسال بها بعد الآن
                changed = True
        if changed and save:
            self.save()

    def current_state(self, now: datetime | None = None) -> tuple[int, EpochState]:
        now = self._now(now)
        for epoch, state in self.epochs.items():
            if state.valid_from <= now < state.valid_until:
                return epoch, state
        raise KeyUnavailable(
            "لا يوجد مفتاح للوقت الحالي: حان موعد تغيير جديد (أو لم يُستورد أي مفتاح بعد). "
            "استورد مفتاح الخزنة أولًا — النظام يرفض الاستمرار بمفتاح قديم.")

    def _parse_header(self, header: bytes, kind: bytes, epoch: int):
        h_kind, version, h_epoch, role_raw, half, pn, n, box, public = HEADER.unpack(header)
        if h_kind != kind or version != FORMAT_VERSION or h_epoch != epoch:
            raise MessageRejected("رأس الحزمة غير متّسق — رُفضت")
        role = role_raw.decode("ascii", "replace")
        if role not in ROLES:
            raise MessageRejected("دور غير معروف في الحزمة — رُفضت")
        if role == self.role:
            raise MessageRejected("هذه حزمة صادرة منك أنت أُعيدت إليك — رُفضت")
        return half, pn, n, box, public

    # ------------------------------------------------------------------ #
    # 1) استلام مفتاح الخزنة + توليد أسرار المصافحة
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
            private, public = new_key_pair()
            state = EpochState(
                valid_from=valid_from, valid_until=valid_until,
                hs_key=one_way(vault_key, b"handshake"), hs_public=public,
                hs_private=private, vault_key=vault_key)
            if role == "B":
                state.hs_kem_private, state.hs_kem_public = new_kem_pair()
            self.epochs[epoch] = state
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
    def _handshake_packet(self, epoch: int, state: EpochState) -> str:
        header_key, body_key = _handshake_keys(state.hs_key)
        header = HEADER.pack(
            b"H", FORMAT_VERSION, epoch, self.role.encode("ascii"), state.hs_public, 0, 0,
            state.hs_kem_box if (self.role == "A" and state.hs_kem_box) else NO_KEM_CT,
            state.hs_kem_public if self.role == "B" else NO_KEM_PUBLIC)
        # علامة "أنا جاهز": تخبر الطرف الآخر أن مصافحته وصلتني
        return _seal(header_key, body_key, header, bytes([1 if state.ready else 0]))

    def my_handshake(self, now: datetime | None = None) -> str:
        """مصافحتي للفترة الحالية (لإرسالها أو إعادة إرسالها للطرف الآخر)."""
        return self._handshake_packet(*self.current_state(now))

    def handshake_for(self, epoch: int) -> str:
        return self._handshake_packet(epoch, self.epochs[epoch])

    def seal_packet(self, texts: list[str], now: datetime | None = None) -> str:
        """
        حزمة رسائل: صفر رسالة = حزمة وهمية، أو رسالة، أو عدة رسائل قصيرة معًا.
        كلها بالشكل نفسه تمامًا.
        """
        now = self._now(now)
        self._purge(now, save=False)
        epoch, state = self.current_state(now)
        if not state.ready:
            raise HandshakePending(
                "مفتاح هذه الفترة غير مكتمل: بانتظار اكتمال المصافحة مع الطرف الآخر.")
        if state.cks is None:   # مثلًا: رجعت ساعة الجهاز إلى الوراء بعد انتهاء الفترة
            raise KeyUnavailable("هذه الفترة انتهت وأُتلفت سلسلة إرسالها؛ لا إرسال بها بعد الآن.")
        payload = encode_passengers(texts)
        message_key = chain_message_key(state.cks)
        header = HEADER.pack(b"M", FORMAT_VERSION, epoch, self.role.encode("ascii"),
                             state.dhs_public, state.pn, state.ns,
                             state.kem_box_out, state.kem_s_public)
        state.cks = chain_next(state.cks)    # المفتاح المستعمل لم يعد قابلًا للحساب
        state.ns += 1
        self.save()   # نحفظ التقدّم قبل الإرسال: لا يُستعمل أي مفتاح مرتين أبدًا
        return _seal(state.header_key, message_key, header, payload)

    def send(self, text: str, now: datetime | None = None) -> str:
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise NodeError(f"النص أطول من الحد المسموح ({MAX_TEXT_BYTES} بايت)؛ قسّمه إلى عدة رسائل")
        return self.seal_packet([text], now)

    def send_dummy(self, now: datetime | None = None) -> str:
        return self.seal_packet([], now)

    # ------------------------------------------------------------------ #
    # 3) الاستقبال (مصافحة أو رسالة أو وهمية: الشكل واحد)
    # ------------------------------------------------------------------ #
    def receive(self, packet: str, now: datetime | None = None) -> Received:
        raw = decode_packet(packet)
        if self.role is None:
            raise KeyUnavailable("هذا النظام لم يستلم أي مفتاح من الخزنة بعد")
        now = self._now(now)
        self._purge(now)
        for epoch, state in sorted(self.epochs.items(), reverse=True):
            if state.ready:
                header = _open_header(state.header_key, raw)
                if header is not None:
                    return self._receive_message(epoch, state, header, raw, now)
            header = _open_header(_handshake_keys(state.hs_key)[0], raw)
            if header is not None:
                return self._receive_handshake(epoch, state, header, raw)
        raise MessageRejected(
            "تعذّر فتح الحزمة بأي مفتاح متاح: إما أنها مزوّرة أو مُعدّلة أو ضجيج، أو ليست من "
            "الطرف المقترن، أو أنها لفترة لم يُستورد مفتاحها بعد، أو قديمة أُتلفت مفاتيحها.")

    def _receive_handshake(self, epoch: int, state: EpochState,
                           header: bytes, raw: bytes) -> Received:
        half, _, _, box, kem_public = self._parse_header(header, b"H", epoch)
        peer_ready = _open_body(_handshake_keys(state.hs_key)[1], raw, header)[0] == 1
        has_box = not hmac.compare_digest(box, NO_KEM_CT)

        if state.ready:
            consistent = hmac.compare_digest(half, state.peer_hs_public)
            if self.role == "A":
                consistent = consistent and hmac.compare_digest(kem_public, state.peer_hs_kem_public)
            elif has_box:
                consistent = consistent and hmac.compare_digest(box, state.hs_kem_box)
            if not consistent:
                raise MessageRejected("مصافحة مختلفة لفترة اكتملت مصافحتها — رُفضت")
            if peer_ready and not state.peer_confirmed:
                state.peer_confirmed = True
                self.save()
            return Received("handshake", epoch, duplicate=True)

        dh_shared = _dh(state.hs_private, half)
        if self.role == "A":
            # B أرسل قفله المفتوح: نضع فيه سرًا ونرسل الصندوق في مصافحتنا التالية
            kem_shared, state.hs_kem_box = kem_lock(kem_public)
            state.peer_hs_kem_public = kem_public
            secrets = derive_epoch(state.vault_key, epoch, dh_shared, kem_shared,
                                   state.hs_public, half, kem_public, state.hs_kem_box)
        else:
            if not has_box:
                # مصافحة A وصلت قبل أن يصله قفلنا: ننتظر مصافحته التالية (تحمل الصندوق)
                return Received("handshake", epoch, waiting=True)
            kem_shared = kem_unlock(state.hs_kem_private, box)
            state.hs_kem_box = box
            secrets = derive_epoch(state.vault_key, epoch, dh_shared, kem_shared,
                                   half, state.hs_public, state.hs_kem_public, box)

        state.header_key, state.key_fp = secrets.header_key, secrets.fingerprint
        state.peer_hs_public = half
        if self.role == "A":
            # مثل "Alice" في المواصفات: أسرار جديدة فورًا، وسلسلة إرسال منها
            state.dhs_private, state.dhs_public = new_key_pair()
            state.kem_s_private, state.kem_s_public = new_kem_pair()
            state.dhr = half
            kem_out, state.kem_box_out = kem_lock(kem_public)
            state.rk, state.cks = kdf_root(secrets.root_key, _dh(state.dhs_private, half), kem_out)
            state.ckr = secrets.initial_chain_b
        else:
            # مثل "Bob": أسرار المصافحة نفسها هي أسراره الأولى، مع سلسلة أولى ليرسل متى شاء
            state.dhs_private, state.dhs_public = state.hs_private, state.hs_public
            state.kem_s_private, state.kem_s_public = state.hs_kem_private, state.hs_kem_public
            state.kem_box_out = NO_KEM_CT
            state.dhr = None
            state.rk = secrets.root_key
            state.cks = secrets.initial_chain_b
            state.ckr = None
        state.ns = state.nr = state.pn = 0
        state.peer_confirmed = peer_ready
        state.hs_private = None      # نُتلف كل ما لم نعد نحتاجه.
        state.hs_kem_private = None
        state.vault_key = None
        self.save()
        return Received("handshake", epoch)

    def _receive_message(self, epoch: int, state: EpochState, header: bytes,
                         raw: bytes, now: datetime) -> Received:
        half, pn, n, box, kem_public = self._parse_header(header, b"M", epoch)
        work = copy.deepcopy(state)   # نعمل على نسخة، ولا نعتمدها إلا بعد نجاح التحقق
        if (half, n) in work.skipped:
            message_key = work.skipped.pop((half, n))
        else:
            is_current = work.dhr is not None and hmac.compare_digest(half, work.dhr)
            replay = (not is_current and any(hmac.compare_digest(half, h) for h in work.old_halves)
                      ) or (is_current and n < work.nr)
            if replay:
                raise ReplayRejected(
                    "هذه الرسالة قُرئت من قبل، أو أنها إعادة إرسال لرسالة مسجّلة: "
                    "مفتاحها أُتلف لحظة قراءتها — رُفضت.")
            if not is_current:
                self._skip(work, pn)                       # مفاتيح ما لم يصل من السلسلة السابقة
                self._ratchet(work, half, box, kem_public)  # عشوائية جديدة (X25519 + ML-KEM)
            self._skip(work, n)
            message_key = chain_message_key(work.ckr)
            work.ckr = chain_next(work.ckr)
            work.nr += 1

        texts = _decode_passengers(_open_body(message_key, raw, header))
        work.peer_confirmed = True
        if now >= work.valid_until:
            work.cks = None
        self.epochs[epoch] = work               # التحقق نجح: نعتمد الحالة الجديدة
        self.save()
        return Received("message" if texts else "dummy", epoch, texts)

    @staticmethod
    def _skip(work: EpochState, until: int) -> None:
        if work.ckr is None:
            return
        if until - work.nr > MAX_SKIP:
            raise MessageRejected("رقم الرسالة بعيد جدًا عن المتوقع — رُفضت")
        while work.nr < until:
            work.skipped[(work.dhr, work.nr)] = chain_message_key(work.ckr)
            work.ckr = chain_next(work.ckr)
            work.nr += 1
        while len(work.skipped) > MAX_STORED_SKIPPED:
            del work.skipped[next(iter(work.skipped))]

    @staticmethod
    def _ratchet(work: EpochState, half: bytes, box: bytes, kem_public: bytes) -> None:
        """
        خطوة السقّاطة الهجينة:
          - نفتح صندوق الطرف الآخر بقفلنا الحالي، ونمزجه مع سرّ X25519 → سلسلة استقبال جديدة؛
          - نولّد نصفًا جديدًا وقفلًا جديدًا، ونضع سرًا في صندوق مقفل بقفله الجديد،
            ونمزجهما → سلسلة إرسال جديدة.
        """
        if hmac.compare_digest(box, NO_KEM_CT) or hmac.compare_digest(kem_public, NO_KEM_PUBLIC):
            raise MessageRejected("خطوة سقّاطة بلا حماية ML-KEM — رُفضت")
        if work.dhr is not None:
            work.old_halves = (work.old_halves + [work.dhr])[-MAX_OLD_HALVES:]
        work.pn, work.ns, work.nr = work.ns, 0, 0
        work.dhr = half
        kem_in = kem_unlock(work.kem_s_private, box)
        work.rk, work.ckr = kdf_root(work.rk, _dh(work.dhs_private, half), kem_in)
        work.dhs_private, work.dhs_public = new_key_pair()
        work.kem_s_private, work.kem_s_public = new_kem_pair()
        kem_out, work.kem_box_out = kem_lock(kem_public)
        work.rk, work.cks = kdf_root(work.rk, _dh(work.dhs_private, half), kem_out)

    # ------------------------------------------------------------------ #
    # معلومات
    # ------------------------------------------------------------------ #
    def key_fingerprint(self, now: datetime | None = None) -> str | None:
        """
        بصمة مفتاح الفترة الحالية. إذا قرأها الطرفان لبعضهما بالهاتف وتطابقت،
        فلا يوجد أي انتحال في المنتصف.
        """
        try:
            return self.current_state(now)[1].key_fp
        except KeyUnavailable:
            return None

    def current_half(self, now: datetime | None = None) -> str | None:
        """بصمة نصفي العام الحالي في السقّاطة (يتغير مع تبادل الكلام)."""
        try:
            state = self.current_state(now)[1]
        except KeyUnavailable:
            return None
        return fingerprint(state.dhs_public, "half") if state.dhs_public else None


# ---------------------------------------------------------------------- #
# واجهة سطر الأوامر
# ---------------------------------------------------------------------- #
def _read_arg(value: str | None) -> str:
    return value if value is not None else sys.stdin.read()


def _cmd_import(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    epochs = node.import_from_folder(args.source)
    print(f"تم استيراد مفتاح الخزنة للفترة {', '.join(map(str, epochs))} ومسحه من مجلد النقل.")
    print("وتم توليد أسرار عشوائية جديدة. أرسل هذه المصافحة إلى الطرف الآخر")
    print("(شكلها مثل أي رسالة مشفرة، ونشرها آمن):")
    print()
    print(node.handshake_for(epochs[-1]))


def _cmd_handshake(args: argparse.Namespace) -> None:
    print(OnlineNode.open(args.node).my_handshake())


def _cmd_send(args: argparse.Namespace) -> None:
    print(OnlineNode.open(args.node).send(_read_arg(args.text)))


def _cmd_dummy(args: argparse.Namespace) -> None:
    print(OnlineNode.open(args.node).send_dummy())


def _cmd_receive(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    result = node.receive(_read_arg(args.packet))
    if result.kind == "message":
        print(result.text)
    elif result.kind == "dummy":
        print("(حزمة وهمية: لا محتوى. لكنها جدّدت العشوائية.)")
    elif result.waiting:
        print("وصلت مصافحة الطرف الآخر، لكنها لا تحمل الصندوق المقفل بعد.")
        print("أرسل له مصافحتك (تحمل قفلك)، ثم استقبل مصافحته التالية.")
    elif result.duplicate:
        print("مصافحة مكررة وصلت من قبل؛ لا شيء جديد.")
    else:
        print(f"اكتملت المصافحة. بصمة مفتاح الفترة: {node.epochs[result.epoch].key_fp}")
        print("(يمكنكما مقارنتها بالهاتف لكشف أي انتحال)")
        if node.role == "A":
            print("أرسل هذه المصافحة الجديدة إلى الطرف الآخر (تحمل الصندوق المقفل):")
            print()
            print(node.handshake_for(result.epoch))


def _cmd_status(args: argparse.Namespace) -> None:
    node = OnlineNode.open(args.node)
    if node.role is None:
        print("النظام غير مقترن بعد (لم يُستورد أي مفتاح).")
        return
    print(f"بصمة الزوج: {node.pair_id}   الدور: {node.role}")
    now = utc_now()
    for epoch, state in sorted(node.epochs.items()):
        current = " ← الحالية" if state.valid_from <= now < state.valid_until else ""
        if state.ready:
            status = (f"جاهزة (هجينة: X25519 + ML-KEM-1024)، بصمة المفتاح {state.key_fp}، "
                      f"نصفي الحالي {fingerprint(state.dhs_public, 'half')}")
        else:
            status = "بانتظار اكتمال المصافحة"
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

    dummy = sub.add_parser("dummy", help="حزمة وهمية (بالشكل نفسه تمامًا)")
    dummy.add_argument("--node", required=True, type=Path)
    dummy.set_defaults(func=_cmd_dummy)

    receive = sub.add_parser("receive", help="استقبال حزمة (مصافحة أو رسالة أو وهمية)")
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
