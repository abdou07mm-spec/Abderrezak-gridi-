"""
أدوات مشتركة بين النظامين
==========================
- مصدر العشوائية الحقيقية، مع "فحص صحة" يرفض المولّد المعطوب.
- دالة باتجاه واحد (HMAC-SHA256) تُبنى عليها كل السلاسل.
- البصمات، والوقت، والكتابة الآمنة للملفات السرية.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

FORMAT_VERSION = 3
ROLES = ("A", "B")  # الطرف الأول والطرف الثاني في الزوج


# ---------------------------------------------------------------------- #
# العشوائية الحقيقية + فحص الصحة
# ---------------------------------------------------------------------- #
class RandomnessFailure(Exception):
    """مولّد العشوائية أعطى نتيجة مشبوهة؛ البرنامج يرفض الاستمرار."""


_recent_outputs: deque = deque(maxlen=256)


def secure_random(size: int, source: Callable[[int], bytes] = os.urandom) -> bytes:
    """
    عشوائية حقيقية من نظام التشغيل (يجمعها من ضجيج فيزيائي داخل الجهاز)،
    مع فحص صحة قبل استعمالها.

    تنبيه مهم: لا يوجد فحص يستطيع إثبات أن العشوائية قوية (انظر
    randomness_lab.py). هذا الفحص يكشف فقط الأعطال الفادحة التي وقعت فعلًا
    في التاريخ:
      - مولّد يكرر النتيجة نفسها (مثل عطب جهاز PlayStation 3 سنة 2010)،
      - مولّد يعطي أصفارًا أو قيمًا قليلة متكررة.
    عند أي عطب من هذا النوع يتوقف البرنامج بدل أن يولّد مفاتيح ضعيفة بصمت.
    """
    data = source(size)
    if not isinstance(data, bytes) or len(data) != size:
        raise RandomnessFailure("مولّد العشوائية لم يُعطِ العدد المطلوب من البايتات")
    if size >= 12:
        if len(set(data)) < min(size // 4, 64):
            raise RandomnessFailure(
                "مخرجات مولّد العشوائية متشابهة بشكل غير طبيعي — توقف البرنامج احتياطًا")
        digest = hashlib.sha256(data).digest()
        if digest in _recent_outputs:
            raise RandomnessFailure(
                "مولّد العشوائية كرر نتيجة سابقة حرفيًا — توقف البرنامج احتياطًا")
        _recent_outputs.append(digest)
    return data


def one_way(key: bytes, label: bytes) -> bytes:
    """دالة باتجاه واحد: سهلة الحساب، ومستحيلة العكس عمليًا (HMAC-SHA256)."""
    return hmac.new(key, label, hashlib.sha256).digest()


# ---------------------------------------------------------------------- #
# الوقت
# ---------------------------------------------------------------------- #
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(moment: datetime) -> datetime:
    """يحوّل أي وقت إلى توقيت UTC (الوقت بلا منطقة زمنية يُعتبر UTC)."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def parse_time(text: str) -> datetime:
    return to_utc(datetime.fromisoformat(text))


def stamp(moment: datetime) -> str:
    return to_utc(moment).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------- #
# البصمات والملفات
# ---------------------------------------------------------------------- #
def fingerprint(secret: bytes, purpose: str) -> str:
    """
    بصمة قصيرة لسرّ ما (مثل XXXX-XXXX-XXXX-XXXX).
    تُحسب بدالة باتجاه واحد، فعرضها لا يكشف السر، لكنها تسمح للطرفين
    بالتأكد أنهما يملكان السر نفسه.
    """
    digest = hashlib.sha256(
        b"fingerprint|" + purpose.encode() + b"|" + secret
    ).hexdigest()[:16].upper()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


def write_private_json(path: Path, data: dict) -> None:
    """
    يكتب ملفًا سريًا بصلاحيات المالك فقط، وبطريقة ذرّية: إما أن تُكتب
    النسخة الجديدة كاملة أو تبقى القديمة كما هي (لا ملف نصف مكتوب).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def read_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def wipe_file(path: Path) -> None:
    """
    يكتب أصفارًا فوق الملف ثم يحذفه.
    ملاحظة: على أقراص SSD والفلاشات لا يضمن هذا المسح الكامل؛ في نظام حقيقي
    يُفضَّل نقل المفاتيح عبر رمز QR بدل ملف.
    """
    path = Path(path)
    size = path.stat().st_size
    with open(path, "r+b") as handle:
        handle.write(b"\0" * size)
        handle.flush()
        os.fsync(handle.fileno())
    path.unlink()


def use_utf8_console() -> None:
    """لكي تظهر الحروف العربية بشكل صحيح في الطرفية (خصوصًا على ويندوز)."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
