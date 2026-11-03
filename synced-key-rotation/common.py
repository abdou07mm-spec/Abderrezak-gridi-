"""
أدوات مشتركة بين النظامين
==========================
- الجدول الزمني للتغيير (Schedule): يحسب "رقم الحقبة" الحالية من الساعة فقط،
  لذلك يعرف المرسل والمستقبل دائمًا أي مفتاح يجب استعماله دون أن يتواصلا.
- البصمات (fingerprint): لمقارنة سرّين بالعين دون كشفهما.
- الكتابة الآمنة للملفات السرية.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

FORMAT_VERSION = 2
ROLES = ("A", "B")  # الطرف الأول والطرف الثاني في الزوج


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(moment: datetime) -> datetime:
    """يحوّل أي وقت إلى توقيت UTC (الوقت بلا منطقة زمنية يُعتبر UTC)."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def stamp(moment: datetime) -> str:
    return to_utc(moment).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class Schedule:
    """
    الجدول الزمني المتفق عليه بين الطرفين.

    "الحقبة" = الفترة التي يبقى فيها مفتاح واحد صالحًا (افتراضيًا يوم كامل
    من 08:00 إلى 08:00). الحقبة رقم 0 تبدأ عند anchor وكل حقبة تدوم period.
    """

    anchor: datetime
    period: timedelta

    @classmethod
    def starting_at(cls, now: datetime, rotation_hour_utc: int = 8,
                    period_hours: int = 24) -> "Schedule":
        if not 0 <= rotation_hour_utc <= 23:
            raise ValueError("ساعة التغيير يجب أن تكون بين 0 و 23")
        if period_hours <= 0:
            raise ValueError("مدة الحقبة يجب أن تكون عددًا موجبًا من الساعات")
        now = to_utc(now)
        anchor = now.replace(hour=rotation_hour_utc, minute=0, second=0, microsecond=0)
        if anchor > now:
            anchor -= timedelta(days=1)
        return cls(anchor, timedelta(hours=period_hours))

    def epoch_at(self, moment: datetime) -> int:
        """رقم الحقبة في لحظة معينة."""
        return (to_utc(moment) - self.anchor) // self.period

    def start_of(self, epoch: int) -> datetime:
        return self.anchor + epoch * self.period

    def to_dict(self) -> dict:
        return {
            "anchor": self.anchor.isoformat(),
            "period_seconds": int(self.period.total_seconds()),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Schedule":
        period = timedelta(seconds=int(data["period_seconds"]))
        if period <= timedelta(0):
            raise ValueError("مدة الحقبة غير صالحة")
        return cls(to_utc(datetime.fromisoformat(data["anchor"])), period)


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
    يُفضَّل نقل المفتاح عبر رمز QR بدل ملف.
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
