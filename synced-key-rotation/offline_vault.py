#!/usr/bin/env python3
"""
النظام رقم 1 — الخزنة غير المتصلة (Offline Vault)
=================================================

يعمل على جهاز لا يتصل بالإنترنت أبدًا.

ماذا يفعل؟
  1. ينشئ مرة واحدة فقط "بذرة سرية" عشوائية مشتركة بين المرسل والمستقبل
     (عند لقاء شخصي: نسخة لكل طرف).
  2. في موعد التغيير (مثلًا 08:00 كل يوم) يشتق من البذرة "مفتاح اليوم" فقط،
     ويُخرجه إلى النظام المتصل (رقم 2) في اتجاه واحد (ملف / فلاشة / رمز QR)
     ثم ينفصل.
  3. بعد كل تغيير يُتلف حالته القديمة، فلا يمكن استرجاع مفاتيح الأيام الماضية
     حتى لو سُرقت الخزنة لاحقًا (السرية الأمامية / Forward Secrecy).

كيف يكون التغيير "عشوائيًا" و"متزامنًا" في الوقت نفسه؟
  المفاتيح تُشتق بدالة باتجاه واحد (HMAC-SHA256) من بذرة عشوائية:

      بذرة ──► سلسلة(1) ──► سلسلة(2) ──► سلسلة(3) ──► ...
                  │             │             │
                  ▼             ▼             ▼
              مفتاح(1)      مفتاح(2)      مفتاح(3)

  - من لا يملك البذرة يرى مفاتيح عشوائية تمامًا لا يمكن توقع التالي منها.
  - من يملك البذرة نفسها يحصل على المفتاح نفسه بالضبط في الوقت نفسه،
    دون أي تواصل بين الطرفين (مثل تطبيق Google Authenticator).
  - الأسهم تسير في اتجاه واحد فقط: لا يمكن الرجوع من سلسلة(3) إلى سلسلة(2).

ملاحظة: مفتاح الخزنة ليس المفتاح النهائي للرسائل. النظام المتصل يمزجه مع سرّ
عشوائي جديد يُتفق عليه كل يوم بتبادل Diffie-Hellman (انظر online_node.py)،
فلو سُرقت الخزنة نفسها يبقى السارق عاجزًا عن قراءة رسائل الأيام التالية.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sys
from datetime import datetime
from pathlib import Path

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
    write_private_json,
)

SEED_BYTES = 32  # 256 بت من العشوائية الحقيقية


class VaultError(Exception):
    """خطأ في الخزنة غير المتصلة."""


def _one_way(chain_key: bytes, label: bytes) -> bytes:
    """دالة باتجاه واحد: سهلة الحساب، ومستحيلة العكس عمليًا."""
    return hmac.new(chain_key, label, hashlib.sha256).digest()


def next_chain_key(chain_key: bytes) -> bytes:
    """الخطوة التالية في السلسلة (لا يمكن الرجوع منها إلى السابقة)."""
    return _one_way(chain_key, b"chain:next")


def derive_message_key(chain_key: bytes) -> bytes:
    """مفتاح التشفير الفعلي للحقبة (256 بت لـ AES-256)."""
    return _one_way(chain_key, b"message:key")


def key_fingerprint(key: bytes) -> str:
    return fingerprint(key, "message-key")


class OfflineVault:
    """الخزنة غير المتصلة: تحفظ حالة السلسلة الحالية فقط."""

    def __init__(self, path: Path, schedule: Schedule, epoch: int,
                 chain_key: bytes, pair_id: str, role: str):
        if role not in ROLES:
            raise VaultError(f"دور غير معروف: {role}")
        self.path = Path(path)
        self.schedule = schedule
        self.epoch = epoch
        self.chain_key = chain_key
        self.pair_id = pair_id
        self.role = role  # "A" لمن أنشأ الاقتران، "B" للطرف الآخر

    # ------------------------------------------------------------------ #
    # الإنشاء والتخزين
    # ------------------------------------------------------------------ #
    @classmethod
    def create_pair(cls, my_path: Path, peer_path: Path, *,
                    rotation_hour_utc: int = 8, period_hours: int = 24,
                    now: datetime | None = None) -> tuple["OfflineVault", "OfflineVault"]:
        """
        اللقاء الأول (مرة واحدة فقط): ينشئ بذرة عشوائية ويكتب نسختين
        متطابقتين من الخزنة، واحدة لكل طرف.
        """
        my_path, peer_path = Path(my_path), Path(peer_path)
        if my_path.resolve() == peer_path.resolve():
            raise VaultError("يجب أن يكون للطرفين ملفان مختلفان")
        for path in (my_path, peer_path):
            if path.exists():
                raise VaultError(f"الملف موجود مسبقًا ولن يُستبدل: {path}")

        now = utc_now() if now is None else to_utc(now)
        schedule = Schedule.starting_at(now, rotation_hour_utc, period_hours)
        seed = secrets.token_bytes(SEED_BYTES)  # عشوائية من نظام التشغيل
        pair_id = fingerprint(seed, "pair")
        epoch = schedule.epoch_at(now)

        vaults = tuple(cls(path, schedule, epoch, seed, pair_id, role)
                       for path, role in zip((my_path, peer_path), ROLES))
        for vault in vaults:
            vault.save()
        return vaults  # type: ignore[return-value]

    @classmethod
    def load(cls, path: Path) -> "OfflineVault":
        data = read_json(path)
        if data.get("format") != "offline-vault" or data.get("version") != FORMAT_VERSION:
            raise VaultError(f"هذا الملف ليس خزنة صالحة: {path} "
                             "(إذا أُنشئ بإصدار سابق من البرنامج فأعد الاقتران)")
        chain_key = bytes.fromhex(data["chain_key"])
        if len(chain_key) != SEED_BYTES:
            raise VaultError("حالة الخزنة تالفة")
        return cls(Path(path), Schedule.from_dict(data["schedule"]),
                   int(data["epoch"]), chain_key, data["pair_id"], data["role"])

    def save(self) -> None:
        # الكتابة فوق الحالة القديمة = إتلافها
        write_private_json(self.path, {
            "format": "offline-vault",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "role": self.role,
            "schedule": self.schedule.to_dict(),
            "epoch": self.epoch,
            "chain_key": self.chain_key.hex(),
        })

    # ------------------------------------------------------------------ #
    # التغيير الدوري
    # ------------------------------------------------------------------ #
    def release_key(self, now: datetime | None = None) -> dict:
        """
        يُخرج مفتاح الحقبة الحالية فقط (لا الماضي ولا المستقبل).
        إذا مرّت عدة حقب منذ آخر تشغيل، تتقدم السلسلة إليها مباشرة
        وتُتلف كل الحالات الوسيطة.
        """
        now = utc_now() if now is None else to_utc(now)
        target = self.schedule.epoch_at(now)
        if target < self.epoch:
            raise VaultError(
                f"الحقبة {target} أقدم من حالة الخزنة (الحقبة {self.epoch}): "
                "مفتاحها أُتلف نهائيًا، وهذا مقصود (السرية الأمامية). "
                "إن لم يكن هذا متوقعًا فتحقق من ساعة الجهاز."
            )
        while self.epoch < target:
            self.chain_key = next_chain_key(self.chain_key)
            self.epoch += 1
        self.save()

        key = derive_message_key(self.chain_key)
        return {
            "format": "key-bundle",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "role": self.role,
            "schedule": self.schedule.to_dict(),
            "epoch": self.epoch,
            "valid_from": self.schedule.start_of(self.epoch).isoformat(),
            "valid_until": self.schedule.start_of(self.epoch + 1).isoformat(),
            "key": key.hex(),
        }


def export_bundle(bundle: dict, folder: Path) -> Path:
    """
    يضع مفتاح اليوم في "منطقة النقل" (مجلد على فلاشة مثلًا) ليأخذه النظام 2.
    النقل في اتجاه واحد فقط: الخزنة تكتب ولا تقرأ أي شيء من النظام المتصل.
    """
    path = Path(folder) / f"key_epoch_{bundle['epoch']:06d}.json"
    write_private_json(path, bundle)
    return path


# ---------------------------------------------------------------------- #
# واجهة سطر الأوامر
# ---------------------------------------------------------------------- #
def _cmd_pair(args: argparse.Namespace) -> None:
    me, peer = OfflineVault.create_pair(
        args.me, args.peer,
        rotation_hour_utc=args.rotation_hour, period_hours=args.period_hours,
    )
    print("تم إنشاء البذرة المشتركة.")
    print(f"  خزنتك:          {me.path}")
    print(f"  خزنة الطرف الآخر: {peer.path}  (سلّمها له يدًا بيد ثم احذفها من جهازك)")
    print(f"  بصمة الزوج:      {me.pair_id}  (قارناها معًا للتأكد)")
    print(f"  موعد التغيير:     كل {args.period_hours} ساعة ابتداءً من "
          f"{stamp(me.schedule.anchor)}")


def _cmd_release(args: argparse.Namespace) -> None:
    vault = OfflineVault.load(args.vault)
    bundle = vault.release_key()
    path = export_bundle(bundle, args.out)
    print(f"تم إخراج مفتاح الحقبة {bundle['epoch']} إلى: {path}")
    print(f"  صالح من {stamp(datetime.fromisoformat(bundle['valid_from']))} "
          f"إلى {stamp(datetime.fromisoformat(bundle['valid_until']))}")
    print(f"  بصمة مفتاح الخزنة: {key_fingerprint(bytes.fromhex(bundle['key']))} "
          "(يجب أن تطابق بصمة الطرف الآخر لنفس الحقبة)")


def _cmd_status(args: argparse.Namespace) -> None:
    vault = OfflineVault.load(args.vault)
    print(f"بصمة الزوج:   {vault.pair_id}")
    print(f"الدور:        {vault.role}")
    print(f"حالة السلسلة: الحقبة {vault.epoch}")
    print(f"الحقبة الآن:  {vault.schedule.epoch_at(utc_now())}")


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="النظام 1: الخزنة غير المتصلة")
    sub = parser.add_subparsers(dest="command", required=True)

    pair = sub.add_parser("pair", help="اللقاء الأول: إنشاء البذرة المشتركة (مرة واحدة)")
    pair.add_argument("--me", required=True, type=Path, help="ملف خزنتك")
    pair.add_argument("--peer", required=True, type=Path, help="ملف خزنة الطرف الآخر")
    pair.add_argument("--rotation-hour", type=int, default=8,
                      help="ساعة التغيير بتوقيت UTC (افتراضيًا 8)")
    pair.add_argument("--period-hours", type=int, default=24,
                      help="مدة صلاحية كل مفتاح بالساعات (افتراضيًا 24)")
    pair.set_defaults(func=_cmd_pair)

    release = sub.add_parser("release", help="إخراج مفتاح الحقبة الحالية (يُشغَّل آليًا عند 08:00)")
    release.add_argument("--vault", required=True, type=Path)
    release.add_argument("--out", required=True, type=Path, help="مجلد النقل (فلاشة مثلًا)")
    release.set_defaults(func=_cmd_release)

    status = sub.add_parser("status", help="عرض حالة الخزنة")
    status.add_argument("--vault", required=True, type=Path)
    status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (VaultError, ValueError, OSError) as error:
        print(f"خطأ: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
