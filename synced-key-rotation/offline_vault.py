#!/usr/bin/env python3
"""
النظام رقم 1 — الخزنة غير المتصلة (Offline Vault)
=================================================

يعمل على جهاز لا يتصل بالإنترنت أبدًا.

1) اللقاء الأول (مرة واحدة فقط): "طقس البذرة"
   تُصنع البذرة السرية بمزج عدة مصادر عشوائية مستقلة:
     - عشوائية جهاز الطرف الأول،
     - عشوائية جهاز الطرف الثاني (اختياري)،
     - رميات نرد حقيقية (اختياري).
   المزج يأخذ قوة أقوى مصدر: يكفي أن يكون مصدر واحد سليمًا وسريًا.
   فإذا كان مولّد أحد الجهازين معطوبًا (كما حدث في خطأ Debian سنة 2008)،
   أنقذته المصادر الأخرى.

2) مواعيد تغيير سرية وغير منتظمة
   موعد كل تغيير يُحسب من السلسلة السرية نفسها: بين ساعتين و10 ساعات
   (افتراضيًا) بعد التغيير السابق، وبدقة الثانية. الطرفان يعرفان المواعيد
   نفسها دون أن يتواصلا، أما المخترق فلا يستطيع توقّعها.

3) عند كل موعد: يُخرج "مفتاح الخزنة" للفترة الجديدة فقط، في اتجاه واحد
   (ملف / فلاشة / رمز QR)، ويُتلف حالته القديمة. لذلك حتى لو سُرقت الخزنة
   لاحقًا، لا يمكن استرجاع مفاتيح الماضي.

      بذرة ──► سلسلة(1) ──► سلسلة(2) ──► سلسلة(3) ──► ...
                  │             │             │
                  ├► مفتاح(1)    ├► مفتاح(2)    ├► مفتاح(3)
                  └► مدة(1)      └► مدة(2)      └► مدة(3)

ملاحظة: مفتاح الخزنة ليس المفتاح النهائي للرسائل. النظام المتصل يمزجه مع سرّ
عشوائي جديد يُتفق عليه بتبادل Diffie-Hellman (انظر online_node.py).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import math
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

SEED_BYTES = 32  # 256 بت
DEFAULT_MIN_HOURS = 2.0
DEFAULT_MAX_HOURS = 10.0
DICE_SEPARATORS = " \t\n,،;-"


class VaultError(Exception):
    """خطأ في الخزنة غير المتصلة."""


# ---------------------------------------------------------------------- #
# السلسلة السرية
# ---------------------------------------------------------------------- #
def next_chain_key(chain_key: bytes) -> bytes:
    """الخطوة التالية في السلسلة (لا يمكن الرجوع منها إلى السابقة)."""
    return one_way(chain_key, b"chain:next")


def derive_vault_key(chain_key: bytes) -> bytes:
    """مفتاح الخزنة للفترة (256 بت)."""
    return one_way(chain_key, b"vault:key")


def period_length(chain_key: bytes, min_seconds: int, max_seconds: int) -> timedelta:
    """مدة الفترة: رقم بين الحدين يُحسب من السلسلة السرية، فلا يمكن توقّعه."""
    span = max_seconds - min_seconds + 1
    value = int.from_bytes(one_way(chain_key, b"schedule:length")[:8], "big")
    return timedelta(seconds=min_seconds + value % span)


def key_fingerprint(key: bytes) -> str:
    return fingerprint(key, "vault-key")


# ---------------------------------------------------------------------- #
# طقس البذرة
# ---------------------------------------------------------------------- #
def parse_dice(text: str) -> list[int]:
    """يقرأ رميات النرد (أرقام من 1 إلى 6، ويمكن فصلها بمسافات أو فواصل)."""
    rolls = []
    for char in text:
        if char in DICE_SEPARATORS:
            continue
        if char not in "123456":
            raise VaultError(f"قيمة غير صالحة في رميات النرد: {char!r} (المسموح من 1 إلى 6 فقط)")
        rolls.append(int(char))
    return rolls


def dice_bits(rolls: int) -> float:
    """كل رمية نرد = log2(6) ≈ 2.58 بت من العشوائية الحقيقية."""
    return rolls * math.log2(6)


def mix_seed(sources: list[tuple[str, bytes]]) -> bytes:
    """
    يمزج كل المصادر في بذرة واحدة بدالة تجزئة.
    النتيجة غير متوقعة ما دام مصدر واحد على الأقل سليمًا وسريًا.
    """
    mixer = hmac.new(b"seed-mix|v3", digestmod=hashlib.sha256)
    for label, value in sources:
        name = label.encode()
        mixer.update(len(name).to_bytes(2, "big") + name)
        mixer.update(len(value).to_bytes(4, "big") + value)
    return mixer.digest()


def make_seed(peer_randomness: bytes | None = None, dice: str | None = None) -> bytes:
    """طقس البذرة: عشوائية هذا الجهاز + (اختياريًا) عشوائية جهاز آخر + رميات نرد."""
    sources = [("this-device", secure_random(SEED_BYTES))]
    if peer_randomness is not None:
        if len(peer_randomness) < 16:
            raise VaultError("عشوائية الطرف الآخر قصيرة جدًا")
        sources.append(("peer-device", peer_randomness))
    if dice:
        rolls = parse_dice(dice)
        if rolls:
            sources.append(("dice", bytes(rolls)))
    return mix_seed(sources)


def schedule_seconds(min_hours: float, max_hours: float) -> tuple[int, int]:
    """حدود المدة العشوائية بين تغييرين، بالثواني (مقرّبة إلى الدقيقة)."""
    min_seconds, max_seconds = round(min_hours * 60) * 60, round(max_hours * 60) * 60
    if min_seconds < 60:
        raise VaultError("أقصر مدة بين تغييرين يجب أن تكون دقيقة واحدة على الأقل")
    if max_seconds < min_seconds:
        raise VaultError("أطول مدة يجب أن تكون أكبر من أقصر مدة أو مساوية لها")
    return min_seconds, max_seconds


# ---------------------------------------------------------------------- #
# رمز الاقتران: كل ما يلزم لنسخ الخزنة عند الطرف الآخر، في سطر يُكتب باليد
# ---------------------------------------------------------------------- #
PAIRING_VERSION = 1
PAIRING_ORIGIN = datetime(2020, 1, 1, tzinfo=timezone.utc)


def encode_pairing_code(seed: bytes, epoch_start: datetime, min_seconds: int,
                        max_seconds: int) -> str:
    """
    البذرة + بداية الجدول + حدود المدة + بصمة تحقق (تكشف أي خطأ في الكتابة).
    هذا الرمز هو السرّ كله: يُسلَّم يدًا بيد، ولا يُرسل أبدًا عبر أي تطبيق.
    """
    minutes = int((to_utc(epoch_start) - PAIRING_ORIGIN).total_seconds() // 60)
    payload = (bytes([PAIRING_VERSION]) + seed + minutes.to_bytes(4, "big")
               + (min_seconds // 60).to_bytes(2, "big") + (max_seconds // 60).to_bytes(2, "big"))
    check = hashlib.sha256(b"pairing-check|" + payload).digest()[:3]
    text = base64.b32encode(payload + check).decode("ascii").rstrip("=")
    return "-".join(text[i:i + 4] for i in range(0, len(text), 4))


def decode_pairing_code(code: str) -> tuple[bytes, datetime, int, int]:
    text = "".join(ch for ch in code.upper() if ch.isalnum())
    try:
        raw = base64.b32decode(text + "=" * (-len(text) % 8))
    except ValueError:
        raise VaultError("رمز الاقتران غير صالح: تحقق من الحروف") from None
    if len(raw) != 1 + SEED_BYTES + 8 + 3 or raw[0] != PAIRING_VERSION:
        raise VaultError("رمز الاقتران غير صالح: طوله غير صحيح")
    payload, check = raw[:-3], raw[-3:]
    if not hmac.compare_digest(check, hashlib.sha256(b"pairing-check|" + payload).digest()[:3]):
        raise VaultError("رمز الاقتران غير صحيح: يوجد خطأ في الكتابة")
    seed = payload[1:1 + SEED_BYTES]
    rest = payload[1 + SEED_BYTES:]
    epoch_start = PAIRING_ORIGIN + timedelta(minutes=int.from_bytes(rest[:4], "big"))
    min_seconds = int.from_bytes(rest[4:6], "big") * 60
    max_seconds = int.from_bytes(rest[6:8], "big") * 60
    if not 60 <= min_seconds <= max_seconds:
        raise VaultError("رمز الاقتران غير صالح")
    return seed, epoch_start, min_seconds, max_seconds


class OfflineVault:
    """الخزنة غير المتصلة: تحفظ حالة السلسلة الحالية فقط."""

    def __init__(self, path: Path, *, pair_id: str, role: str, min_seconds: int,
                 max_seconds: int, epoch: int, epoch_start: datetime,
                 chain_key: bytes, released_epoch: int | None = None):
        if role not in ROLES:
            raise VaultError(f"دور غير معروف: {role}")
        self.path = Path(path)
        self.pair_id = pair_id
        self.role = role  # "A" لمن أنشأ الاقتران، "B" للطرف الآخر
        self.min_seconds = min_seconds
        self.max_seconds = max_seconds
        self.epoch = epoch
        self.epoch_start = to_utc(epoch_start)
        self.chain_key = chain_key
        self.released_epoch = released_epoch

    # ------------------------------------------------------------------ #
    # الإنشاء والتخزين
    # ------------------------------------------------------------------ #
    @classmethod
    def create_pair(cls, my_path: Path, peer_path: Path, *,
                    min_hours: float = DEFAULT_MIN_HOURS,
                    max_hours: float = DEFAULT_MAX_HOURS,
                    peer_randomness: bytes | None = None,
                    dice: str | None = None,
                    now: datetime | None = None) -> tuple["OfflineVault", "OfflineVault"]:
        """
        اللقاء الأول (مرة واحدة فقط): يصنع البذرة ويكتب نسختين متطابقتين
        من الخزنة، واحدة لكل طرف.
        """
        my_path, peer_path = Path(my_path), Path(peer_path)
        if my_path.resolve() == peer_path.resolve():
            raise VaultError("يجب أن يكون للطرفين ملفان مختلفان")
        for path in (my_path, peer_path):
            if path.exists():
                raise VaultError(f"الملف موجود مسبقًا ولن يُستبدل: {path}")
        min_seconds, max_seconds = schedule_seconds(min_hours, max_hours)
        seed = make_seed(peer_randomness, dice)
        now = utc_now() if now is None else to_utc(now)
        epoch_start = now.replace(microsecond=0)
        return tuple(cls.from_seed(path, seed, role, epoch_start, min_seconds, max_seconds)
                     for path, role in zip((my_path, peer_path), ROLES))  # type: ignore[return-value]

    @classmethod
    def from_seed(cls, path: Path, seed: bytes, role: str, epoch_start: datetime,
                  min_seconds: int, max_seconds: int) -> "OfflineVault":
        """ينشئ خزنة من بذرة (عند الإنشاء، أو من رمز الاقتران عند الطرف الآخر)."""
        path = Path(path)
        if path.exists():
            raise VaultError(f"الملف موجود مسبقًا ولن يُستبدل: {path}")
        if len(seed) != SEED_BYTES:
            raise VaultError("طول البذرة غير صحيح")
        vault = cls(path, pair_id=fingerprint(seed, "pair"), role=role,
                    min_seconds=min_seconds, max_seconds=max_seconds,
                    epoch=0, epoch_start=epoch_start, chain_key=seed)
        vault.save()
        return vault

    @classmethod
    def load(cls, path: Path) -> "OfflineVault":
        data = read_json(path)
        if data.get("format") != "offline-vault" or data.get("version") != FORMAT_VERSION:
            raise VaultError(f"هذا الملف ليس خزنة صالحة: {path} "
                             "(إذا أُنشئ بإصدار سابق من البرنامج فأعد الاقتران)")
        chain_key = bytes.fromhex(data["chain_key"])
        if len(chain_key) != SEED_BYTES:
            raise VaultError("حالة الخزنة تالفة")
        return cls(Path(path), pair_id=data["pair_id"], role=data["role"],
                   min_seconds=int(data["min_seconds"]), max_seconds=int(data["max_seconds"]),
                   epoch=int(data["epoch"]), epoch_start=parse_time(data["epoch_start"]),
                   chain_key=chain_key, released_epoch=data.get("released_epoch"))

    def save(self) -> None:
        # الكتابة فوق الحالة القديمة = إتلافها
        write_private_json(self.path, {
            "format": "offline-vault",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "role": self.role,
            "min_seconds": self.min_seconds,
            "max_seconds": self.max_seconds,
            "epoch": self.epoch,
            "epoch_start": self.epoch_start.isoformat(),
            "chain_key": self.chain_key.hex(),
            "released_epoch": self.released_epoch,
        })

    # ------------------------------------------------------------------ #
    # المواعيد السرية
    # ------------------------------------------------------------------ #
    def next_change(self) -> datetime:
        """موعد التغيير القادم (يعرفه الجهاز الأوفلاين فقط)."""
        return self.epoch_start + period_length(self.chain_key, self.min_seconds, self.max_seconds)

    def upcoming_changes(self, count: int) -> list[datetime]:
        """المواعيد القادمة، دون تغيير حالة الخزنة (للعرض والتجربة فقط)."""
        chain, start, result = self.chain_key, self.epoch_start, []
        for _ in range(count):
            start += period_length(chain, self.min_seconds, self.max_seconds)
            chain = next_chain_key(chain)
            result.append(start)
        return result

    def _advance_to(self, now: datetime) -> None:
        if now < self.epoch_start:
            raise VaultError(
                f"الوقت المطلوب ({stamp(now)}) أقدم من حالة الخزنة: مفاتيحه أُتلفت نهائيًا، "
                "وهذا مقصود (السرية الأمامية). إن لم يكن هذا متوقعًا فتحقق من ساعة الجهاز.")
        while now >= self.next_change():
            self.epoch_start = self.next_change()
            self.chain_key = next_chain_key(self.chain_key)
            self.epoch += 1

    # ------------------------------------------------------------------ #
    # إخراج المفتاح
    # ------------------------------------------------------------------ #
    def release_key(self, now: datetime | None = None) -> dict:
        """
        يُخرج مفتاح الفترة الحالية فقط (لا الماضي ولا المستقبل).
        إذا مرّت عدة فترات منذ آخر تشغيل، تتقدم السلسلة مباشرة
        وتُتلف كل الحالات الوسيطة.
        """
        self._advance_to(utc_now() if now is None else to_utc(now))
        self.released_epoch = self.epoch
        self.save()
        return {
            "format": "key-bundle",
            "version": FORMAT_VERSION,
            "pair_id": self.pair_id,
            "role": self.role,
            "epoch": self.epoch,
            "valid_from": self.epoch_start.isoformat(),
            "valid_until": self.next_change().isoformat(),
            "key": derive_vault_key(self.chain_key).hex(),
        }

    def release_if_new(self, now: datetime | None = None) -> dict | None:
        """مثل release_key، لكن لا يُخرج شيئًا إذا لم يحن موعد تغيير جديد."""
        now = utc_now() if now is None else to_utc(now)
        self._advance_to(now)
        if self.released_epoch == self.epoch:
            self.save()
            return None
        return self.release_key(now)


def export_bundle(bundle: dict, folder: Path) -> Path:
    """
    يضع مفتاح الفترة في "منطقة النقل" (مجلد على فلاشة مثلًا) ليأخذه النظام 2.
    النقل في اتجاه واحد فقط: الخزنة تكتب ولا تقرأ أي شيء من النظام المتصل.
    """
    path = Path(folder) / f"key_epoch_{bundle['epoch']:06d}.json"
    write_private_json(path, bundle)
    return path


# ---------------------------------------------------------------------- #
# واجهة سطر الأوامر
# ---------------------------------------------------------------------- #
def _cmd_contribute(args: argparse.Namespace) -> None:
    value = secure_random(SEED_BYTES)
    write_private_json(args.out, {"format": "randomness", "value": value.hex()})
    print(f"تم توليد 256 بت من عشوائية هذا الجهاز في: {args.out}")
    print("انقل الملف إلى جهاز الاقتران؛ سيُمسح تلقائيًا بعد استعماله.")


def _cmd_pair(args: argparse.Namespace) -> None:
    peer_randomness = None
    if args.peer_randomness:
        data = read_json(args.peer_randomness)
        if data.get("format") != "randomness":
            raise VaultError("ملف عشوائية الطرف الآخر غير صالح")
        peer_randomness = bytes.fromhex(data["value"])
    me, peer = OfflineVault.create_pair(
        args.me, args.peer, min_hours=args.min_hours, max_hours=args.max_hours,
        peer_randomness=peer_randomness, dice=args.dice)
    if args.peer_randomness:
        wipe_file(args.peer_randomness)

    print("تم صنع البذرة المشتركة من المصادر التالية:")
    print("  - عشوائية هذا الجهاز: 256 بت")
    if peer_randomness is not None:
        print(f"  - عشوائية جهاز الطرف الآخر: {len(peer_randomness) * 8} بت (ومُسح ملفها)")
    if args.dice:
        rolls = len(parse_dice(args.dice))
        print(f"  - {rolls} رمية نرد: حوالي {dice_bits(rolls):.0f} بت"
              + ("" if rolls >= 100 else "  (100 رمية أو أكثر تكفي وحدها لـ 256 بت)"))
    print("  البذرة غير متوقعة ما دام مصدر واحد على الأقل سليمًا وسريًا.")
    print(f"خزنتك:            {me.path}")
    print(f"خزنة الطرف الآخر: {peer.path}  (سلّمها له يدًا بيد ثم احذفها من جهازك)")
    print(f"بصمة الزوج:       {me.pair_id}  (قارناها معًا للتأكد)")
    print(f"مواعيد التغيير:   سرية وغير منتظمة، كل {args.min_hours:g} إلى {args.max_hours:g} ساعات")


def _release(vault: OfflineVault, out: Path, force: bool) -> bool:
    bundle = vault.release_key() if force else vault.release_if_new()
    if bundle is None:
        return False
    path = export_bundle(bundle, out)
    print(f"[{stamp(utc_now())}] تم إخراج مفتاح الفترة {bundle['epoch']} إلى: {path}")
    print(f"  بصمة مفتاح الخزنة: {key_fingerprint(bytes.fromhex(bundle['key']))}")
    return True


def _cmd_release(args: argparse.Namespace) -> None:
    if not _release(OfflineVault.load(args.vault), args.out, args.force):
        print("لم يحن موعد تغيير جديد بعد؛ لم يُخرج أي مفتاح.")


def _cmd_watch(args: argparse.Namespace) -> None:
    print("الخزنة في وضع المراقبة: ستُخرج المفتاح الجديد عند كل موعد سري. (Ctrl+C للإيقاف)")
    while True:
        vault = OfflineVault.load(args.vault)
        _release(vault, args.out, force=False)
        wait = (vault.next_change() - utc_now()).total_seconds()
        time.sleep(max(1.0, min(args.check_seconds, wait)))


def _cmd_status(args: argparse.Namespace) -> None:
    vault = OfflineVault.load(args.vault)
    print(f"بصمة الزوج:     {vault.pair_id}")
    print(f"الدور:          {vault.role}")
    print(f"حالة السلسلة:   الفترة {vault.epoch} (بدأت {stamp(vault.epoch_start)})")
    print(f"التغيير القادم: {stamp(vault.next_change())}  (سري: لا تشاركه)")


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="النظام 1: الخزنة غير المتصلة")
    sub = parser.add_subparsers(dest="command", required=True)

    contribute = sub.add_parser("contribute",
                                help="يولّد عشوائية جهاز الطرف الثاني لمزجها في البذرة")
    contribute.add_argument("--out", required=True, type=Path)
    contribute.set_defaults(func=_cmd_contribute)

    pair = sub.add_parser("pair", help="اللقاء الأول: صنع البذرة المشتركة (مرة واحدة)")
    pair.add_argument("--me", required=True, type=Path, help="ملف خزنتك")
    pair.add_argument("--peer", required=True, type=Path, help="ملف خزنة الطرف الآخر")
    pair.add_argument("--peer-randomness", type=Path,
                      help="ملف العشوائية الذي ولّده جهاز الطرف الآخر بالأمر contribute")
    pair.add_argument("--dice", help='رميات نرد حقيقية، مثل "3 6 1 2 5 ..." (يُنصح بـ 100 رمية أو أكثر)')
    pair.add_argument("--min-hours", type=float, default=DEFAULT_MIN_HOURS,
                      help=f"أقصر مدة بين تغييرين (افتراضيًا {DEFAULT_MIN_HOURS:g})")
    pair.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS,
                      help=f"أطول مدة بين تغييرين (افتراضيًا {DEFAULT_MAX_HOURS:g})")
    pair.set_defaults(func=_cmd_pair)

    release = sub.add_parser("release", help="إخراج المفتاح إذا حان موعد تغيير (آمن للتشغيل كل دقيقة)")
    release.add_argument("--vault", required=True, type=Path)
    release.add_argument("--out", required=True, type=Path, help="مجلد النقل (فلاشة مثلًا)")
    release.add_argument("--force", action="store_true", help="إعادة إخراج مفتاح الفترة الحالية")
    release.set_defaults(func=_cmd_release)

    watch = sub.add_parser("watch", help="تشغيل مستمر: يُخرج المفتاح تلقائيًا عند كل موعد سري")
    watch.add_argument("--vault", required=True, type=Path)
    watch.add_argument("--out", required=True, type=Path)
    watch.add_argument("--check-seconds", type=float, default=30.0)
    watch.set_defaults(func=_cmd_watch)

    status = sub.add_parser("status", help="عرض حالة الخزنة")
    status.add_argument("--vault", required=True, type=Path)
    status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
    except Exception as error:  # نعرض رسالة واضحة بدل تفاصيل تقنية
        print(f"خطأ: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
