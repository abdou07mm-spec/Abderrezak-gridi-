#!/usr/bin/env python3
"""
مختبر العشوائية
===============
سؤال المختبر: هل "يبدو عشوائيًا" يعني "لا يمكن تتبّعه"؟

نأخذ ثلاث طرق لتوليد المفاتيح، ونطبّق عليها الاختبارات الإحصائية نفسها،
ثم نهاجمها:
  1. سلسلتنا (HMAC-SHA256 من بذرة سرية من 256 بت).
  2. مولّد بايثون العادي random (اسمه Mersenne Twister): سريع وجيد للألعاب
     والمحاكاة، لكنه غير مصمم للأسرار.
  3. محاكاة لخطأ Debian الحقيقي (2006-2008): كان السرّ الوحيد رقم العملية
     في الجهاز (PID)، أي 32,768 احتمالًا فقط.

ثم نختبر "فحص الصحة" الذي يرفض المولّد المعطوب، ونحسب قوة رميات النرد.

التشغيل:  python randomness_lab.py
"""
from __future__ import annotations

import hashlib
import math
import os
import random
import time
import zlib

from common import RandomnessFailure, secure_random, use_utf8_console
from offline_vault import derive_vault_key, dice_bits, next_chain_key

KEYS = 10_000          # عدد المفاتيح في كل اختبار (كل مفتاح 256 بت)
SECONDS_PER_YEAR = 3.156e7
UNIVERSE_AGE_YEARS = 1.38e10


# ---------------------------------------------------------------------- #
# المولّدات الثلاثة
# ---------------------------------------------------------------------- #
def our_chain() -> list[bytes]:
    chain, keys = os.urandom(32), []
    for _ in range(KEYS):
        keys.append(derive_vault_key(chain))
        chain = next_chain_key(chain)
    return keys


def mersenne(rng: random.Random) -> list[bytes]:
    return [rng.getrandbits(256).to_bytes(32, "big") for _ in range(KEYS)]


def debian_style(pid: int) -> list[bytes]:
    return [hashlib.sha256(f"{pid}:{i}".encode()).digest() for i in range(KEYS)]


# ---------------------------------------------------------------------- #
# الاختبارات الإحصائية
# ---------------------------------------------------------------------- #
def statistical_tests(keys: list[bytes]) -> tuple[bool, str]:
    """
    أربعة اختبارات معروفة. كل منها يقيس "هل يبدو عشوائيًا؟":
      - توازن الأصفار والآحاد (monobit)،
      - توزيع قيم البايتات (chi-square)،
      - التشابه بين كل مفتاح والذي يليه (يجب أن يكون 50% تمامًا كالصدفة)،
      - قابلية الضغط (البيانات العشوائية لا تنضغط).
    """
    data = b"".join(keys)
    bits = len(data) * 8
    ones = sum(bin(byte).count("1") for byte in data)
    monobit_z = (ones - bits / 2) / math.sqrt(bits / 4)

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    expected = len(data) / 256
    chi2_z = (sum((c - expected) ** 2 / expected for c in counts) - 255) / math.sqrt(510)

    differing = sum(bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")
                    for a, b in zip(keys, keys[1:]))
    similarity = 1 - differing / (256 * (len(keys) - 1))
    compression = len(zlib.compress(data, 9)) / len(data)

    passed = (abs(monobit_z) < 3 and abs(chi2_z) < 3
              and abs(similarity - 0.5) < 0.005 and compression > 0.99)
    summary = (f"توازن البتات z={monobit_z:+.2f} | توزيع البايتات z={chi2_z:+.2f} | "
               f"تشابه المتتاليات {similarity:.1%} | الضغط {compression:.3f}")
    return passed, summary


# ---------------------------------------------------------------------- #
# الهجمات
# ---------------------------------------------------------------------- #
def _untemper(value: int) -> int:
    """يعكس الخطوة الأخيرة في Mersenne Twister ليستعيد حالته الداخلية."""
    def undo_right(y: int, shift: int) -> int:
        result = y
        for _ in range(32 // shift + 1):
            result = y ^ (result >> shift)
        return result & 0xFFFFFFFF

    def undo_left(y: int, shift: int, mask: int) -> int:
        result = y
        for _ in range(32 // shift + 1):
            result = y ^ ((result << shift) & mask)
        return result & 0xFFFFFFFF

    value = undo_right(value, 18)
    value = undo_left(value, 15, 0xEFC60000)
    value = undo_left(value, 7, 0x9D2C5680)
    return undo_right(value, 11)


def attack_mersenne() -> int:
    victim = random.Random(os.urandom(16))
    observed = [victim.getrandbits(32) for _ in range(624)]        # ما يراه المخترق
    clone = random.Random()
    clone.setstate((3, tuple(_untemper(v) for v in observed) + (624,), None))
    future = [victim.getrandbits(256) for _ in range(5)]            # مفاتيح الضحية القادمة
    predicted = [clone.getrandbits(256) for _ in range(5)]          # تنبؤات المخترق
    return sum(a == b for a, b in zip(future, predicted))


def attack_debian(target: bytes) -> tuple[int, float]:
    start = time.perf_counter()
    for pid in range(1, 32769):
        if hashlib.sha256(f"{pid}:0".encode()).digest() == target:
            return pid, time.perf_counter() - start
    raise RuntimeError("لم يُعثر على السر")


def chain_speed() -> float:
    chain, count = os.urandom(32), 100_000
    start = time.perf_counter()
    for _ in range(count):
        chain = next_chain_key(chain)
    return count / (time.perf_counter() - start)


def main() -> None:
    use_utf8_console()
    print("=" * 74)
    print(f"1) الاختبارات الإحصائية على {KEYS:,} مفتاح من كل مولّد (كل مفتاح 256 بت)")
    print("=" * 74)
    secret_pid = random.SystemRandom().randint(1, 32768)
    generators = (
        ("سلسلتنا (HMAC-SHA256)", our_chain()),
        ("مولّد بايثون العادي", mersenne(random.Random(os.urandom(16)))),
        ("محاكاة خطأ Debian", debian_style(secret_pid)),
    )
    for name, keys in generators:
        passed, summary = statistical_tests(keys)
        print(f"  {name}: {'نجح ✓' if passed else 'فشل ✗'}")
        print(f"      {summary}")
    print("  ← الثلاثة تبدو عشوائية تمامًا للاختبارات.")

    print()
    print("=" * 74)
    print("2) الهجمات")
    print("=" * 74)
    hits = attack_mersenne()
    print(f"  مولّد بايثون العادي: بعد مراقبة 624 رقمًا (ما يعادل 78 مفتاحًا) استعاد المخترق")
    print(f"      حالته الداخلية، وتنبّأ بـ {hits} من 5 مفاتيح قادمة بالضبط ✗")
    pid, seconds = attack_debian(debian_style(secret_pid)[0])
    print(f"  محاكاة خطأ Debian: جرّب المخترق كل الاحتمالات (32,768) فوجد السر {pid}")
    print(f"      في {seconds:.3f} ثانية ✗")
    rate = chain_speed()
    world_rate = 1e28  # 10 مليارات جهاز × مليار مليار محاولة في الثانية لكل جهاز (تقدير خيالي)
    world_years = 2 ** 256 / world_rate / SECONDS_PER_YEAR
    print("  سلسلتنا: لا يُعرف أي طريق مختصر؛ لم يبقَ إلا تجربة كل البذور الممكنة (2^256):")
    print(f"      بهذا الجهاز ({rate:,.0f} محاولة/ثانية): "
          f"{2 ** 256 / rate / SECONDS_PER_YEAR:.1e} سنة")
    print(f"      بكل حواسيب العالم مجتمعة (تقدير خيالي): {world_years:.1e} سنة")
    print(f"      أي {world_years / UNIVERSE_AGE_YEARS:.1e} ضعف عمر الكون ✓")

    print()
    print("=" * 74)
    print("3) فحص الصحة: رفض المولّد المعطوب قبل أن يصنع مفاتيح ضعيفة")
    print("=" * 74)
    stuck_value = os.urandom(32)
    broken = (
        ("مولّد يعطي أصفارًا", lambda n: bytes(n)),
        ("مولّد عالق يكرر النتيجة نفسها (مثل عطب PlayStation 3)", lambda n: stuck_value[:n]),
        ("مولّد سليم (نظام التشغيل)", os.urandom),
    )
    for name, source in broken:
        try:
            secure_random(32, source)
            secure_random(32, source)
            print(f"  {name}: قُبل ✓")
        except RandomnessFailure as error:
            print(f"  {name}: رُفض ✗ — {error}")

    print()
    print("=" * 74)
    print("4) النرد: عشوائية فيزيائية لا يمكن لأي برنامج التلاعب بها")
    print("=" * 74)
    print(f"  رمية واحدة = {dice_bits(1):.2f} بت.  "
          f"لـ 256 بت تكفي {math.ceil(256 / dice_bits(1))} رمية.")
    for rolls in (10, 50, 99, 150):
        print(f"  {rolls:>3} رمية = {dice_bits(rolls):6.1f} بت")

    print()
    print("=" * 74)
    print("الخلاصة")
    print("=" * 74)
    print("  • الاختبارات الإحصائية تكشف العشوائية الرديئة جدًا فقط، ولا تستطيع إثبات القوة.")
    print("  • عدم القدرة على التتبع يأتي من شرطين:")
    print("      1) عشوائية حقيقية كافية في المصدر (بذرتنا 256 بت؛ خطأ Debian كان 15 بت).")
    print("      2) حساب باتجاه واحد (مولّد بايثون العادي قابل للعكس، أما HMAC فلا).")
    print("  • لذلك نمزج عدة مصادر حقيقية (جهازان + نرد)، ونفحص المولّد قبل استعماله.")


if __name__ == "__main__":
    main()
