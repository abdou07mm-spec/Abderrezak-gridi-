#!/usr/bin/env python3
"""
التطبيق المثبّت: جهة أونلاين وجهة أوفلاين على الجهاز نفسه
==========================================================
بعد التثبيت والاقتران يكون في الجهاز جهتان مستقلتان، تعملان وحدهما:

  الجهة الأوفلاين (vault_service.py):
    - تبدأ فورًا، بلا شبكة وبلا أي إذن.
    - تغيّر المفاتيح في مواعيد سرية عشوائية (بين حدّين)، حسب ساعة الجهاز.
    - تكتب كل مفتاح جديد في "مجلد التسليم"، ولا تقرأ شيئًا من الجهة الأونلاين.
    - في لينكس يعزلها نظام التشغيل نفسه عن الشبكة؛ وفي غيره تمنع نفسها برمجيًا.

  الجهة الأونلاين (messenger.py):
    - تأخذ المفاتيح من مجلد التسليم وحدها، وتشغّل الحافلة، وتعرض المحادثة.

خطوة واحدة لا يمكن حذفها: الاقتران مرة واحدة مع الطرف الآخر، برمز يُكتب باليد
(لا أحد يستطيع مشاركة سرّ مع شخص دون أن يتبادلا شيئًا ولو مرة).

الأوامر:
  python secure_app.py create --home ahmed                  # ينشئ الاقتران ويعرض الرمز
  python secure_app.py join   --home sara --code "XXXX-..."  # الطرف الآخر يكتب الرمز
  python secure_app.py start  --home ahmed --relay https://relay.example.org --name أحمد
"""
from __future__ import annotations

import argparse
import shutil
import signal
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from common import read_json, stamp, to_utc, use_utf8_console, utc_now
from offline_vault import (
    DEFAULT_MAX_HOURS,
    DEFAULT_MIN_HOURS,
    OfflineVault,
    VaultError,
    decode_pairing_code,
    encode_pairing_code,
    make_seed,
    schedule_seconds,
)

HERE = Path(__file__).resolve().parent


def layout(home: Path) -> tuple[Path, Path, Path]:
    """(ملف الخزنة الأوفلاين، ملف الجهة الأونلاين، مجلد التسليم)"""
    home = Path(home)
    return home / "offline" / "vault.json", home / "online" / "node.json", home / "drop"


# ---------------------------------------------------------------------- #
# الاقتران (مرة واحدة)
# ---------------------------------------------------------------------- #
def create(home: Path, min_hours: float = DEFAULT_MIN_HOURS, max_hours: float = DEFAULT_MAX_HOURS,
           dice: str | None = None, now: datetime | None = None) -> tuple[str, OfflineVault]:
    """ينشئ خزنة الطرف الأول، ويعيد رمز الاقتران الذي يُعطى للطرف الثاني."""
    vault_path, _, _ = layout(home)
    min_seconds, max_seconds = schedule_seconds(min_hours, max_hours)
    seed = make_seed(dice=dice)
    epoch_start = to_utc(now or utc_now()).replace(second=0, microsecond=0)
    vault = OfflineVault.from_seed(vault_path, seed, "A", epoch_start, min_seconds, max_seconds)
    return encode_pairing_code(seed, epoch_start, min_seconds, max_seconds), vault


def join(home: Path, code: str) -> OfflineVault:
    """ينشئ خزنة الطرف الثاني من الرمز الذي كتبه."""
    vault_path, _, _ = layout(home)
    seed, epoch_start, min_seconds, max_seconds = decode_pairing_code(code)
    return OfflineVault.from_seed(vault_path, seed, "B", epoch_start, min_seconds, max_seconds)


# ---------------------------------------------------------------------- #
# التشغيل
# ---------------------------------------------------------------------- #
def system_isolation_available() -> bool:
    """هل يستطيع نظام التشغيل عزل برنامج عن الشبكة دون صلاحيات المدير؟ (لينكس)"""
    if not sys.platform.startswith("linux") or not shutil.which("unshare"):
        return False
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True,
                              timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def offline_command(vault_path: Path, drop: Path, check_seconds: float) -> list[str]:
    command = [sys.executable, str(HERE / "vault_service.py"), "--vault", str(vault_path),
               "--drop", str(drop), "--check-seconds", str(check_seconds)]
    # "unshare -rn": فضاء شبكة جديد فارغ، لا يحتوي أي اتصال بالخارج
    return (["unshare", "-rn"] + command) if system_isolation_available() else command


def start(home: Path, relay: str, name: str = "", port: int = 8001, fast: bool = False,
          browser: bool = True, relay_ca: str | None = None) -> int:
    vault_path, node_path, drop = layout(home)
    if not vault_path.exists():
        print("خطأ: لا توجد خزنة بعد. نفّذ create (أنت) أو join (الطرف الآخر) أولًا.",
              file=sys.stderr)
        return 1
    drop.mkdir(parents=True, exist_ok=True)
    node_path.parent.mkdir(parents=True, exist_ok=True)

    online = [sys.executable, str(HERE / "messenger.py"), "--node", str(node_path),
              "--keys-from", str(drop), "--relay", relay, "--port", str(port), "--no-browser"]
    if name:
        online += ["--name", name]
    if fast:
        online.append("--fast")
    if relay_ca:
        online += ["--relay-ca", relay_ca]

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    processes: list[subprocess.Popen] = []
    logs = []
    try:
        for command, log_path in (
            (offline_command(vault_path, drop, 1.0 if fast else 30.0), vault_path.parent / "service.log"),
            (online, node_path.parent / "app.log"),
        ):
            log = open(log_path, "w", encoding="utf-8")
            logs.append(log)
            processes.append(subprocess.Popen(command, cwd=HERE, stdout=log, stderr=subprocess.STDOUT))
        time.sleep(1.5)
        if any(p.poll() is not None for p in processes):
            print(f"خطأ: إحدى الجهتين توقفت. انظر السجلات في {home}", file=sys.stderr)
            return 1

        isolation = "؟"
        try:
            status = read_json(drop / "vault_status.json")
            isolation = ("يفرضه نظام التشغيل ✓" if status["isolation"] == "system"
                         else "برمجي فقط ⚠")
        except (OSError, ValueError, KeyError):
            pass
        vault = OfflineVault.load(vault_path)
        print(f"التطبيق يعمل{(' — ' + name) if name else ''}:")
        print(f"  الجهة الأوفلاين: تعمل وحدها، وعزلها عن الشبكة {isolation}")
        print(f"                   بصمة الزوج {vault.pair_id}، والمفاتيح تتغيّر في مواعيد سرية")
        print(f"  الجهة الأونلاين: http://127.0.0.1:{port}/")
        print("  (Ctrl+C لإيقاف الجهتين)")
        if browser:
            webbrowser.open(f"http://127.0.0.1:{port}/")
        while all(p.poll() is None for p in processes):
            time.sleep(0.5)
        print("توقفت إحدى الجهتين؛ أُوقف الأخرى.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for log in logs:
            log.close()


# ---------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="التطبيق: جهة أونلاين وجهة أوفلاين")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create", help="إنشاء الاقتران (الطرف الأول) وعرض الرمز")
    c.add_argument("--home", required=True, type=Path, help="مجلد التطبيق على هذا الجهاز")
    c.add_argument("--min-hours", type=float, default=DEFAULT_MIN_HOURS)
    c.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS)
    c.add_argument("--dice", help="رميات نرد حقيقية لتقوية البذرة (اختياري)")

    j = sub.add_parser("join", help="الانضمام بالرمز (الطرف الثاني)")
    j.add_argument("--home", required=True, type=Path)
    j.add_argument("--code", required=True)

    s = sub.add_parser("start", help="تشغيل الجهتين")
    s.add_argument("--home", required=True, type=Path)
    s.add_argument("--relay", required=True, help="عنوان خادم الترحيل")
    s.add_argument("--relay-ca")
    s.add_argument("--name", default="")
    s.add_argument("--port", type=int, default=8001)
    s.add_argument("--fast", action="store_true", help="وضع التجربة السريع")
    s.add_argument("--no-browser", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            code, vault = create(args.home, args.min_hours, args.max_hours, args.dice)
            print("تم إنشاء الخزنة. أعطِ هذا الرمز للطرف الآخر يدًا بيد أو بصوت منخفض،")
            print("ولا ترسله أبدًا عبر أي تطبيق أو بريد: هذا الرمز هو السرّ كله.")
            print()
            print(f"    {code}")
            print()
            print(f"بصمة الزوج: {vault.pair_id}  (يجب أن تظهر نفسها عند الطرف الآخر)")
            print("الرمز لا يُحفظ في أي مكان، ولن يمكن عرضه مرة أخرى.")
        elif args.command == "join":
            vault = join(args.home, args.code)
            print(f"تم الانضمام. بصمة الزوج: {vault.pair_id}  (قارناها: يجب أن تتطابق)")
            print(f"بداية الجدول السري: {stamp(vault.epoch_start)}")
        else:
            return start(args.home, args.relay, args.name, args.port, args.fast,
                         not args.no_browser, args.relay_ca)
    except (VaultError, ValueError, OSError) as error:
        print(f"خطأ: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
