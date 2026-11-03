#!/usr/bin/env python3
"""
تجربة التطبيق كاملًا على جهاز واحد، بأمر واحد
=============================================
يحاكي جهازين (أحمد وسارة) بالخطوات الحقيقية نفسها:
  1. أحمد ينشئ الاقتران (secure_app.py create) فيظهر الرمز.
  2. سارة تنضم بالرمز (secure_app.py join).
  3. يعمل خادم الترحيل، ثم يشغّل كل منهما تطبيقه (secure_app.py start):
     جهة أوفلاين معزولة تغيّر المفاتيح وحدها في مواعيد سرية، وجهة أونلاين.

ثم تُفتح صفحتان في المتصفح: واحدة لأحمد وواحدة لسارة.

وضع التجربة السريع: تغيير سري كل 2 إلى 4 دقائق، وحافلة كل 3 إلى 8 ثوانٍ.
(في الاستعمال الحقيقي: التغيير كل 2 إلى 10 ساعات، والحافلة كل 5 دقائق في المتوسط.)

التشغيل:  python try_locally.py
"""
from __future__ import annotations

import argparse
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

import secure_app
from common import use_utf8_console

HERE = Path(__file__).resolve().parent
MARKER = ".trial_run"


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="تجربة التطبيق كاملًا على جهاز واحد")
    parser.add_argument("--base-port", type=int, default=8000)
    parser.add_argument("--folder", type=Path, default=HERE / "trial_run")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)

    folder: Path = args.folder
    if folder.exists():
        if not (folder / MARKER).exists():
            print(f"خطأ: المجلد {folder} موجود وليس مجلد تجربة سابقة؛ لن أحذفه.", file=sys.stderr)
            return 1
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    (folder / MARKER).write_text("مجلد تجربة؛ يُحذف ويُعاد إنشاؤه عند كل تشغيل.\n", encoding="utf-8")

    # الاقتران: أحمد ينشئ، وسارة تنضم بالرمز (في الواقع: كل واحد على جهازه)
    dice = " ".join(str(secrets.randbelow(6) + 1) for _ in range(100))   # في التجربة: نرد محاكى
    code, vault = secure_app.create(folder / "ahmed", min_hours=2 / 60, max_hours=4 / 60, dice=dice)
    secure_app.join(folder / "sara", code)
    print("الاقتران (مرة واحدة):")
    print(f"  رمز أحمد لسارة: {code}")
    print(f"  بصمة الزوج: {vault.pair_id}")

    relay_port, port_a, port_b = args.base_port, args.base_port + 1, args.base_port + 2
    relay = f"http://127.0.0.1:{relay_port}"
    py = sys.executable
    commands = {
        "relay": [py, "relay_server.py", "--port", str(relay_port)],
        "ahmed": [py, "secure_app.py", "start", "--home", str(folder / "ahmed"), "--relay", relay,
                  "--port", str(port_a), "--name", "أحمد", "--fast", "--no-browser"],
        "sara": [py, "secure_app.py", "start", "--home", str(folder / "sara"), "--relay", relay,
                 "--port", str(port_b), "--name", "سارة", "--fast", "--no-browser"],
    }

    # الإيقاف بأي طريقة (Ctrl+C أو إشارة من النظام) يُوقف كل البرامج
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    processes: list[subprocess.Popen] = []
    logs = []
    try:
        for name, command in commands.items():
            log = open(folder / f"{name}.log", "w", encoding="utf-8")
            logs.append(log)
            processes.append(subprocess.Popen(command, cwd=HERE, stdout=log, stderr=subprocess.STDOUT))
            if name == "relay":
                for _ in range(50):
                    try:
                        urllib.request.urlopen(f"{relay}/health", timeout=1).read()
                        break
                    except OSError:
                        time.sleep(0.1)
        time.sleep(3.0)
        for process, name in zip(processes, commands):
            if process.poll() is not None:
                print(f"خطأ: {name} توقف. انظر {folder / (name + '.log')}", file=sys.stderr)
                return 1

        print("كل شيء يعمل (وضع التجربة السريع):")
        print(f"  خادم الترحيل:  {relay}")
        print(f"  أحمد:          http://127.0.0.1:{port_a}/")
        print(f"  سارة:          http://127.0.0.1:{port_b}/")
        print("  لكل منهما جهة أوفلاين معزولة تغيّر المفاتيح وحدها كل 2 إلى 4 دقائق (مواعيد سرية).")
        print("  انتظر بضع ثوانٍ حتى تكتمل المصافحة الهجينة، ثم اكتب في إحدى الصفحتين.")
        print(f"  السجلات في: {folder}")
        print("  (Ctrl+C لإيقاف كل شيء)")
        if not args.no_browser:
            webbrowser.open(f"http://127.0.0.1:{port_a}/")
            webbrowser.open(f"http://127.0.0.1:{port_b}/")
        while all(p.poll() is None for p in processes):
            time.sleep(0.5)
        print("توقف أحد البرامج؛ أُوقف الباقي.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nإيقاف...")
        return 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
        for log in logs:
            log.close()


if __name__ == "__main__":
    sys.exit(main())
