#!/usr/bin/env python3
"""
تجربة التطبيق كاملًا على جهاز واحد، بأمر واحد
=============================================
يشغّل خمسة برامج معًا في وضع سريع:
  1. خادم الترحيل (صناديق البريد).
  2. خزنة أحمد وخزنة سارة (أوفلاين) في وضع المراقبة: تغيير سري كل 2 إلى 4 دقائق.
  3. تطبيق أحمد وتطبيق سارة: حافلة كل 3 إلى 8 ثوانٍ.

ثم يفتح صفحتين في المتصفح: واحدة لأحمد وواحدة لسارة. اكتب في إحداهما،
وانظر الرسالة تصل إلى الأخرى عبر الحافلة والخادم.

التشغيل:  python try_locally.py
(في الاستعمال الحقيقي: الحافلة كل 5 دقائق في المتوسط، والتغيير كل 2 إلى 10 ساعات.)
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

from common import use_utf8_console
from offline_vault import OfflineVault

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
    (folder / "logs").mkdir(parents=True)
    (folder / MARKER).write_text("مجلد تجربة؛ يُحذف ويُعاد إنشاؤه عند كل تشغيل.\n", encoding="utf-8")

    dice = " ".join(str(secrets.randbelow(6) + 1) for _ in range(100))   # في التجربة: نرد محاكى
    OfflineVault.create_pair(folder / "ahmed_vault.json", folder / "sara_vault.json",
                             min_hours=2 / 60, max_hours=4 / 60, dice=dice)

    relay_port, port_a, port_b = args.base_port, args.base_port + 1, args.base_port + 2
    relay = f"http://127.0.0.1:{relay_port}"
    py = sys.executable
    commands = {
        "relay": [py, "relay_server.py", "--port", str(relay_port)],
        "vault_ahmed": [py, "offline_vault.py", "watch", "--vault", str(folder / "ahmed_vault.json"),
                        "--out", str(folder / "usb_ahmed"), "--check-seconds", "2"],
        "vault_sara": [py, "offline_vault.py", "watch", "--vault", str(folder / "sara_vault.json"),
                       "--out", str(folder / "usb_sara"), "--check-seconds", "2"],
        "app_ahmed": [py, "messenger.py", "--node", str(folder / "ahmed_node.json"),
                      "--keys-from", str(folder / "usb_ahmed"), "--relay", relay,
                      "--port", str(port_a), "--name", "أحمد", "--fast", "--no-browser"],
        "app_sara": [py, "messenger.py", "--node", str(folder / "sara_node.json"),
                     "--keys-from", str(folder / "usb_sara"), "--relay", relay,
                     "--port", str(port_b), "--name", "سارة", "--fast", "--no-browser"],
    }

    # الإيقاف بأي طريقة (Ctrl+C أو إشارة من النظام) يُوقف البرامج الخمسة كلها
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    processes: list[subprocess.Popen] = []
    try:
        for name, command in commands.items():
            log = open(folder / "logs" / f"{name}.log", "w", encoding="utf-8")
            processes.append(subprocess.Popen(command, cwd=HERE, stdout=log, stderr=subprocess.STDOUT))
            if name == "relay":
                for _ in range(50):
                    try:
                        urllib.request.urlopen(f"{relay}/health", timeout=1).read()
                        break
                    except OSError:
                        time.sleep(0.1)
        time.sleep(1.0)
        for process, name in zip(processes, commands):
            if process.poll() is not None:
                print(f"خطأ: البرنامج {name} توقف. انظر {folder / 'logs' / (name + '.log')}",
                      file=sys.stderr)
                return 1

        print("كل شيء يعمل (وضع التجربة السريع):")
        print(f"  خادم الترحيل:  {relay}")
        print(f"  تطبيق أحمد:    http://127.0.0.1:{port_a}/")
        print(f"  تطبيق سارة:    http://127.0.0.1:{port_b}/")
        print("  الخزنتان تُخرجان المفاتيح في مواعيد سرية كل 2 إلى 4 دقائق.")
        print("  انتظر بضع ثوانٍ حتى تكتمل المصافحة الهجينة، ثم اكتب في إحدى الصفحتين.")
        print(f"  السجلات في: {folder / 'logs'}")
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
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    sys.exit(main())
