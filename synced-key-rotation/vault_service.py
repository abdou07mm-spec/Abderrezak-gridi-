#!/usr/bin/env python3
"""
الجهة الأوفلاين: تعمل وحدها
============================
تبدأ فور تشغيلها، دون أي إذن، ودون أن يسألها أحد:

  - في كل موعد سري عشوائي (من السلسلة السرية) تتقدّم إلى الفترة الجديدة،
    وتُتلف حالتها القديمة، وتكتب مفتاح الفترة في "مجلد التسليم".
  - تأخذ الوقت من ساعة الجهاز.
  - تكتب فقط ولا تقرأ أي شيء من الجهة الأونلاين: الطريق باتجاه واحد.
  - لا تتصل بالشبكة أبدًا:
      * يمنعها نظام التشغيل نفسه حين يكون ذلك متاحًا (في لينكس: تُشغَّل في
        "فضاء شبكة" فارغ لا يحتوي أي اتصال)،
      * وتمنع نفسها داخل البرنامج أيضًا: أي محاولة لفتح اتصال تفشل فورًا.
  - تكتب "نبضة" في مجلد التسليم لتعرف الجهة الأونلاين أنها تعمل، وهل عزلها
    يفرضه النظام أم برمجي فقط.

التشغيل (عادةً يشغّلها secure_app.py وحده):
  python vault_service.py --vault offline/vault.json --drop drop/
"""
from __future__ import annotations

import argparse
import signal
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from common import use_utf8_console, utc_now, write_private_json
from offline_vault import OfflineVault, export_bundle

STATUS_FILE = "vault_status.json"


def network_reachable() -> bool:
    """هل توجد شبكة يمكن الوصول إليها؟ (لا يُرسل أي شيء فعلًا.)"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def seal_off_network() -> None:
    """يمنع هذا البرنامج من فتح أي اتصال، مهما حاول أي جزء منه."""
    def refuse(*_args, **_kwargs):
        raise OSError("الجهة الأوفلاين لا تتصل بالشبكة أبدًا")
    for name in ("socket", "create_connection", "socketpair", "fromfd", "getaddrinfo",
                 "create_server"):
        if hasattr(socket, name):
            setattr(socket, name, refuse)


def tick(vault_path: Path, drop: Path, isolation: str, now: datetime | None = None) -> datetime:
    """
    دورة واحدة: إن حان موعد سري جديد يُخرج مفتاحه، ثم يكتب النبضة.
    يعيد موعد التغيير القادم.
    """
    now = now or utc_now()
    vault = OfflineVault.load(vault_path)
    bundle = vault.release_if_new(now)
    if bundle is not None:
        export_bundle(bundle, drop)
    write_private_json(drop / STATUS_FILE, {
        "isolation": isolation,
        "heartbeat": now.isoformat(),
        "pair_id": vault.pair_id,
    })
    return vault.next_change()


def run(vault_path: Path, drop: Path, check_seconds: float = 30.0) -> None:
    isolation = "software" if network_reachable() else "system"
    seal_off_network()
    drop.mkdir(parents=True, exist_ok=True)
    print("الجهة الأوفلاين تعمل. العزل: "
          + ("يفرضه نظام التشغيل ✓" if isolation == "system" else "برمجي فقط ⚠"), flush=True)
    while True:
        next_change = tick(vault_path, drop, isolation)
        wait = (next_change - utc_now()).total_seconds()
        time.sleep(max(0.5, min(check_seconds, wait)))


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="الجهة الأوفلاين: تغيّر المفاتيح وحدها في مواعيد سرية")
    parser.add_argument("--vault", required=True, type=Path)
    parser.add_argument("--drop", required=True, type=Path, help="مجلد التسليم (تكتب فيه فقط)")
    parser.add_argument("--check-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        run(args.vault, args.drop, args.check_seconds)
    except KeyboardInterrupt:
        pass
    except Exception as error:
        print(f"خطأ: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
