#!/usr/bin/env python3
"""
التطبيق: مراسلة آمنة بنقل آلي
==============================
يجمع كل الطبقات في برنامج واحد يعمل باستمرار:

  - يستورد مفتاح الخزنة وحده من مجلد النقل عند كل تغيير سري.
  - يشغّل "الحافلة": حزمة كل 5 دقائق في المتوسط (حقيقية أو وهمية)، تُرسل
    آليًا إلى صندوق الطرف الآخر على خادم الترحيل (relay_server.py).
  - يتفقّد صندوقه بانتظام، ويفتح ما يصل.
  - يعرض واجهة محادثة في المتصفح على هذا الجهاز فقط (127.0.0.1).

رقم صندوق البريد سري ويتغيّر مع كل فترة: يُشتق من مفتاح الفترة، فيحسبه
الطرفان وحدهما، ولا يستطيع الخادم ربط فترة بأخرى.

الرسائل تُحفظ في الذاكرة فقط: تختفي عند إغلاق التطبيق (فلا يجد سارق الجهاز
سجلًا مقروءًا على القرص).

التشغيل (مثال):
  python messenger.py --node ahmed_node.json --keys-from /media/usb \\
      --relay https://relay.example.org --name أحمد
"""
from __future__ import annotations

import argparse
import hmac
import json
import secrets
import ssl
import sys
import threading
import urllib.request
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from bus import MAX_GAP, MIN_GAP, Bus, Departure
from common import one_way, use_utf8_console, utc_now
from online_node import (
    MAX_TEXT_BYTES,
    EpochState,
    KeyUnavailable,
    MessageRejected,
    NodeError,
    OnlineNode,
)

HERE = Path(__file__).resolve().parent
MAX_LOG = 1000
MAX_OUTBOX = 2000


def mailbox_for(state: EpochState, role: str) -> str:
    """رقم صندوق بريد الطرف role في هذه الفترة: سري، ويتغيّر مع كل تغيير سري."""
    return one_way(state.hs_key, b"mailbox:" + role.encode("ascii"))[:16].hex()


class RelayClient:
    """يتحدث مع خادم الترحيل."""

    def __init__(self, base_url: str, timeout: float = 10.0, cafile: str | None = None):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.context = (ssl.create_default_context(cafile=cafile)
                        if self.base.startswith("https://") else None)

    def put(self, box: str, packet: str) -> None:
        request = urllib.request.Request(
            f"{self.base}/box/{box}", data=packet.encode("ascii"), method="POST",
            headers={"Content-Type": "text/plain"})
        with urllib.request.urlopen(request, timeout=self.timeout, context=self.context):
            pass

    def take(self, box: str) -> list[str]:
        with urllib.request.urlopen(f"{self.base}/box/{box}", timeout=self.timeout,
                                    context=self.context) as response:
            return list(json.loads(response.read())["packets"])


class Messenger:
    """قلب التطبيق: الحافلة + صناديق البريد + استيراد المفاتيح."""

    def __init__(self, node_path: Path, keys_dir: Path, relay: RelayClient, *, name: str = "",
                 min_gap: timedelta = MIN_GAP, max_gap: timedelta = MAX_GAP,
                 poll_every: timedelta = timedelta(seconds=20), now: datetime | None = None):
        now = now or utc_now()
        self.node = OnlineNode.open(node_path)
        self.keys_dir = Path(keys_dir)
        self.relay = relay
        self.name = name
        self.poll_every = poll_every
        self.bus = Bus.start(self.node, now, min_gap, max_gap)
        self.next_poll = now
        self.lock = threading.RLock()
        self.outbox: list[tuple[str, str]] = []      # حزم لم تصل إلى الخادم بعد (انقطاع)
        self.log: list[dict] = []
        self.next_id = 1
        self.stats = {"packets_out": 0, "packets_in": 0, "dummies_in": 0, "unopened": 0}
        self.relay_ok: bool | None = None
        self.last_peer_box: str | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------------ #
    def note(self, who: str, text: str, moment: datetime) -> None:
        self.log.append({"id": self.next_id, "who": who, "text": text,
                         "time": moment.astimezone().strftime("%H:%M:%S")})
        self.next_id += 1
        del self.log[:-MAX_LOG]

    def _error_once(self, text: str, now: datetime) -> None:
        if text != self.last_error:
            self.last_error = text
            self.note("system", text, now)

    def enqueue(self, text: str) -> None:
        with self.lock:
            self.bus.enqueue(text, utc_now())

    # ------------------------------------------------------------------ #
    def step(self, now: datetime | None = None) -> None:
        """دورة واحدة: استيراد المفاتيح، وإطلاق الحافلات، وتفقّد الصندوق."""
        now = now or utc_now()
        with self.lock:
            self._import_keys(now)
            for departure in self.bus.departures_until(now):
                self._load(departure)
            outgoing = list(self.outbox)
            boxes: list[str] = []
            if now >= self.next_poll:
                self.next_poll = now + self.poll_every
                if self.node.role:
                    boxes = [mailbox_for(s, self.node.role) for s in self.node.epochs.values()]
        sent = self._ship(outgoing)                 # الشبكة خارج القفل: الواجهة لا تتجمد
        fetched = self._fetch(boxes)
        with self.lock:
            del self.outbox[:sent]
            self.stats["packets_out"] += sent
            for packet in fetched:
                self._receive(packet, now)

    def _import_keys(self, now: datetime) -> None:
        if not self.keys_dir.is_dir() or not any(self.keys_dir.glob("key_epoch_*.json")):
            return
        try:
            epochs = self.node.import_from_folder(self.keys_dir, now)
        except (NodeError, ValueError, KeyError, OSError) as error:
            self._error_once(f"تعذّر استيراد مفتاح الخزنة: {error}", now)
            return
        self.note("system", f"وصل مفتاح الخزنة للفترة {epochs[-1]} (تغيير سري للمفاتيح). "
                            "المصافحة الهجينة تركب الحافلات التالية.", now)

    def _load(self, departure: Departure) -> None:
        """نضع الحزمة في طريقها إلى صندوق الطرف الآخر."""
        try:
            _, state = self.node.current_state(departure.time)
            box = mailbox_for(state, self.node.peer_role)
        except KeyUnavailable:
            box = self.last_peer_box          # ضجيج: يذهب إلى آخر صندوق معروف
        if box is None:
            return                            # لم يصل أي مفتاح بعد: لا يوجد صندوق نرسل إليه
        self.last_peer_box = box
        self.outbox.append((box, departure.packet))
        del self.outbox[:-MAX_OUTBOX]
        for text in departure.texts:
            self.note("me", text, departure.time)

    def _ship(self, outgoing: list[tuple[str, str]]) -> int:
        sent = 0
        for box, packet in outgoing:
            try:
                self.relay.put(box, packet)
            except OSError:
                self.relay_ok = False
                break
            sent += 1
            self.relay_ok = True
        return sent

    def _fetch(self, boxes: list[str]) -> list[str]:
        packets: list[str] = []
        for box in boxes:
            try:
                packets.extend(self.relay.take(box))
                self.relay_ok = True
            except (OSError, ValueError, KeyError):
                self.relay_ok = False
        return packets

    def _receive(self, packet: str, now: datetime) -> None:
        try:
            result = self.node.receive(packet, now)
        except NodeError:
            self.stats["unopened"] += 1       # ضجيج، أو مصافحة قبل الاستيراد (ستُعاد)
            return
        self.stats["packets_in"] += 1
        if result.kind == "message":
            for text in result.texts:
                self.note("peer", text, now)
        elif result.kind == "dummy":
            self.stats["dummies_in"] += 1
        elif not result.duplicate and not result.waiting:
            fp = self.node.epochs[result.epoch].key_fp
            self.note("system", f"اكتملت المصافحة الهجينة للفترة {result.epoch}. بصمة المفتاح: {fp}",
                      now)

    # ------------------------------------------------------------------ #
    def snapshot(self, after_id: int = 0, now: datetime | None = None) -> dict:
        with self.lock:
            now = now or utc_now()
            try:
                epoch, state = self.node.current_state(now)
            except KeyUnavailable:
                epoch, state = None, None
            return {
                "name": self.name,
                "role": self.node.role,
                "epoch": epoch,
                "ready": bool(state and state.ready),
                "confirmed": bool(state and state.peer_confirmed),
                "fingerprint": state.key_fp if state else None,
                "next_bus": max(0.0, (self.bus.next_departure - now).total_seconds()),
                "queue": [text for _, text in self.bus.queue],
                "relay_ok": self.relay_ok,
                "stats": dict(self.stats),
                "messages": [m for m in self.log if m["id"] > after_id],
                "max_text": MAX_TEXT_BYTES,
            }

    def run_forever(self, stop: threading.Event, tick: float = 0.25) -> None:
        while not stop.is_set():
            try:
                self.step()
            except Exception as error:   # لا نريد أن يتوقف التطبيق بصمت
                with self.lock:
                    self._error_once(f"خطأ غير متوقع: {error}", utc_now())
            stop.wait(tick)


# ---------------------------------------------------------------------- #
# الواجهة المحلية (المتصفح)
# ---------------------------------------------------------------------- #
def make_ui_server(messenger: Messenger, port: int) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(24)
    page = (HERE / "messenger_ui.html").read_text(encoding="utf-8").replace("__TOKEN__", token)

    class UIHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:   # noqa: A002
            pass

        def _allowed(self, api: bool) -> bool:
            # نقبل فقط طلبات هذا الجهاز (حماية من مواقع خبيثة ومن "إعادة ربط DNS")
            port_now = self.server.server_address[1]
            if self.headers.get("Host") not in (f"127.0.0.1:{port_now}", f"localhost:{port_now}"):
                return False
            return not api or hmac.compare_digest(self.headers.get("X-Token", ""), token)

        def _send(self, status: int, body: bytes, kind: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; "
                             "style-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data: dict) -> None:
            self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self) -> None:   # noqa: N802
            url = urlparse(self.path)
            if url.path == "/":
                if not self._allowed(api=False):
                    return self._send(403, b"forbidden", "text/plain")
                return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            if url.path == "/api/state":
                if not self._allowed(api=True):
                    return self._json(403, {"error": "forbidden"})
                try:
                    after = int(parse_qs(url.query).get("after", ["0"])[0])
                except ValueError:
                    after = 0
                return self._json(200, messenger.snapshot(after))
            self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:   # noqa: N802
            if urlparse(self.path).path != "/api/send":
                return self._send(404, b"not found", "text/plain")
            if not self._allowed(api=True):
                return self._json(403, {"ok": False, "error": "forbidden"})
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 64 * 1024)
                text = json.loads(self.rfile.read(length))["text"]
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("الرسالة فارغة")
                messenger.enqueue(text)
            except (ValueError, KeyError, TypeError, NodeError) as error:
                return self._json(400, {"ok": False, "error": str(error)})
            self._json(200, {"ok": True})

    server = ThreadingHTTPServer(("127.0.0.1", port), UIHandler)
    server.daemon_threads = True
    return server, token


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="تطبيق المراسلة الآمنة بنقل آلي")
    parser.add_argument("--node", required=True, type=Path, help="ملف النظام المتصل")
    parser.add_argument("--keys-from", required=True, type=Path,
                        help="مجلد النقل الذي تكتب فيه الخزنة مفاتيحها")
    parser.add_argument("--relay", required=True, help="عنوان خادم الترحيل")
    parser.add_argument("--relay-ca", help="شهادة الخادم إذا كانت ذاتية التوقيع")
    parser.add_argument("--port", type=int, default=8001, help="منفذ الواجهة على هذا الجهاز")
    parser.add_argument("--name", default="", help="اسمك (للعرض فقط)")
    parser.add_argument("--fast", action="store_true",
                        help="وضع التجربة: حافلة كل 3 إلى 8 ثوانٍ وتفقّد الصندوق كل ثانية")
    parser.add_argument("--bus-min-seconds", type=float)
    parser.add_argument("--bus-max-seconds", type=float)
    parser.add_argument("--poll-seconds", type=float)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)

    min_gap, max_gap, poll = MIN_GAP, MAX_GAP, timedelta(seconds=20)
    if args.fast:
        min_gap, max_gap, poll = timedelta(seconds=3), timedelta(seconds=8), timedelta(seconds=1)
    if args.bus_min_seconds:
        min_gap = timedelta(seconds=args.bus_min_seconds)
    if args.bus_max_seconds:
        max_gap = timedelta(seconds=args.bus_max_seconds)
    if args.poll_seconds:
        poll = timedelta(seconds=args.poll_seconds)

    try:
        messenger = Messenger(args.node, args.keys_from, RelayClient(args.relay, cafile=args.relay_ca),
                              name=args.name, min_gap=min_gap, max_gap=max_gap, poll_every=poll)
        server, _ = make_ui_server(messenger, args.port)
    except (NodeError, ValueError, OSError) as error:
        print(f"خطأ: {error}", file=sys.stderr)
        return 1

    stop = threading.Event()
    worker = threading.Thread(target=messenger.run_forever, args=(stop,), daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{args.port}/"
    print(f"التطبيق يعمل{(' — ' + args.name) if args.name else ''}. افتح: {url}  (Ctrl+C للإيقاف)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
