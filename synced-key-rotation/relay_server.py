#!/usr/bin/env python3
"""
خادم الترحيل (صندوق البريد)
============================
الهاتفان لا يستطيعان عادةً الاتصال ببعضهما مباشرة (ليس لهما عنوان ثابت،
وقد يكون أحدهما مطفأً). لذلك يضع المرسل حزمته في "صندوق بريد" على هذا
الخادم، ويأخذها المستقبل حين يتصل. هكذا يعمل Signal وغيره أيضًا.

ماذا يرى هذا الخادم؟
  - حزمًا بطول ثابت ومشفّرة بالكامل: لا يعرف محتواها ولا نوعها ولا طولها.
  - أرقام صناديق عشوائية تتغيّر مع كل تغيير سري للمفاتيح (يحسبها الطرفان من
    مفتاح الفترة)، فلا يستطيع ربط محادثة فترة بالفترة التي تليها.
  - ما لا يخفيه: عنوان الجهاز الذي يتصل به (IP) وأوقات الاتصال. لإخفائه
    يلزم المرور عبر شبكة مثل Tor.

ماذا يفعل؟
  - POST /box/<رقم الصندوق>  ← يضع حزمة واحدة في الصندوق.
  - GET  /box/<رقم الصندوق>  ← يعطي كل الحزم المنتظرة ويحذفها منه.
  - لا يسجّل شيئًا: لا عناوين، ولا أرقام صناديق، ولا أوقات.
  - يحذف أي حزمة لم تُستلم خلال 24 ساعة.

التشغيل:
  python relay_server.py --port 8000
  (على الإنترنت يجب تشغيله عبر HTTPS: --tls-cert cert.pem --tls-key key.pem)
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import use_utf8_console
from online_node import PACKET_BYTES

PACKET_CHARS = (PACKET_BYTES + 2) // 3 * 4          # طول الحزمة بعد ترميز base64
PACKET_PATTERN = re.compile(rb"\A[A-Za-z0-9_\-]+={0,2}\Z")
BOX_PATTERN = re.compile(r"\A/box/([0-9a-f]{32})\Z")
PACKET_TTL_SECONDS = 24 * 3600
MAX_PACKETS_PER_BOX = 1000
MAX_BOXES = 10_000


class MailboxStore:
    """الصناديق في الذاكرة فقط (لا شيء يُكتب على القرص)."""

    def __init__(self, ttl: float = PACKET_TTL_SECONDS):
        self.ttl = ttl
        self._boxes: dict[str, deque] = {}
        self._lock = threading.Lock()

    def put(self, box: str, packet: bytes) -> bool:
        with self._lock:
            self._expire()
            queue = self._boxes.get(box)
            if queue is None:
                if len(self._boxes) >= MAX_BOXES:
                    return False
                queue = self._boxes[box] = deque(maxlen=MAX_PACKETS_PER_BOX)
            queue.append((time.monotonic(), packet))
            return True

    def take(self, box: str) -> list[str]:
        with self._lock:
            self._expire()
            queue = self._boxes.pop(box, None)
            return [packet.decode("ascii") for _, packet in queue] if queue else []

    def count(self) -> int:
        with self._lock:
            return sum(len(q) for q in self._boxes.values())

    def _expire(self) -> None:
        limit = time.monotonic() - self.ttl
        for box in list(self._boxes):
            queue = self._boxes[box]
            while queue and queue[0][0] < limit:
                queue.popleft()
            if not queue:
                del self._boxes[box]


def make_handler(store: MailboxStore) -> type[BaseHTTPRequestHandler]:
    class RelayHandler(BaseHTTPRequestHandler):
        server_version = "relay"
        sys_version = ""

        def log_message(self, format: str, *args) -> None:   # noqa: A002
            pass   # لا نسجّل شيئًا: لا عناوين ولا صناديق ولا أوقات

        def _reply(self, status: int, body: bytes = b"", kind: str = "text/plain") -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:   # noqa: N802
            if self.path == "/health":
                return self._reply(200, b"ok")
            match = BOX_PATTERN.match(self.path)
            if not match:
                return self._reply(404)
            body = json.dumps({"packets": store.take(match.group(1))}).encode()
            self._reply(200, body, "application/json")

        def do_POST(self) -> None:   # noqa: N802
            match = BOX_PATTERN.match(self.path)
            if not match:
                return self._reply(404)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._reply(400)
            if length != PACKET_CHARS:
                return self._reply(400, b"wrong packet size")
            packet = self.rfile.read(length)
            if len(packet) != PACKET_CHARS or not PACKET_PATTERN.match(packet):
                return self._reply(400, b"not a packet")
            if not store.put(match.group(1), packet):
                return self._reply(503, b"full")
            self._reply(204)

    return RelayHandler


def make_server(host: str = "127.0.0.1", port: int = 8000, store: MailboxStore | None = None,
                tls_cert: str | None = None, tls_key: str | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(store or MailboxStore()))
    server.daemon_threads = True
    if tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main(argv: list[str] | None = None) -> int:
    use_utf8_console()
    parser = argparse.ArgumentParser(description="خادم الترحيل: صناديق بريد للحزم المشفرة")
    parser.add_argument("--host", default="127.0.0.1",
                        help="0.0.0.0 لقبول اتصالات من أجهزة أخرى (افتراضيًا: هذا الجهاز فقط)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--tls-cert", help="شهادة HTTPS (ضرورية على الإنترنت)")
    parser.add_argument("--tls-key", help="المفتاح الخاص للشهادة")
    args = parser.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        print("خطأ: يجب تحديد --tls-cert و --tls-key معًا", file=sys.stderr)
        return 1
    server = make_server(args.host, args.port, tls_cert=args.tls_cert, tls_key=args.tls_key)
    scheme = "https" if args.tls_cert else "http"
    print(f"خادم الترحيل يعمل على {scheme}://{args.host}:{args.port}  (Ctrl+C للإيقاف)")
    print("لا يسجّل أي شيء، ويحذف كل حزمة لم تُستلم خلال 24 ساعة.")
    if not args.tls_cert and args.host not in ("127.0.0.1", "localhost"):
        print("⚠ تنبيه: بدون HTTPS. مقبول داخل شبكة منزلية للتجربة، لا على الإنترنت.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
