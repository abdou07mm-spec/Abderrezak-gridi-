"""
اختبارات التطبيق: خادم الترحيل، والنقل الآلي عبر HTTP حقيقي (بوقت محاكى)،
وحماية الواجهة المحلية.
التشغيل:  python -m unittest -v
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from messenger import Messenger, RelayClient, mailbox_for, make_ui_server
from offline_vault import OfflineVault, export_bundle
from online_node import MAX_TEXT_BYTES
from relay_server import PACKET_CHARS, MailboxStore, make_server

T0 = datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc)
BOX = "0123456789abcdef0123456789abcdef"


def serve(server) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


class RecordingStore(MailboxStore):
    """صناديق تسجّل أطوال كل ما يصل، لنتحقق مما يراه الخادم."""

    def __init__(self):
        super().__init__()
        self.sizes: list[int] = []
        self.boxes: set[str] = set()

    def put(self, box: str, packet: bytes) -> bool:
        self.sizes.append(len(packet))
        self.boxes.add(box)
        return super().put(box, packet)


class FlakyRelay(RelayClient):
    """خادم يمكن "قطعه" لمحاكاة انقطاع الشبكة."""
    down = False

    def put(self, box: str, packet: str) -> None:
        if self.down:
            raise OSError("الشبكة مقطوعة")
        super().put(box, packet)

    def take(self, box: str) -> list[str]:
        if self.down:
            raise OSError("الشبكة مقطوعة")
        return super().take(box)


class RelayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = MailboxStore()
        self.server = make_server("127.0.0.1", 0, self.store)
        serve(self.server)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def post(self, path: str, body: bytes) -> int:
        request = urllib.request.Request(self.base + path, data=body, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_put_then_take_in_order_and_deleted(self) -> None:
        packets = [(chr(65 + i) * PACKET_CHARS).encode() for i in range(3)]
        for packet in packets:
            self.assertEqual(self.post(f"/box/{BOX}", packet), 204)
        client = RelayClient(self.base)
        self.assertEqual(client.take(BOX), [p.decode() for p in packets])
        self.assertEqual(client.take(BOX), [])               # أُخذت = حُذفت

    def test_rejects_wrong_size_bad_chars_and_bad_box(self) -> None:
        self.assertEqual(self.post(f"/box/{BOX}", b"A" * (PACKET_CHARS - 1)), 400)
        self.assertEqual(self.post(f"/box/{BOX}", b"!" * PACKET_CHARS), 400)
        self.assertEqual(self.post(f"/box/{BOX}", b"A" * (PACKET_CHARS - 1) + b"\n"), 400)
        self.assertEqual(self.post("/box/not-a-box", b"A" * PACKET_CHARS), 404)
        self.assertEqual(self.store.count(), 0)

    def test_old_packets_expire(self) -> None:
        store = MailboxStore(ttl=0.05)
        store.put(BOX, b"A" * PACKET_CHARS)
        time.sleep(0.1)
        self.assertEqual(store.take(BOX), [])


class TransportTest(unittest.TestCase):
    """تطبيقان حقيقيان يتراسلان عبر خادم ترحيل حقيقي (HTTP)، والوقت محاكى."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.store = RecordingStore()
        self.server = make_server("127.0.0.1", 0, self.store)
        serve(self.server)
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.vaults = OfflineVault.create_pair(tmp / "va.json", tmp / "vb.json", now=T0)
        self.usb = (tmp / "usb_a", tmp / "usb_b")
        self.relay_a = FlakyRelay(base)
        gaps = dict(min_gap=timedelta(seconds=2), max_gap=timedelta(seconds=6),
                    poll_every=timedelta(seconds=1), now=T0)
        self.a = Messenger(tmp / "na.json", self.usb[0], self.relay_a, name="A", **gaps)
        self.b = Messenger(tmp / "nb.json", self.usb[1], RelayClient(base), name="B", **gaps)
        self.changes = self.vaults[0].upcoming_changes(3)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def secret_change(self, when: datetime) -> None:
        for vault, usb in zip(self.vaults, self.usb):
            export_bundle(vault.release_key(when), usb)

    def run_for(self, start: datetime, seconds: int) -> datetime:
        now = start
        for _ in range(seconds):
            now += timedelta(seconds=1)
            self.a.step(now)
            self.b.step(now)
        return now

    @staticmethod
    def texts(messenger: Messenger, who: str) -> list[str]:
        return [m["text"] for m in messenger.log if m["who"] == who]

    def test_end_to_end_with_secret_change(self) -> None:
        start = self.changes[0]
        self.secret_change(start)
        now = self.run_for(start, 60)
        snap_a, snap_b = self.a.snapshot(now=now), self.b.snapshot(now=now)
        self.assertTrue(snap_a["ready"] and snap_a["confirmed"] and snap_b["confirmed"])
        self.assertEqual(snap_a["fingerprint"], snap_b["fingerprint"])

        self.a.enqueue("one")
        self.a.enqueue("two")
        self.b.enqueue("ثلاثة")
        now = self.run_for(now, 30)
        self.assertEqual(self.texts(self.b, "peer"), ["one", "two"])
        self.assertEqual(self.texts(self.a, "peer"), ["ثلاثة"])

        boxes_before = set(self.store.boxes)
        self.secret_change(self.changes[1])               # تغيير سري: صناديق جديدة
        now = self.run_for(self.changes[1], 60)
        self.a.enqueue("after the change")
        self.run_for(now, 30)
        self.assertEqual(self.texts(self.b, "peer")[-1], "after the change")
        self.assertNotEqual(self.store.boxes - boxes_before, set())
        epochs = self.a.node.epochs
        self.assertNotEqual(mailbox_for(epochs[1], "B"), mailbox_for(epochs[2], "B"))
        self.assertEqual(set(self.store.sizes), {PACKET_CHARS})    # الخادم يرى حزمًا متطابقة فقط

    def test_bus_keeps_running_when_idle(self) -> None:
        self.secret_change(self.changes[0])
        self.run_for(self.changes[0], 120)
        self.assertGreater(self.b.stats["dummies_in"], 10)          # حزم وهمية دون أي كتابة
        self.assertEqual(self.texts(self.b, "peer"), [])

    def test_network_outage_then_recovery(self) -> None:
        self.secret_change(self.changes[0])
        now = self.run_for(self.changes[0], 60)
        self.relay_a.down = True
        for i in range(3):
            self.a.enqueue(f"during outage {i}")
        now = self.run_for(now, 40)
        self.assertFalse(self.a.snapshot(now=now)["relay_ok"])
        self.assertTrue(self.a.outbox)                                  # الحزم تنتظر
        self.relay_a.down = False
        self.run_for(now, 30)
        self.assertEqual(self.texts(self.b, "peer"), [f"during outage {i}" for i in range(3)])


class LocalUiTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.messenger = Messenger(tmp / "n.json", tmp / "usb", RelayClient("http://127.0.0.1:9"),
                                   name="test", now=T0)
        self.server, self.token = make_ui_server(self.messenger, 0)
        serve(self.server)
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def call(self, path: str, body: dict | None = None, token: str | None = None,
             host: str | None = None) -> tuple[int, bytes]:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=None if body is None else json.dumps(body).encode(),
            method="GET" if body is None else "POST")
        if token:
            request.add_header("X-Token", token)
        if host:
            request.add_header("Host", host)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def test_page_carries_token_and_api_requires_it(self) -> None:
        status, page = self.call("/")
        self.assertEqual(status, 200)
        self.assertIn(self.token.encode(), page)
        self.assertEqual(self.call("/api/state")[0], 403)
        self.assertEqual(self.call("/api/state", token="wrong")[0], 403)
        self.assertEqual(self.call("/api/state", token=self.token)[0], 200)

    def test_foreign_host_is_rejected(self) -> None:
        self.assertEqual(self.call("/", host="evil.example")[0], 403)
        self.assertEqual(self.call("/api/state", token=self.token, host="evil.example")[0], 403)

    def test_send_enqueues_and_validates(self) -> None:
        status, body = self.call("/api/send", {"text": "مرحبا"}, token=self.token)
        self.assertEqual((status, json.loads(body)["ok"]), (200, True))
        self.assertEqual([t for _, t in self.messenger.bus.queue], ["مرحبا"])
        status, _ = self.call("/api/send", {"text": "x" * (MAX_TEXT_BYTES + 1)}, token=self.token)
        self.assertEqual(status, 400)
        self.assertEqual(self.call("/api/send", {"text": "hi"})[0], 403)


if __name__ == "__main__":
    unittest.main()


class InstalledAppTest(unittest.TestCase):
    """الجهتان بعد التثبيت: الاقتران بالرمز، والجهة الأوفلاين المستقلة، وكشف اختلاف الساعات."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pairing_code_gives_identical_vaults_and_schedule(self) -> None:
        import secure_app
        code, vault_a = secure_app.create(self.tmp / "a", min_hours=2, max_hours=10, now=T0)
        vault_b = secure_app.join(self.tmp / "b", code.lower().replace("-", " "))
        self.assertEqual(vault_a.pair_id, vault_b.pair_id)
        self.assertEqual((vault_a.role, vault_b.role), ("A", "B"))
        self.assertEqual(vault_a.upcoming_changes(5), vault_b.upcoming_changes(5))
        change = vault_a.upcoming_changes(1)[0]
        self.assertEqual(vault_a.release_key(change)["key"], vault_b.release_key(change)["key"])

    def test_pairing_code_typo_and_reuse_rejected(self) -> None:
        import secure_app
        from offline_vault import VaultError
        code, _ = secure_app.create(self.tmp / "a", now=T0)
        typo = code[:-1] + ("A" if code[-1] != "A" else "B")
        with self.assertRaises(VaultError):
            secure_app.join(self.tmp / "b", typo)
        secure_app.join(self.tmp / "b", code)
        with self.assertRaises(VaultError):                     # لا يُستبدل ملف خزنة موجود
            secure_app.join(self.tmp / "b", code)

    def test_offline_side_changes_keys_by_itself_at_secret_times(self) -> None:
        import secure_app
        import vault_service
        _, vault = secure_app.create(self.tmp / "a", min_hours=2, max_hours=10, now=T0)
        vault_path, _, drop = secure_app.layout(self.tmp / "a")
        changes = vault.upcoming_changes(3)
        released = []
        moment = T0
        while moment < changes[2] + timedelta(minutes=5):        # دورة كل 5 دقائق (وقت محاكى)
            vault_service.tick(vault_path, drop, "system", moment)
            released.extend(sorted(p.name for p in drop.glob("key_epoch_*.json")))
            for path in drop.glob("key_epoch_*.json"):
                path.unlink()                                    # الجهة الأونلاين تأخذها
            moment += timedelta(minutes=5)
        self.assertEqual(released, [f"key_epoch_{e:06d}.json" for e in range(4)])
        status = json.loads((drop / vault_service.STATUS_FILE).read_text())
        self.assertEqual(status["isolation"], "system")

    def test_offline_side_cannot_open_any_connection(self) -> None:
        import subprocess
        import sys
        code = ("import vault_service, socket\n"
                "vault_service.seal_off_network()\n"
                "try:\n    socket.socket()\n    print('OPEN')\n"
                "except OSError:\n    print('BLOCKED')\n"
                "try:\n    socket.create_connection(('127.0.0.1', 9))\n    print('OPEN')\n"
                "except OSError:\n    print('BLOCKED')\n")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             cwd=Path(__file__).parent).stdout.split()
        self.assertEqual(out, ["BLOCKED", "BLOCKED"])

    def test_clock_skew_between_devices_is_detected(self) -> None:
        from online_node import OnlineNode
        vault_a, vault_b = OfflineVault.create_pair(self.tmp / "va.json", self.tmp / "vb.json", now=T0)
        now = vault_a.upcoming_changes(1)[0] + timedelta(minutes=10)
        node_a = OnlineNode.open(self.tmp / "na.json")
        node_b = OnlineNode.open(self.tmp / "nb.json")
        node_a.import_bundle(vault_a.release_key(now), now)
        node_b.import_bundle(vault_b.release_key(now), now)
        ahead = node_b.receive(node_a.my_handshake(now + timedelta(minutes=5)), now)  # ساعة أحمد متقدّمة
        self.assertAlmostEqual(ahead.clock_skew, 300, delta=2)
        synced = node_a.receive(node_b.my_handshake(now), now)
        self.assertAlmostEqual(synced.clock_skew, 0, delta=2)
