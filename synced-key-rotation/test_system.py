"""
اختبارات آلية للتأكد من أن النظام يتصرف كما هو متوقع.
التشغيل:  python -m unittest -v
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import online_node
from common import FORMAT_VERSION, RandomnessFailure, secure_random
from offline_vault import OfflineVault, VaultError, dice_bits, export_bundle, parse_dice
from online_node import (
    BODY_OFFSET,
    HEADER,
    MAX_TEXT_BYTES,
    NONCE_BYTES,
    HandshakePending,
    KeyUnavailable,
    MessageRejected,
    NodeError,
    OnlineNode,
    ReplayRejected,
    chain_message_key,
    decode_packet,
    derive_epoch,
    layer_keys,
    read_handshake,
)

T0 = datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc)


def later(moment: datetime, minutes: int) -> datetime:
    return moment + timedelta(minutes=minutes)


def flip(packet: str, index: int) -> str:
    raw = bytearray(packet.encode())
    raw[index] = ord("A") if raw[index] != ord("A") else ord("B")
    return raw.decode()


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.vault_a, self.vault_b = OfflineVault.create_pair(
            self.tmp / "a" / "vault.json", self.tmp / "b" / "vault.json",
            min_hours=2, max_hours=10, now=T0)
        self.node_a = OnlineNode.open(self.tmp / "a" / "node.json")
        self.node_b = OnlineNode.open(self.tmp / "b" / "node.json")
        self.changes = self.vault_a.upcoming_changes(8)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def import_both(self, now: datetime) -> None:
        self.node_a.import_bundle(self.vault_a.release_key(now), now)
        self.node_b.import_bundle(self.vault_b.release_key(now), now)

    def change(self, index: int) -> datetime:
        """تغيير كامل عند الموعد السري رقم index: استيراد + مصافحة."""
        now = self.changes[index]
        self.import_both(now)
        self.node_b.receive(self.node_a.my_handshake(now), now)
        self.node_a.receive(self.node_b.my_handshake(now), now)
        return now


class VaultTest(Base):
    def test_both_vaults_compute_same_secret_schedule(self) -> None:
        self.assertEqual(self.changes, self.vault_b.upcoming_changes(8))

    def test_schedule_is_irregular_and_within_bounds(self) -> None:
        gaps = [(b - a).total_seconds() for a, b in zip([T0] + self.changes, self.changes)]
        self.assertTrue(all(2 * 3600 <= gap <= 10 * 3600 for gap in gaps))
        self.assertGreater(len(set(gaps)), 1)
        self.assertGreater(len({c.second for c in self.changes} | {c.minute for c in self.changes}), 1)

    def test_different_pairs_have_different_schedules(self) -> None:
        other, _ = OfflineVault.create_pair(self.tmp / "x.json", self.tmp / "y.json", now=T0)
        self.assertNotEqual(other.upcoming_changes(3), self.changes[:3])

    def test_vaults_release_same_key_and_validity(self) -> None:
        for change in self.changes[:3]:
            a = self.vault_a.release_key(later(change, 1))
            b = self.vault_b.release_key(later(change, 1))
            self.assertEqual((a["key"], a["valid_from"], a["valid_until"]),
                             (b["key"], b["valid_from"], b["valid_until"]))
            self.assertEqual(a["valid_from"], change.isoformat())

    def test_release_if_new_only_releases_once_per_period(self) -> None:
        self.assertIsNotNone(self.vault_a.release_if_new(self.changes[0]))
        self.assertIsNone(self.vault_a.release_if_new(later(self.changes[0], 30)))
        self.assertIsNotNone(self.vault_a.release_if_new(self.changes[1]))

    def test_vault_cannot_go_back_in_time(self) -> None:
        self.vault_a.release_key(self.changes[3])
        with self.assertRaises(VaultError):
            self.vault_a.release_key(self.changes[1])
        with self.assertRaises(VaultError):
            OfflineVault.load(self.vault_a.path).release_key(later(self.changes[0], 5))

    def test_pairing_never_overwrites_existing_vault(self) -> None:
        with self.assertRaises(VaultError):
            OfflineVault.create_pair(self.vault_a.path, self.tmp / "new.json")

    def test_pair_gets_two_distinct_roles(self) -> None:
        self.assertEqual((self.vault_a.role, self.vault_b.role), ("A", "B"))

    def test_every_entropy_source_changes_the_seed(self) -> None:
        fixed = mock.patch("offline_vault.secure_random", return_value=b"\x07" * 32)
        seeds = set()
        with fixed:
            for i, (peer, dice) in enumerate([(None, None), (b"p" * 32, None),
                                              (None, "1 2 3"), (b"p" * 32, "1 2 3")]):
                vault, _ = OfflineVault.create_pair(
                    self.tmp / f"s{i}a.json", self.tmp / f"s{i}b.json",
                    peer_randomness=peer, dice=dice, now=T0)
                seeds.add(vault.chain_key)
        self.assertEqual(len(seeds), 4)

    def test_dice_parsing(self) -> None:
        self.assertEqual(parse_dice("1 6, 3،4\n2-5"), [1, 6, 3, 4, 2, 5])
        with self.assertRaises(VaultError):
            parse_dice("1 2 7")
        self.assertGreaterEqual(dice_bits(100), 256)


class RandomnessTest(unittest.TestCase):
    def test_health_check_rejects_broken_generators(self) -> None:
        with self.assertRaises(RandomnessFailure):
            secure_random(32, lambda n: bytes(n))
        stuck = os.urandom(32)
        secure_random(32, lambda n: stuck)
        with self.assertRaises(RandomnessFailure):
            secure_random(32, lambda n: stuck)
        with self.assertRaises(RandomnessFailure):
            secure_random(32, lambda n: b"short")

    def test_health_check_accepts_real_randomness(self) -> None:
        self.assertEqual(len({secure_random(32) for _ in range(200)}), 200)


class HandshakeTest(Base):
    def test_handshake_gives_same_key_on_both_sides(self) -> None:
        now = self.change(0)
        self.assertIsNotNone(self.node_a.key_fingerprint(now))
        self.assertEqual(self.node_a.key_fingerprint(now), self.node_b.key_fingerprint(now))

    def test_fresh_randomness_every_change(self) -> None:
        fingerprints = set()
        for index in range(4):
            fingerprints.add(self.node_a.key_fingerprint(self.change(index)))
        self.assertEqual(len(fingerprints), 4)

    def test_same_vault_key_new_handshake_gives_new_key(self) -> None:
        now = self.changes[0]
        bundle_a, bundle_b = self.vault_a.release_key(now), self.vault_b.release_key(now)
        fingerprints = []
        for run in range(2):
            na = OnlineNode.open(self.tmp / f"r{run}" / "a.json")
            nb = OnlineNode.open(self.tmp / f"r{run}" / "b.json")
            na.import_bundle(bundle_a, now)
            nb.import_bundle(bundle_b, now)
            nb.receive(na.my_handshake(now), now)
            na.receive(nb.my_handshake(now), now)
            fingerprints.append(na.key_fingerprint(now))
        self.assertNotEqual(fingerprints[0], fingerprints[1])

    def test_cannot_send_before_handshake_completes(self) -> None:
        self.import_both(self.changes[0])
        with self.assertRaises(HandshakePending):
            self.node_a.send("hello", later(self.changes[0], 1))

    def test_forged_handshake_is_rejected(self) -> None:
        now = self.changes[0]
        self.import_both(now)
        fake, _ = OfflineVault.create_pair(self.tmp / "f1.json", self.tmp / "f2.json", now=T0)
        forger = OnlineNode.open(self.tmp / "forger.json")
        forger.import_bundle(fake.release_key(now), now)
        with self.assertRaises(MessageRejected):
            self.node_b.receive(forger.my_handshake(now), now)

    def test_reflected_handshake_is_rejected(self) -> None:
        now = self.changes[0]
        self.import_both(now)
        with self.assertRaises(MessageRejected):
            self.node_a.receive(self.node_a.my_handshake(now), now)

    def test_duplicate_harmless_conflicting_rejected(self) -> None:
        now = self.change(0)
        fp = self.node_b.key_fingerprint(now)
        result = self.node_b.receive(self.node_a.my_handshake(now), now)
        self.assertTrue(result.duplicate)
        self.assertEqual(self.node_b.key_fingerprint(now), fp)
        other = OnlineNode.open(self.tmp / "other.json")
        other.import_bundle(OfflineVault.load(self.vault_a.path).release_key(now), now)
        with self.assertRaises(MessageRejected):
            self.node_b.receive(other.my_handshake(now), now)

    def test_handshake_before_vault_import_waits(self) -> None:
        now = self.changes[0]
        self.node_a.import_bundle(self.vault_a.release_key(now), now)
        self.node_b.import_bundle(self.vault_b.release_key(T0), T0)
        with self.assertRaises(MessageRejected):
            self.node_b.receive(self.node_a.my_handshake(now), now)
        self.node_b.import_bundle(self.vault_b.release_key(later(now, 30)), later(now, 30))
        self.node_b.receive(self.node_a.my_handshake(now), later(now, 30))
        self.node_a.receive(self.node_b.my_handshake(now), later(now, 30))
        packet = self.node_a.send("ok", later(now, 31))
        self.assertEqual(self.node_b.receive(packet, later(now, 31)).text, "ok")

    def test_secrets_are_wiped_after_handshake(self) -> None:
        self.change(0)
        state = OnlineNode.open(self.node_a.path).epochs[1]
        self.assertIsNone(state.vault_key)
        self.assertIsNone(state.my_private)
        stored = self.node_a.path.read_text()
        self.assertNotIn("epoch_key", stored)

    def test_stolen_vault_cannot_read_after_next_handshake(self) -> None:
        """
        أقوى مخترق صامت: يملك الخزنة المسروقة (أي مفتاح الخزنة الصحيح)، ويفتح
        المصافحتين المسجّلتين فيحصل على النصفين العامين الحقيقيين. ينقصه فقط
        المفتاح الخاص الذي وُلد بعد السرقة.
        """
        self.change(0)
        stolen = self.tmp / "thief_vault.json"
        shutil.copy(self.vault_a.path, stolen)
        now = self.changes[1]
        self.import_both(now)
        hs_a, hs_b = self.node_a.my_handshake(now), self.node_b.my_handshake(now)
        real_shared = X25519PrivateKey.from_private_bytes(self.node_a.epochs[2].my_private).exchange(
            X25519PublicKey.from_public_bytes(self.node_b.epochs[2].my_public))
        self.node_b.receive(hs_a, now)
        self.node_a.receive(hs_b, now)
        real_fp = self.node_b.key_fingerprint(now)
        packet = self.node_a.send("after the theft", later(now, 5))

        vault_key = bytes.fromhex(OfflineVault.load(stolen).release_key(now)["key"])
        epoch, role_a, pub_a = read_handshake(vault_key, hs_a)
        _, role_b, pub_b = read_handshake(vault_key, hs_b)
        self.assertEqual((epoch, role_a, role_b), (2, "A", "B"))
        # البناء فعلًا يعتمد على سرّ Diffie-Hellman: بالسرّ الحقيقي نحصل على المفتاح نفسه...
        self.assertEqual(derive_epoch(vault_key, epoch, real_shared, pub_a, pub_b).fingerprint,
                         real_fp)
        # ...ودونه تفشل كل محاولات المخترق
        own_guess = X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(pub_b))
        for guess in (bytes(32), own_guess, pub_a, pub_b, vault_key):
            self.assertNotEqual(derive_epoch(vault_key, epoch, guess, pub_a, pub_b).fingerprint,
                                real_fp)
        self.assertEqual(self.node_b.receive(packet, later(now, 5)).text, "after the theft")


class MessageTest(Base):
    def setUp(self) -> None:
        super().setUp()
        self.now = self.change(0)

    def test_round_trip_both_directions(self) -> None:
        packet = self.node_a.send("مرحبا 👋", later(self.now, 1))
        self.assertEqual(self.node_b.receive(packet, later(self.now, 2)).text, "مرحبا 👋")
        reply = self.node_b.send("أهلًا", later(self.now, 3))
        self.assertEqual(self.node_a.receive(reply, later(self.now, 4)).text, "أهلًا")

    def test_all_packets_have_identical_size(self) -> None:
        sizes = {
            len(self.node_a.my_handshake(self.now)),
            len(self.node_a.send("", later(self.now, 1))),
            len(self.node_a.send("hi", later(self.now, 1))),
            len(self.node_a.send("x" * MAX_TEXT_BYTES, later(self.now, 1))),
        }
        self.assertEqual(len(sizes), 1)
        with self.assertRaises(NodeError):
            self.node_a.send("x" * (MAX_TEXT_BYTES + 1), later(self.now, 1))

    def test_out_of_order_delivery(self) -> None:
        packets = [self.node_a.send(f"m{i}", later(self.now, 1)) for i in range(4)]
        for i in (2, 0, 3, 1):
            self.assertEqual(self.node_b.receive(packets[i], later(self.now, 2)).text, f"m{i}")
        for packet in packets:                               # كل المفاتيح أُتلفت بعد القراءة
            with self.assertRaises(ReplayRejected):
                self.node_b.receive(packet, later(self.now, 3))

    def test_replay_is_rejected(self) -> None:
        packet = self.node_a.send("once", later(self.now, 1))
        self.node_b.receive(packet, later(self.now, 2))
        with self.assertRaises(ReplayRejected):
            self.node_b.receive(packet, later(self.now, 3))

    def test_stolen_device_cannot_read_already_read_messages(self) -> None:
        packets = [self.node_a.send(f"m{i}", later(self.now, 1)) for i in range(3)]
        for packet in packets:
            self.node_b.receive(packet, later(self.now, 2))
        copy = self.tmp / "stolen.json"
        shutil.copy(self.node_b.path, copy)
        stolen = OnlineNode.open(copy)
        for packet in packets:
            with self.assertRaises(MessageRejected):
                stolen.receive(packet, later(self.now, 3))

    def test_stolen_device_useless_after_next_change(self) -> None:
        copy = self.tmp / "stolen.json"
        shutil.copy(self.node_b.path, copy)
        same_period = self.node_a.send("same period", later(self.now, 5))
        self.assertEqual(OnlineNode.open(copy).receive(same_period, later(self.now, 6)).text,
                         "same period")
        nxt = self.change(1)
        packet = self.node_a.send("next period", later(nxt, 5))
        with self.assertRaises(MessageRejected):
            OnlineNode.open(copy).receive(packet, later(nxt, 6))

    def test_tampering_is_detected_and_state_untouched(self) -> None:
        packet = self.node_a.send("secret", later(self.now, 1))
        for index in (5, 30, 700, len(packet) - 5):
            with self.assertRaises(MessageRejected):
                self.node_b.receive(flip(packet, index), later(self.now, 2))
        self.assertEqual(self.node_b.receive(packet, later(self.now, 3)).text, "secret")
        with self.assertRaises(MessageRejected):
            self.node_b.receive("not a packet", later(self.now, 3))

    def test_two_independent_layers(self) -> None:
        state = self.node_a.epochs[1]
        chain, counter = state.send_chain, state.send_counter
        packet = self.node_a.send("layered", later(self.now, 1))
        k_aes, k_chacha = layer_keys(chain_message_key(chain))
        self.assertNotEqual(k_aes, k_chacha)
        raw = decode_packet(packet)
        nonce, body = raw[:NONCE_BYTES], raw[BODY_OFFSET:]
        header = HEADER.pack(b"M", FORMAT_VERSION, 1, b"A", counter)
        with self.assertRaises(InvalidTag):                 # مفتاح AES وحده لا يكفي
            AESGCM(k_aes).decrypt(nonce, body, header)
        inner = ChaCha20Poly1305(k_chacha).decrypt(nonce, body, header)
        self.assertNotIn(b"layered", inner)                 # بعد نزع طبقة: ما زال مشفرًا
        self.assertIn(b"layered", AESGCM(k_aes).decrypt(nonce, inner, header))

    def test_header_is_hidden(self) -> None:
        packet = self.node_a.send("hidden", later(self.now, 1))
        raw = decode_packet(packet)
        visible = HEADER.pack(b"M", FORMAT_VERSION, 1, b"A", 0)
        self.assertNotIn(visible, raw)
        self.assertNotIn(b"hidden", raw)

    def test_too_many_skipped_messages_rejected(self) -> None:
        with mock.patch.object(online_node, "MAX_SKIP", 3):
            packets = [self.node_a.send(f"m{i}", later(self.now, 1)) for i in range(6)]
            with self.assertRaises(MessageRejected):
                self.node_b.receive(packets[5], later(self.now, 2))
            self.assertEqual(self.node_b.receive(packets[3], later(self.now, 2)).text, "m3")

    def test_late_message_within_grace_then_expired(self) -> None:
        packet = self.node_a.send("late", later(self.changes[1], -1))
        nxt = self.change(1)
        self.assertEqual(self.node_b.receive(packet, later(nxt, 30)).text, "late")
        old_period = OnlineNode.open(self.node_a.path).epochs[1]
        self.assertIsNone(old_period.send_chain)           # لا إرسال بفترة انتهت

    def test_old_period_expires_after_grace(self) -> None:
        packet = self.node_a.send("very late", later(self.changes[1], -1))
        nxt = self.changes[1]
        expired = nxt + online_node.GRACE_PERIOD + timedelta(seconds=1)
        with self.assertRaises(MessageRejected):
            self.node_b.receive(packet, expired)

    def test_refuses_to_send_when_change_is_due(self) -> None:
        with self.assertRaises(KeyUnavailable):
            self.node_a.send("hello", later(self.changes[1], 1))

    def test_state_survives_reload(self) -> None:
        packet = self.node_a.send("persist", later(self.now, 1))
        reloaded = OnlineNode.open(self.node_b.path)
        self.assertEqual(reloaded.receive(packet, later(self.now, 2)).text, "persist")
        again = self.node_a.send("next", later(self.now, 3))
        self.assertEqual(OnlineNode.open(self.node_b.path).receive(again, later(self.now, 4)).text,
                         "next")


class PairingTest(Base):
    def test_bundle_from_another_pair_is_rejected(self) -> None:
        other, _ = OfflineVault.create_pair(self.tmp / "x.json", self.tmp / "y.json", now=T0)
        self.change(0)
        with self.assertRaises(NodeError):
            self.node_a.import_bundle(other.release_key(self.changes[0]), self.changes[0])

    def test_bundle_from_peer_vault_is_rejected(self) -> None:
        self.change(0)
        with self.assertRaises(NodeError):
            self.node_a.import_bundle(self.vault_b.release_key(self.changes[0]), self.changes[0])

    def test_different_pairs_cannot_read_each_other(self) -> None:
        other_a, other_b = OfflineVault.create_pair(self.tmp / "x.json", self.tmp / "y.json",
                                                    now=T0)
        now = self.change(0)
        stranger = OnlineNode.open(self.tmp / "stranger.json")
        stranger.import_bundle(other_b.release_key(now), now)
        with self.assertRaises(MessageRejected):
            stranger.receive(self.node_a.send("private", later(now, 1)), later(now, 1))

    def test_transfer_folder_is_emptied_after_import(self) -> None:
        usb = self.tmp / "usb"
        export_bundle(self.vault_a.release_key(self.changes[0]), usb)
        self.node_a.import_from_folder(usb, self.changes[0])
        self.assertEqual(list(usb.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
