"""
اختبارات آلية للتأكد من أن النظام يتصرف كما هو متوقع.
التشغيل:  python -m unittest -v
"""
from __future__ import annotations

import secrets
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from offline_vault import OfflineVault, VaultError, export_bundle
from online_node import (
    HandshakePending,
    KeyUnavailable,
    MessageRejected,
    NodeError,
    OnlineNode,
    X25519PrivateKey,
    sign_handshake,
)


def at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)


class SyncedRotationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.vault_a, self.vault_b = OfflineVault.create_pair(
            self.tmp / "a" / "vault.json", self.tmp / "b" / "vault.json",
            rotation_hour_utc=8, now=at(2, 20),
        )
        self.node_a = OnlineNode.open(self.tmp / "a" / "node.json")
        self.node_b = OnlineNode.open(self.tmp / "b" / "node.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def import_both(self, now: datetime) -> None:
        self.node_a.import_bundle(self.vault_a.release_key(now), now)
        self.node_b.import_bundle(self.vault_b.release_key(now), now)

    def rotate(self, now: datetime) -> None:
        """تغيير كامل: استيراد مفتاحَي الخزنتين + تبادل المصافحتين."""
        self.import_both(now)
        self.node_b.accept_handshake(self.node_a.my_handshake(now), now)
        self.node_a.accept_handshake(self.node_b.my_handshake(now), now)

    # --- الخزنة غير المتصلة ---------------------------------------------
    def test_vaults_derive_same_key_without_talking(self) -> None:
        for day in (3, 4, 9):
            key_a = self.vault_a.release_key(at(day, 8))["key"]
            key_b = self.vault_b.release_key(at(day, 8))["key"]
            self.assertEqual(key_a, key_b)

    def test_vault_keys_change_every_epoch(self) -> None:
        keys = {self.vault_a.release_key(at(day, 8, 30))["key"] for day in range(3, 13)}
        self.assertEqual(len(keys), 10)

    def test_epoch_boundary_is_rotation_hour(self) -> None:
        self.assertEqual(self.vault_a.schedule.epoch_at(at(3, 7, 59)), 0)
        self.assertEqual(self.vault_a.schedule.epoch_at(at(3, 8, 0)), 1)

    def test_pair_gets_two_distinct_roles(self) -> None:
        self.assertEqual((self.vault_a.role, self.vault_b.role), ("A", "B"))

    def test_vault_cannot_go_back_in_time(self) -> None:
        self.vault_a.release_key(at(6, 8))
        with self.assertRaises(VaultError):
            self.vault_a.release_key(at(4, 8))
        stolen = OfflineVault.load(self.vault_a.path)
        with self.assertRaises(VaultError):
            stolen.release_key(at(3, 9))

    def test_pairing_never_overwrites_existing_vault(self) -> None:
        with self.assertRaises(VaultError):
            OfflineVault.create_pair(self.vault_a.path, self.tmp / "new.json")

    # --- المصافحة (Diffie-Hellman) ---------------------------------------
    def test_handshake_gives_same_final_key_on_both_sides(self) -> None:
        self.rotate(at(3, 8))
        self.assertIsNotNone(self.node_a.key_fingerprint(at(3, 9)))
        self.assertEqual(self.node_a.epochs[1].key, self.node_b.epochs[1].key)

    def test_final_key_is_not_the_vault_key(self) -> None:
        vault_key = bytes.fromhex(self.vault_a.release_key(at(3, 8))["key"])
        self.vault_b.release_key(at(3, 8))
        self.rotate(at(3, 8))
        self.assertNotEqual(self.node_a.epochs[1].key, vault_key)

    def test_fresh_randomness_every_epoch(self) -> None:
        publics, keys = set(), set()
        for day in range(3, 8):
            self.rotate(at(day, 8))
            state = self.node_a.epochs[day - 2]
            publics.add(state.my_public)
            keys.add(state.key)
        self.assertEqual((len(publics), len(keys)), (5, 5))

    def test_same_vault_key_with_new_handshake_gives_new_key(self) -> None:
        """نفس مفتاح الخزنة + مصافحة جديدة = مفتاح نهائي مختلف (العشوائية حقيقية)."""
        bundle_a = self.vault_a.release_key(at(3, 8))
        bundle_b = self.vault_b.release_key(at(3, 8))
        finals = []
        for run in range(2):
            na = OnlineNode.open(self.tmp / f"run{run}" / "a.json")
            nb = OnlineNode.open(self.tmp / f"run{run}" / "b.json")
            na.import_bundle(bundle_a, at(3, 8))
            nb.import_bundle(bundle_b, at(3, 8))
            nb.accept_handshake(na.my_handshake(at(3, 8)), at(3, 8))
            na.accept_handshake(nb.my_handshake(at(3, 8)), at(3, 8))
            finals.append(na.epochs[1].key)
        self.assertNotEqual(finals[0], finals[1])

    def test_cannot_send_before_handshake_completes(self) -> None:
        self.import_both(at(3, 8))
        with self.assertRaises(HandshakePending):
            self.node_a.encrypt("hello", at(3, 9))

    def test_handshake_before_vault_import_waits(self) -> None:
        self.node_a.import_bundle(self.vault_a.release_key(at(3, 8)), at(3, 8))
        self.node_b.import_bundle(self.vault_b.release_key(at(2, 21)), at(2, 21))
        with self.assertRaises(KeyUnavailable):
            self.node_b.accept_handshake(self.node_a.my_handshake(at(3, 8)), at(3, 8))
        self.node_b.import_bundle(self.vault_b.release_key(at(3, 9)), at(3, 9))
        self.node_b.accept_handshake(self.node_a.my_handshake(at(3, 9)), at(3, 9))
        self.node_a.accept_handshake(self.node_b.my_handshake(at(3, 9)), at(3, 9))
        token = self.node_a.encrypt("ok", at(3, 10))
        self.assertEqual(self.node_b.decrypt(token, at(3, 10)), "ok")

    def test_forged_handshake_is_rejected(self) -> None:
        self.import_both(at(3, 8))
        public = X25519PrivateKey.generate().public_key().public_bytes_raw()
        forged = sign_handshake(secrets.token_bytes(32), "A", 1, public)
        with self.assertRaises(MessageRejected):
            self.node_b.accept_handshake(forged, at(3, 8))

    def test_tampered_handshake_is_rejected(self) -> None:
        self.import_both(at(3, 8))
        raw = bytearray(self.node_a.my_handshake(at(3, 8)).encode())
        raw[20] = ord("A") if raw[20] != ord("A") else ord("B")
        with self.assertRaises(MessageRejected):
            self.node_b.accept_handshake(raw.decode(), at(3, 8))

    def test_reflected_handshake_is_rejected(self) -> None:
        self.import_both(at(3, 8))
        with self.assertRaises(MessageRejected):
            self.node_a.accept_handshake(self.node_a.my_handshake(at(3, 8)), at(3, 8))

    def test_duplicate_handshake_is_harmless_conflicting_one_is_rejected(self) -> None:
        self.rotate(at(3, 8))
        key = self.node_b.epochs[1].key
        self.node_b.accept_handshake(self.node_a.my_handshake(at(3, 9)), at(3, 9))
        self.assertEqual(self.node_b.epochs[1].key, key)
        bundle = OfflineVault.load(self.vault_a.path).release_key(at(3, 9))
        other = OnlineNode.open(self.tmp / "other.json")
        other.import_bundle(bundle, at(3, 9))
        with self.assertRaises(MessageRejected):
            self.node_b.accept_handshake(other.my_handshake(at(3, 9)), at(3, 9))

    def test_secrets_are_wiped_after_handshake(self) -> None:
        self.rotate(at(3, 8))
        state = OnlineNode.open(self.node_a.path).epochs[1]
        self.assertIsNone(state.vault_key)
        self.assertIsNone(state.my_private)
        self.assertIsNotNone(state.key)

    def test_stolen_vault_cannot_read_after_next_handshake(self) -> None:
        """الأهم: سرقة الخزنة + تسجيل كل الإنترنت لا تكفي لقراءة الرسائل التالية."""
        self.rotate(at(3, 8))
        stolen_path = self.tmp / "thief" / "vault.json"
        stolen_path.parent.mkdir()
        shutil.copy(self.vault_a.path, stolen_path)
        thief_vault = OfflineVault.load(stolen_path)

        self.rotate(at(4, 8))
        token = self.node_a.encrypt("after the theft", at(4, 9))

        thief = OnlineNode.open(self.tmp / "thief" / "node.json")
        thief.import_bundle(thief_vault.release_key(at(4, 8)), at(4, 8))
        thief.accept_handshake(self.node_b.my_handshake(at(4, 8)), at(4, 8))
        with self.assertRaises(MessageRejected):
            thief.decrypt(token, at(4, 9))
        self.assertEqual(self.node_b.decrypt(token, at(4, 9)), "after the theft")

    # --- التشفير ونافذة السماح -------------------------------------------
    def test_round_trip_both_directions(self) -> None:
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("مرحبا 👋", at(3, 9))
        self.assertEqual(self.node_b.decrypt(token, at(3, 9, 1)), "مرحبا 👋")
        reply = self.node_b.encrypt("أهلًا", at(3, 9, 2))
        self.assertEqual(self.node_a.decrypt(reply, at(3, 9, 3)), "أهلًا")

    def test_state_survives_reload_from_disk(self) -> None:
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("hello", at(3, 9))
        reloaded = OnlineNode.open(self.node_b.path)
        self.assertEqual(reloaded.decrypt(token, at(3, 9)), "hello")
        self.assertEqual(OfflineVault.load(self.vault_a.path).epoch, 1)

    def test_grace_window_accepts_yesterday_only(self) -> None:
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("late", at(4, 7, 59))
        self.rotate(at(4, 8))
        self.assertEqual(self.node_b.decrypt(token, at(4, 8, 1)), "late")
        self.rotate(at(5, 8))
        with self.assertRaises(KeyUnavailable):
            self.node_b.decrypt(token, at(5, 8, 1))

    def test_old_epochs_are_purged_from_online_node(self) -> None:
        for day in range(3, 8):
            self.rotate(at(day, 8))
        self.assertEqual(sorted(OnlineNode.open(self.node_a.path).epochs), [4, 5])

    def test_tampering_is_detected(self) -> None:
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("secret", at(3, 9))
        raw = bytearray(token.encode())
        raw[-5] = ord("A") if raw[-5] != ord("A") else ord("B")
        with self.assertRaises(MessageRejected):
            self.node_b.decrypt(raw.decode(), at(3, 9))
        with self.assertRaises(MessageRejected):
            self.node_b.decrypt("not a message", at(3, 9))

    def test_refuses_to_encrypt_with_stale_key(self) -> None:
        self.rotate(at(3, 8))
        with self.assertRaises(KeyUnavailable):
            self.node_a.encrypt("hello", at(4, 9))

    # --- الاقتران -------------------------------------------------------
    def test_bundle_from_another_pair_is_rejected(self) -> None:
        other, _ = OfflineVault.create_pair(
            self.tmp / "x" / "vault.json", self.tmp / "y" / "vault.json", now=at(2, 20),
        )
        self.rotate(at(3, 8))
        with self.assertRaises(NodeError):
            self.node_a.import_bundle(other.release_key(at(3, 8)), at(3, 8))

    def test_bundle_from_peer_vault_is_rejected(self) -> None:
        self.rotate(at(3, 8))
        with self.assertRaises(NodeError):
            self.node_a.import_bundle(self.vault_b.release_key(at(3, 8)), at(3, 8))

    def test_different_pairs_cannot_read_each_other(self) -> None:
        other_a, other_b = OfflineVault.create_pair(
            self.tmp / "x" / "vault.json", self.tmp / "y" / "vault.json", now=at(2, 20),
        )
        sa = OnlineNode.open(self.tmp / "x" / "node.json")
        sb = OnlineNode.open(self.tmp / "y" / "node.json")
        sa.import_bundle(other_a.release_key(at(3, 8)), at(3, 8))
        sb.import_bundle(other_b.release_key(at(3, 8)), at(3, 8))
        sb.accept_handshake(sa.my_handshake(at(3, 8)), at(3, 8))
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("private", at(3, 9))
        with self.assertRaises(MessageRejected):
            sb.decrypt(token, at(3, 9))
        with self.assertRaises(MessageRejected):
            self.node_b.accept_handshake(sa.my_handshake(at(3, 8)), at(3, 8))

    def test_transfer_folder_is_emptied_after_import(self) -> None:
        usb = self.tmp / "usb"
        export_bundle(self.vault_a.release_key(at(3, 8)), usb)
        self.node_a.import_from_folder(usb, at(3, 8))
        self.assertEqual(list(usb.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
