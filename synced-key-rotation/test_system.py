"""
اختبارات آلية للتأكد من أن النظام يتصرف كما هو متوقع.
التشغيل:  python -m unittest -v
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from offline_vault import OfflineVault, VaultError, export_bundle
from online_node import KeyUnavailable, MessageRejected, NodeError, OnlineNode


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

    def rotate(self, now: datetime) -> None:
        self.node_a.import_bundle(self.vault_a.release_key(now), now)
        self.node_b.import_bundle(self.vault_b.release_key(now), now)

    def test_both_sides_derive_same_key_without_talking(self) -> None:
        for day in (3, 4, 9):
            key_a = self.vault_a.release_key(at(day, 8))["key"]
            key_b = self.vault_b.release_key(at(day, 8))["key"]
            self.assertEqual(key_a, key_b)

    def test_keys_change_every_epoch(self) -> None:
        keys = {self.vault_a.release_key(at(day, 8, 30))["key"] for day in range(3, 13)}
        self.assertEqual(len(keys), 10)

    def test_epoch_boundary_is_rotation_hour(self) -> None:
        self.assertEqual(self.vault_a.schedule.epoch_at(at(3, 7, 59)), 0)
        self.assertEqual(self.vault_a.schedule.epoch_at(at(3, 8, 0)), 1)

    def test_round_trip(self) -> None:
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("مرحبا 👋", at(3, 9))
        self.assertEqual(self.node_b.decrypt(token, at(3, 9, 1)), "مرحبا 👋")

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

    def test_old_keys_are_purged_from_online_node(self) -> None:
        for day in range(3, 8):
            self.rotate(at(day, 8))
        self.assertEqual(sorted(OnlineNode.open(self.node_a.path).keys), [4, 5])

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

    def test_vault_cannot_go_back_in_time(self) -> None:
        self.vault_a.release_key(at(6, 8))
        with self.assertRaises(VaultError):
            self.vault_a.release_key(at(4, 8))
        stolen = OfflineVault.load(self.vault_a.path)
        with self.assertRaises(VaultError):
            stolen.release_key(at(3, 9))

    def test_bundle_from_another_pair_is_rejected(self) -> None:
        other, _ = OfflineVault.create_pair(
            self.tmp / "x" / "vault.json", self.tmp / "y" / "vault.json", now=at(2, 20),
        )
        self.rotate(at(3, 8))
        with self.assertRaises(NodeError):
            self.node_a.import_bundle(other.release_key(at(3, 8)), at(3, 8))

    def test_different_pairs_cannot_read_each_other(self) -> None:
        other, _ = OfflineVault.create_pair(
            self.tmp / "x" / "vault.json", self.tmp / "y" / "vault.json", now=at(2, 20),
        )
        stranger = OnlineNode.open(self.tmp / "x" / "node.json")
        stranger.import_bundle(other.release_key(at(3, 8)), at(3, 8))
        self.rotate(at(3, 8))
        token = self.node_a.encrypt("private", at(3, 9))
        with self.assertRaises(MessageRejected):
            stranger.decrypt(token, at(3, 9))

    def test_transfer_folder_is_emptied_after_import(self) -> None:
        usb = self.tmp / "usb"
        export_bundle(self.vault_a.release_key(at(3, 8)), usb)
        self.node_a.import_from_folder(usb, at(3, 8))
        self.assertEqual(list(usb.iterdir()), [])

    def test_pairing_never_overwrites_existing_vault(self) -> None:
        with self.assertRaises(VaultError):
            OfflineVault.create_pair(self.vault_a.path, self.tmp / "new.json")


if __name__ == "__main__":
    unittest.main()
