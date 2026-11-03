#!/usr/bin/env python3
"""
نسخة بايثون كطرف في اختبارات التوافق مع نسخة أندرويد (Kotlin).
تقرأ أوامر JSON سطرًا سطرًا من الإدخال، وتجيب بسطر JSON. الأوقات بالثواني منذ 1970 (UTC).
"""
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import messenger as messenger_mod                       # noqa: E402
import secure_app                                       # noqa: E402
from common import fingerprint                          # noqa: E402
from offline_vault import (OfflineVault, decode_pairing_code, encode_pairing_code,  # noqa: E402
                           export_bundle, mix_seed)
from online_node import (MLKEM1024PrivateKey, MLKEM1024PublicKey, NodeError,  # noqa: E402
                         OnlineNode, derive_epoch, kdf_root)

TMP = Path(tempfile.mkdtemp())
state = {}


def t(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def h(data):
    return data.hex()


def b(text):
    return bytes.fromhex(text)


def handle(c):
    cmd = c["cmd"]
    # --- متجهات اختبار ثابتة ---
    if cmd == "pairing_encode":
        return {"code": encode_pairing_code(b(c["seed"]), t(c["start"]), c["min"], c["max"])}
    if cmd == "pairing_decode":
        seed, start, lo, hi = decode_pairing_code(c["code"])
        return {"seed": h(seed), "start": int(start.timestamp()), "min": lo, "max": hi}
    if cmd == "mix_seed":
        return {"seed": h(mix_seed([(label, b(v)) for label, v in c["sources"]]))}
    if cmd == "fingerprint":
        return {"fp": fingerprint(b(c["secret"]), c["purpose"])}
    if cmd == "vault_keys":
        vault = OfflineVault.from_seed(TMP / f"v{len(state)}_{c['start']}.json", b(c["seed"]), "A",
                                       t(c["start"]), c["min"], c["max"])
        state[f"v{len(state)}"] = vault
        changes = vault.upcoming_changes(c["count"])
        keys = [vault.release_key(when)["key"] for when in changes]
        return {"changes": [int(x.timestamp()) for x in changes], "keys": keys}
    if cmd == "mlkem_public":
        return {"public": h(MLKEM1024PrivateKey.from_seed_bytes(b(c["seed"])).public_key().public_bytes_raw())}
    if cmd == "mlkem_lock":
        secret, box = MLKEM1024PublicKey.from_public_bytes(b(c["public"])).encapsulate()
        return {"secret": h(secret), "box": h(box)}
    if cmd == "mlkem_unlock":
        return {"secret": h(MLKEM1024PrivateKey.from_seed_bytes(b(c["seed"])).decapsulate(b(c["box"])))}
    if cmd == "derive_epoch":
        s = derive_epoch(b(c["vault_key"]), c["epoch"], b(c["dh"]), b(c["kem"]), b(c["pub_a"]),
                         b(c["pub_b"]), b(c["kem_public_b"]), b(c["kem_box"]))
        return {"header_key": h(s.header_key), "root_key": h(s.root_key),
                "initial_chain_b": h(s.initial_chain_b), "fingerprint": s.fingerprint}
    if cmd == "kdf_root":
        rk, ck = kdf_root(b(c["rk"]), b(c["dh"]), b(c["kem"]))
        return {"rk": h(rk), "ck": h(ck)}

    # --- طرف حي (الدور A، مثل secure_app create) ---
    if cmd == "create":
        code, vault = secure_app.create(TMP / "peer", c["min_hours"], c["max_hours"], now=t(c["now"]))
        state["vault"], state["node"] = vault, OnlineNode.open(TMP / "peer" / "node.json")
        return {"code": code, "pair_id": vault.pair_id}
    if cmd == "changes":
        return {"changes": [int(x.timestamp()) for x in state["vault"].upcoming_changes(c["count"])]}
    if cmd == "release":
        epoch = state["node"].import_bundle(state["vault"].release_key(t(c["now"])), t(c["now"]))
        return {"epoch": epoch}
    if cmd == "handshake":
        return {"packet": state["node"].my_handshake(t(c["now"]))}
    if cmd == "send":
        return {"packet": state["node"].send(c["text"], t(c["now"]))}
    if cmd == "dummy":
        return {"packet": state["node"].send_dummy(t(c["now"]))}
    if cmd == "fp":
        return {"fp": state["node"].key_fingerprint(t(c["now"]))}
    if cmd == "receive":
        try:
            r = state["node"].receive(c["packet"], t(c["now"]))
        except NodeError as error:
            return {"error": type(error).__name__}
        return {"kind": r.kind, "texts": list(r.texts), "duplicate": r.duplicate,
                "waiting": r.waiting, "skew": r.clock_skew}

    # --- تطبيق بايثون كامل (حافلة + خادم ترحيل) بوقت محاكى ---
    if cmd == "messenger_start":
        keys = TMP / "peer" / "drop"
        state["keys"] = keys
        state["messenger"] = messenger_mod.Messenger(
            TMP / "peer" / "node.json", keys, messenger_mod.RelayClient(c["relay"]), name="python",
            min_gap=timedelta(seconds=c["min_gap"]), max_gap=timedelta(seconds=c["max_gap"]),
            poll_every=timedelta(seconds=c["poll"]), now=t(c["now"]))
        return {}
    if cmd == "messenger_release":
        export_bundle(state["vault"].release_key(t(c["now"])), state["keys"])
        return {}
    if cmd == "messenger_step":
        state["messenger"].step(t(c["now"]))
        return {}
    if cmd == "messenger_enqueue":
        state["messenger"].bus.enqueue(c["text"], t(c["now"]))
        return {}
    if cmd == "messenger_texts":
        return {"texts": [m["text"] for m in state["messenger"].log if m["who"] == "peer"],
                "fingerprint": state["messenger"].snapshot(now=t(c["now"]))["fingerprint"]}
    raise ValueError(f"أمر غير معروف: {cmd}")


for line in sys.stdin:
    try:
        reply = handle(json.loads(line))
    except Exception as error:   # نعيد الخطأ للاختبار بدل التوقف
        reply = {"fatal": f"{type(error).__name__}: {error}"}
    print(json.dumps(reply, ensure_ascii=False), flush=True)
