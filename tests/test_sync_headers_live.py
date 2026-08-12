from mimblewimble.p2p.message import Capabilities, MsgHand
from scripts import sync_headers_live


def test_smoke_hand_matches_library_hand_serializer(monkeypatch):
    nonce_bytes = bytes.fromhex("0102030405060708")
    monkeypatch.setattr(sync_headers_live.os, "urandom", lambda size: nonce_bytes)
    genesis_hash = bytes.fromhex("ab" * 32)

    frame = sync_headers_live._build_hand(
        "192.0.2.10:3414", "198.51.100.20:3414", genesis_hash
    )

    assert frame == MsgHand(
        capabilities=int(Capabilities.FULL_NODE),
        nonce=int.from_bytes(nonce_bytes, "big"),
        sender_addr="192.0.2.10:3414",
        receiver_addr="198.51.100.20:3414",
        genesis_hash=genesis_hash,
    ).serialize()