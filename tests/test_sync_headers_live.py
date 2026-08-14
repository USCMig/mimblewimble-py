from mimblewimble.p2p.message import Capabilities, MsgHand
from scripts import sync_headers_live


def test_resolve_sender_addr_uses_ipv6_for_ipv6_remote(monkeypatch):
    class FakeProbe:
        def __init__(self, family, socket_type):
            assert family == sync_headers_live.socket.AF_INET6
            assert socket_type == sync_headers_live.socket.SOCK_DGRAM

        def connect(self, address):
            assert address == ("::1", 3414)

        def getsockname(self):
            return ("::1", 54321, 0, 0)

        def close(self):
            pass

    monkeypatch.setattr(sync_headers_live.socket, "socket", FakeProbe)

    assert (
        sync_headers_live._resolve_sender_addr("::1:3414", "0.0.0.0:13414")
        == "::1:13414"
    )


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