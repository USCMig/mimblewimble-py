"""
tests/test_p2p_messages.py

Unit tests for mimblewimble/p2p/message.py — P2P wire message serialisation.

Mirrors the p2p round-trip tests in:
  grin/p2p/tests/ser_deser.rs
  grin/p2p/tests/capabilities.rs
  grin/p2p/tests/peer_addr.rs
  grin/p2p/tests/peer_handshake.rs
"""

import struct
import pytest

from mimblewimble.genesis import mainnet
from mimblewimble.p2p.message import (
    MAINNET_MAGIC,
    TESTNET_MAGIC,
    HEADER_LEN,
    PROTOCOL_VERSION,
    USER_AGENT,
    MessageType,
    Capabilities,
    PeerAddr,
    pack_header,
    unpack_header,
    _encode_str,
    _decode_str,
    MsgError,
    MsgHand,
    MsgShake,
    MsgPing,
    MsgPong,
    MsgGetPeerAddrs,
    MsgPeerAddrs,
    MsgGetHeaders,
    MsgHeaders,
    MsgGetBlock,
    MsgGetCompactBlock,
    MsgTxHashSetRequest,
    MsgTxHashSetArchive,
    MsgBanReason,
    MsgCompactBlock,
    MsgOutputSegment,
    MsgRangeProofSegment,
    MsgKernelSegment,
)
from mimblewimble.serializer import Serializer


@pytest.mark.parametrize(
    "message_type",
    [MsgOutputSegment, MsgRangeProofSegment, MsgKernelSegment],
)
def test_empty_segment_response_roundtrip(message_type):
    block_hash = bytes.fromhex("ab" * 32)
    message = message_type(block_hash=block_hash)
    _, msg_type, body_length = unpack_header(message.serialize())
    body = message.serialize()[-body_length:]

    assert msg_type == message.msg_type
    parsed = message_type.deserialize(body)
    assert parsed.block_hash == block_hash
    assert parsed.segment is None


# ---------------------------------------------------------------------------
# Magic bytes and frame header
# ---------------------------------------------------------------------------


class TestMagicAndFraming:
    def test_protocol_version_matches_current_grin(self):
        assert PROTOCOL_VERSION == 1000

    def test_mainnet_magic_bytes(self):
        assert MAINNET_MAGIC == bytes([0x61, 0x3D])

    def test_testnet_magic_bytes(self):
        assert TESTNET_MAGIC == bytes([0x83, 0xC1])

    def test_header_length_is_11(self):
        assert HEADER_LEN == 11  # 2 magic + 1 type + 8 body_len

    def test_pack_header_length(self):
        body = b"\xde\xad\xbe\xef"
        frame = pack_header(MessageType.Ping, body)
        assert len(frame) == HEADER_LEN + len(body)

    def test_pack_header_magic(self):
        frame = pack_header(MessageType.Ping, b"")
        assert frame[:2] == MAINNET_MAGIC

    def test_pack_header_testnet_magic(self):
        frame = pack_header(MessageType.Ping, b"", magic=TESTNET_MAGIC)
        assert frame[:2] == TESTNET_MAGIC

    def test_unpack_header_roundtrip(self):
        body = b"\x01\x02\x03"
        frame = pack_header(MessageType.Pong, body)
        magic, msg_type, body_len = unpack_header(frame)
        assert magic == MAINNET_MAGIC
        assert msg_type == MessageType.Pong
        assert body_len == len(body)

    def test_unpack_header_too_short_raises(self):
        with pytest.raises(ValueError):
            unpack_header(b"\x61\x3d")

    def test_pack_unpack_all_message_types(self):
        for mt in MessageType:
            body = b"\xff" * 4
            frame = pack_header(mt, body)
            _, parsed_type, body_len = unpack_header(frame)
            assert parsed_type == mt
            assert body_len == 4


# ---------------------------------------------------------------------------
# Capabilities bitmask (mirrors p2p/tests/capabilities.rs)
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_unknown_is_zero(self):
        assert int(Capabilities.UNKNOWN) == 0

    def test_full_hist_is_bit_0(self):
        assert int(Capabilities.FULL_HIST) == 1

    def test_txhashset_hist_is_bit_1(self):
        assert int(Capabilities.TXHASHSET_HIST) == 2

    def test_peer_list_is_bit_2(self):
        assert int(Capabilities.PEER_LIST) == 4

    def test_tx_kernel_hash_is_bit_3(self):
        assert int(Capabilities.TX_KERNEL_HASH) == 8

    def test_pibd_hist_is_bit_4(self):
        assert int(Capabilities.PIBD_HIST) == 16

    def test_block_hist_is_bit_5(self):
        assert int(Capabilities.BLOCK_HIST) == 32

    def test_pibd_hist_1_is_bit_6(self):
        assert int(Capabilities.PIBD_HIST_1) == 64

    def test_full_node_combines_base_caps(self):
        expected = (
            Capabilities.FULL_HIST
            | Capabilities.TXHASHSET_HIST
            | Capabilities.PEER_LIST
            | Capabilities.TX_KERNEL_HASH
            | Capabilities.PIBD_HIST
            | Capabilities.PIBD_HIST_1
        )
        assert int(Capabilities.FULL_NODE) == int(expected)

    def test_capabilities_bitwise_or(self):
        combo = int(Capabilities.FULL_HIST) | int(Capabilities.PEER_LIST)
        assert combo == 5

    def test_capabilities_bitwise_and(self):
        # Check that FULL_NODE contains PEER_LIST
        assert int(Capabilities.FULL_NODE) & int(Capabilities.PEER_LIST) != 0

    def test_unknown_not_in_full_node(self):
        # UNKNOWN (0) is a sentinel, not in FULL_NODE
        assert int(Capabilities.UNKNOWN) == 0


# ---------------------------------------------------------------------------
# PeerAddr (mirrors p2p/tests/peer_addr.rs)
# ---------------------------------------------------------------------------


class TestPeerAddr:
    def _roundtrip(self, addr_str: str) -> PeerAddr:
        pa = PeerAddr(addr=addr_str)
        serialized = pa.serialize()
        reconstructed, _ = PeerAddr.deserialize(serialized)
        return reconstructed

    def test_ipv4_addr_roundtrip(self):
        r = self._roundtrip("127.0.0.1:3414")
        assert r.addr == "127.0.0.1:3414"

    def test_ipv6_addr_roundtrip(self):
        r = self._roundtrip("[::1]:3414")
        assert r.addr == "[::1]:3414"

    def test_hostname_is_not_a_wire_peer_address(self):
        with pytest.raises(ValueError):
            PeerAddr(addr="node.example.com:3414").serialize()

    def test_empty_address_is_not_a_wire_peer_address(self):
        with pytest.raises(ValueError):
            PeerAddr(addr="").serialize()

    def test_serialize_is_length_prefixed(self):
        pa = PeerAddr(addr="a:1")
        with pytest.raises(ValueError):
            pa.serialize()

    def test_serialize_uses_grin_ipv4_socket_address_layout(self):
        raw = PeerAddr(addr="127.0.0.1:3414").serialize()
        assert raw == b"\x00\x7f\x00\x00\x01\x0dV"


# ---------------------------------------------------------------------------
# Individual message round-trips
# ---------------------------------------------------------------------------


def _body_of(full_frame: bytes) -> bytes:
    return full_frame[HEADER_LEN:]


class TestMsgError:
    def test_roundtrip(self):
        original = MsgError(message="something went wrong")
        body = _body_of(original.serialize())
        r = MsgError.deserialize(body)
        assert r.message == original.message

    def test_empty_message(self):
        original = MsgError(message="")
        body = _body_of(original.serialize())
        r = MsgError.deserialize(body)
        assert r.message == ""


class TestMsgHand:
    def _roundtrip(self, **kwargs) -> MsgHand:
        original = MsgHand(**kwargs)
        body = _body_of(original.serialize())
        return MsgHand.deserialize(body)

    def test_default_roundtrip(self):
        r = self._roundtrip()
        assert r.version == PROTOCOL_VERSION
        assert r.user_agent == USER_AGENT

    def test_custom_nonce(self):
        r = self._roundtrip(nonce=0xDEADBEEF_CAFEBABE)
        assert r.nonce == 0xDEADBEEF_CAFEBABE

    def test_genesis_hash_preserved(self):
        ghash = bytes(range(32))
        r = self._roundtrip(genesis_hash=ghash)
        assert r.genesis_hash == ghash

    def test_sender_receiver_preserved(self):
        r = self._roundtrip(sender_addr="1.2.3.4:3414", receiver_addr="5.6.7.8:3414")
        assert r.sender_addr == "1.2.3.4:3414"
        assert r.receiver_addr == "5.6.7.8:3414"

    def test_capabilities_preserved(self):
        r = self._roundtrip(capabilities=int(Capabilities.FULL_NODE))
        assert r.capabilities == int(Capabilities.FULL_NODE)

    def test_genesis_difficulty_preserved(self):
        r = self._roundtrip(genesis_block_difficulty=999_999)
        assert r.genesis_block_difficulty == 999_999

    def test_msg_type_is_hand(self):
        assert MsgHand.msg_type == MessageType.Hand


class TestMsgShake:
    def _roundtrip(self, **kwargs) -> MsgShake:
        original = MsgShake(**kwargs)
        body = _body_of(original.serialize())
        return MsgShake.deserialize(body)

    def test_default_roundtrip(self):
        r = self._roundtrip()
        assert r.version == PROTOCOL_VERSION

    def test_genesis_hash_preserved(self):
        ghash = bytes(range(32))
        r = self._roundtrip(genesis_hash=ghash)
        assert r.genesis_hash == ghash

    def test_msg_type_is_shake(self):
        assert MsgShake.msg_type == MessageType.Shake


class TestMsgPingPong:
    def test_ping_uses_big_endian_wire_values(self):
        body = _body_of(MsgPing(total_difficulty=0x0102030405060708, height=9).serialize())
        assert body == bytes.fromhex("01020304050607080000000000000009")

    def test_pong_uses_big_endian_wire_values(self):
        body = _body_of(MsgPong(total_difficulty=9, height=0x0102030405060708).serialize())
        assert body == bytes.fromhex("00000000000000090102030405060708")

    def test_ping_roundtrip(self):
        original = MsgPing(total_difficulty=12345, height=99)
        body = _body_of(original.serialize())
        r = MsgPing.deserialize(body)
        assert r.total_difficulty == 12345
        assert r.height == 99

    def test_pong_roundtrip(self):
        original = MsgPong(total_difficulty=99999, height=42)
        body = _body_of(original.serialize())
        r = MsgPong.deserialize(body)
        assert r.total_difficulty == 99999
        assert r.height == 42

    def test_ping_zero_values(self):
        original = MsgPing(total_difficulty=0, height=0)
        body = _body_of(original.serialize())
        r = MsgPing.deserialize(body)
        assert r.total_difficulty == 0
        assert r.height == 0

    def test_ping_msg_type(self):
        assert MsgPing.msg_type == MessageType.Ping

    def test_pong_msg_type(self):
        assert MsgPong.msg_type == MessageType.Pong


class TestMsgGetPeerAddrs:
    def test_wire_capabilities_are_big_endian(self):
        body = _body_of(MsgGetPeerAddrs(capabilities=0x01020304).serialize())
        assert body == bytes.fromhex("01020304")

    def test_roundtrip(self):
        original = MsgGetPeerAddrs(capabilities=int(Capabilities.FULL_NODE))
        body = _body_of(original.serialize())
        r = MsgGetPeerAddrs.deserialize(body)
        assert r.capabilities == int(Capabilities.FULL_NODE)

    def test_msg_type(self):
        assert MsgGetPeerAddrs.msg_type == MessageType.GetPeerAddrs


class TestMsgPeerAddrs:
    def test_wire_peer_count_is_big_endian(self):
        body = _body_of(MsgPeerAddrs(peers=[PeerAddr("10.0.0.1:3414")]).serialize())
        assert body == bytes.fromhex("00000001000a0000010d56")

    def test_empty_peers_roundtrip(self):
        original = MsgPeerAddrs(peers=[])
        body = _body_of(original.serialize())
        r = MsgPeerAddrs.deserialize(body)
        assert r.peers == []

    def test_single_peer_roundtrip(self):
        original = MsgPeerAddrs(peers=[PeerAddr("10.0.0.1:3414")])
        body = _body_of(original.serialize())
        r = MsgPeerAddrs.deserialize(body)
        assert len(r.peers) == 1
        assert r.peers[0].addr == "10.0.0.1:3414"

    def test_multiple_peers_roundtrip(self):
        peers = [PeerAddr(f"10.0.0.{i}:3414") for i in range(5)]
        original = MsgPeerAddrs(peers=peers)
        body = _body_of(original.serialize())
        r = MsgPeerAddrs.deserialize(body)
        assert len(r.peers) == 5
        assert [p.addr for p in r.peers] == [p.addr for p in peers]

    def test_msg_type(self):
        assert MsgPeerAddrs.msg_type == MessageType.PeerAddrs


class TestMsgGetHeaders:
    def test_wire_locator_count_is_a_single_byte(self):
        body = _body_of(MsgGetHeaders(locator=[bytes.fromhex("ab" * 32)]).serialize())
        assert body == b"\x01" + bytes.fromhex("ab" * 32)

    def test_empty_locator_roundtrip(self):
        original = MsgGetHeaders(locator=[])
        body = _body_of(original.serialize())
        r = MsgGetHeaders.deserialize(body)
        assert r.locator == []

    def test_single_hash_roundtrip(self):
        h = bytes(range(32))
        original = MsgGetHeaders(locator=[h])
        body = _body_of(original.serialize())
        r = MsgGetHeaders.deserialize(body)
        assert len(r.locator) == 1
        assert r.locator[0] == h

    def test_multiple_hashes_roundtrip(self):
        hashes = [bytes([i] * 32) for i in range(5)]
        original = MsgGetHeaders(locator=hashes)
        body = _body_of(original.serialize())
        r = MsgGetHeaders.deserialize(body)
        assert len(r.locator) == 5
        for i, h in enumerate(r.locator):
            assert h == hashes[i]

    def test_msg_type(self):
        assert MsgGetHeaders.msg_type == MessageType.GetHeaders


class TestMsgHeaders:
    @staticmethod
    def _serialized_header() -> bytes:
        serializer = Serializer()
        mainnet.getHeader().serialize(serializer)
        return serializer.getvalue()

    def test_wire_layout_is_big_endian_count_followed_by_headers(self):
        raw_header = self._serialized_header()
        body = _body_of(MsgHeaders(headers=[raw_header]).serialize())

        assert body == b"\x00\x01" + raw_header

    def test_multiple_headers_are_concatenated_without_length_prefixes(self):
        raw_header = self._serialized_header()
        body = _body_of(MsgHeaders(headers=[raw_header, raw_header]).serialize())

        assert body == b"\x00\x02" + raw_header + raw_header
        assert MsgHeaders.deserialize(body).headers == [raw_header, raw_header]

    def test_truncated_header_is_rejected(self):
        raw_header = self._serialized_header()
        with pytest.raises(ValueError, match="Malformed serialised block header"):
            MsgHeaders.deserialize(b"\x00\x01" + raw_header[:-1])


class TestMsgGetBlock:
    def test_roundtrip(self):
        block_hash = bytes(range(32))
        original = MsgGetBlock(block_hash=block_hash)
        body = _body_of(original.serialize())
        r = MsgGetBlock.deserialize(body)
        assert r.block_hash == block_hash

    def test_msg_type(self):
        assert MsgGetBlock.msg_type == MessageType.GetBlock


class TestMsgGetCompactBlock:
    def test_roundtrip(self):
        block_hash = bytes([0xAB] * 32)
        original = MsgGetCompactBlock(block_hash=block_hash)
        body = _body_of(original.serialize())
        r = MsgGetCompactBlock.deserialize(body)
        assert r.block_hash == block_hash

    def test_msg_type(self):
        assert MsgGetCompactBlock.msg_type == MessageType.GetCompactBlock


class TestMsgTxHashSet:
    def test_request_uses_big_endian_height(self):
        body = _body_of(
            MsgTxHashSetRequest(block_hash=b"\x11" * 32, height=0x0102030405060708).serialize()
        )
        assert body == b"\x11" * 32 + bytes.fromhex("0102030405060708")

    def test_request_roundtrip(self):
        block_hash = bytes([0x11] * 32)
        original = MsgTxHashSetRequest(block_hash=block_hash, height=12345)
        body = _body_of(original.serialize())
        r = MsgTxHashSetRequest.deserialize(body)
        assert r.block_hash == block_hash
        assert r.height == 12345

    def test_archive_roundtrip(self):
        block_hash = bytes([0x22] * 32)
        zip_data = b"PK\x03\x04" + b"\xbe\xef" * 20
        original = MsgTxHashSetArchive(
            block_hash=block_hash, height=999, zip_bytes=zip_data
        )
        body = _body_of(original.serialize())
        r = MsgTxHashSetArchive.deserialize(body)
        assert r.block_hash == block_hash
        assert r.height == 999
        assert r.zip_bytes == b""
        assert r.bytes_len == len(zip_data)

    def test_archive_empty_zip(self):
        original = MsgTxHashSetArchive(block_hash=b"\x00" * 32, height=0, zip_bytes=b"")
        body = _body_of(original.serialize())
        r = MsgTxHashSetArchive.deserialize(body)
        assert r.zip_bytes == b""
        assert r.bytes_len == 0

    def test_archive_frame_contains_only_big_endian_metadata(self):
        body = _body_of(
            MsgTxHashSetArchive(
                block_hash=b"\x22" * 32,
                height=0x0102030405060708,
                zip_bytes=b"archive",
            ).serialize()
        )
        assert body == b"\x22" * 32 + bytes.fromhex("01020304050607080000000000000007")


class TestMsgBanReason:
    def test_roundtrip(self):
        original = MsgBanReason(ban_reason="too many errors")
        body = _body_of(original.serialize())
        r = MsgBanReason.deserialize(body)
        assert r.ban_reason == "too many errors"

    def test_msg_type(self):
        assert MsgBanReason.msg_type == MessageType.BanReason


class TestMsgCompactBlock:
    def test_roundtrip_raw_body(self):
        """Compact block stores raw bytes; roundtrip preserves them."""
        raw = b"\xde\xad\xbe\xef" * 16
        original = MsgCompactBlock(raw_body=raw)
        body = _body_of(original.serialize())
        r = MsgCompactBlock.deserialize(body)
        assert r.raw_body == raw

    def test_empty_raw_body(self):
        original = MsgCompactBlock(raw_body=b"")
        body = _body_of(original.serialize())
        r = MsgCompactBlock.deserialize(body)
        assert r.raw_body == b""

    def test_msg_type(self):
        assert MsgCompactBlock.msg_type == MessageType.CompactBlock


# ---------------------------------------------------------------------------
# Message type enum values (mirrors Grin's Type enum in msg.rs)
# ---------------------------------------------------------------------------


class TestMessageTypeValues:
    def test_error_is_0(self):
        assert MessageType.Error == 0

    def test_hand_is_1(self):
        assert MessageType.Hand == 1

    def test_shake_is_2(self):
        assert MessageType.Shake == 2

    def test_ping_is_3(self):
        assert MessageType.Ping == 3

    def test_pong_is_4(self):
        assert MessageType.Pong == 4

    def test_get_peer_addrs_is_5(self):
        assert MessageType.GetPeerAddrs == 5

    def test_peer_addrs_is_6(self):
        assert MessageType.PeerAddrs == 6

    def test_get_headers_is_7(self):
        assert MessageType.GetHeaders == 7

    def test_header_is_8(self):
        assert MessageType.Header == 8

    def test_headers_is_9(self):
        assert MessageType.Headers == 9

    def test_get_block_is_10(self):
        assert MessageType.GetBlock == 10

    def test_block_is_11(self):
        assert MessageType.Block == 11

    def test_compact_block_is_12(self):
        assert MessageType.GetCompactBlock == 12

    def test_compact_block_is_13(self):
        assert MessageType.CompactBlock == 13

    def test_stem_transaction_is_14(self):
        assert MessageType.StemTransaction == 14

    def test_transaction_is_15(self):
        assert MessageType.Transaction == 15

    def test_message_types_after_transaction_match_grin_wire_protocol(self):
        assert [
            MessageType.TxHashSetRequest,
            MessageType.TxHashSetArchive,
            MessageType.BanReason,
            MessageType.GetTransaction,
            MessageType.TransactionKernel,
            MessageType.GetOutputBitmapSegment,
            MessageType.OutputBitmapSegment,
            MessageType.GetOutputSegment,
            MessageType.OutputSegment,
            MessageType.GetRangeProofSegment,
            MessageType.RangeProofSegment,
            MessageType.GetKernelSegment,
            MessageType.KernelSegment,
        ] == list(range(16, 29))
