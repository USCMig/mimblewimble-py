"""
mimblewimble/p2p/message.py

Grin P2P wire protocol message types and serialisation.

Message frame:
    2 bytes  magic          [0x61, 0x3d] on mainnet
    1 byte   msg_type       uint8 (MessageType enum value)
    8 bytes  body_len       BE uint64

Message bodies in this module use Grin's big-endian serialization. Variable-length
byte strings have a u64 big-endian length prefix.

Reference: p2p/src/msg.rs in the Grin repository.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import ip_address
from typing import List, Optional, Tuple

from mimblewimble.blockchain import BlockHeader
from mimblewimble.mmr.segment import (
    Segment,
    SegmentIdentifier,
    SegmentType,
    SegmentTypeIdentifier,
)
from mimblewimble.serializer import Serializer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAINNET_MAGIC: bytes = bytes([0x61, 0x3D])
TESTNET_MAGIC: bytes = bytes([0x83, 0xC1])
HEADER_LEN: int = 2 + 1 + 8  # magic(2) + type(1) + body_len(8)

# Current protocol version advertised in Hand/Shake.
# Matches Grin core's ``global::PROTOCOL_VERSION``.
PROTOCOL_VERSION: int = 1000

# User-agent string
USER_AGENT: str = "MW/mimblewimble-py/0.1.0"

# Maximum number of headers in a single Headers message
MAX_HEADERS: int = 512

# Maximum number of peer addresses in PeerAddrs
MAX_PEER_ADDRS: int = 256


# ---------------------------------------------------------------------------
# MessageType
# ---------------------------------------------------------------------------


class MessageType(IntEnum):
    """Grin P2P message type codes, matching Grin's ``Type`` enum in msg.rs."""

    Error = 0
    Hand = 1
    Shake = 2
    Ping = 3
    Pong = 4
    GetPeerAddrs = 5
    PeerAddrs = 6
    GetHeaders = 7
    Header = 8
    Headers = 9
    GetBlock = 10
    Block = 11
    GetCompactBlock = 12
    CompactBlock = 13
    StemTransaction = 14
    Transaction = 15
    TxHashSetRequest = 16
    TxHashSetArchive = 17
    BanReason = 18
    GetTransaction = 19
    TransactionKernel = 20
    GetOutputBitmapSegment = 21
    OutputBitmapSegment = 22
    GetOutputSegment = 23
    OutputSegment = 24
    GetRangeProofSegment = 25
    RangeProofSegment = 26
    GetKernelSegment = 27
    KernelSegment = 28


# ---------------------------------------------------------------------------
# Framing helpers
# ---------------------------------------------------------------------------


def pack_header(
    msg_type: MessageType, body: bytes, magic: bytes = MAINNET_MAGIC
) -> bytes:
    """Prepend the 11-byte frame header to *body*."""
    return magic + struct.pack(">BQ", int(msg_type), len(body)) + body


def unpack_header(data: bytes) -> Tuple[bytes, MessageType, int]:
    """Parse the 11-byte frame header.

    Returns:
        (magic, msg_type, body_len)
    Raises:
        ValueError if the header is malformed.
    """
    if len(data) < HEADER_LEN:
        raise ValueError(f"Header too short: {len(data)} < {HEADER_LEN}")
    magic = data[:2]
    msg_type, body_len = struct.unpack_from(">BQ", data, 2)
    return magic, MessageType(msg_type), body_len


# ---------------------------------------------------------------------------
# Low-level encode/decode helpers
# ---------------------------------------------------------------------------


def _encode_str(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return _encode_len_prefixed_bytes(encoded)


def _decode_str(data: bytes, offset: int) -> Tuple[str, int]:
    value, offset = _decode_len_prefixed_bytes(data, offset)
    return value.decode("utf-8"), offset


def _encode_bytes(b: bytes) -> bytes:
    return _encode_len_prefixed_bytes(b)


def _decode_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
    return _decode_len_prefixed_bytes(data, offset)


def _encode_len_prefixed_bytes(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _decode_len_prefixed_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
    (length,) = struct.unpack_from(">Q", data, offset)
    offset += 8
    end = offset + length
    if len(data) < end:
        raise ValueError("Length-prefixed bytes are truncated")
    return data[offset:end], end


# ---------------------------------------------------------------------------
# Peer address
# ---------------------------------------------------------------------------


@dataclass
class PeerAddr:
    """Single peer address (host:port) as used in PeerAddrs messages."""

    addr: str  # "host:port"

    def serialize(self) -> bytes:
        host, port_text = self.addr.rsplit(":", 1)
        address = ip_address(host.strip("[]"))
        if address.version == 4:
            return b"\x00" + address.packed + struct.pack(">H", int(port_text))
        return b"\x01" + address.packed + struct.pack(">H", int(port_text))

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple["PeerAddr", int]:
        if len(data) <= offset:
            raise ValueError("Peer address is missing its IP family")
        family = data[offset]
        offset += 1
        address_length = 4 if family == 0 else 16
        end = offset + address_length + 2
        if len(data) < end:
            raise ValueError("Peer address is truncated")
        address = ip_address(data[offset : offset + address_length])
        port = struct.unpack_from(">H", data, offset + address_length)[0]
        host = str(address)
        if address.version == 6:
            host = f"[{host}]"
        return cls(addr=f"{host}:{port}"), end


# ---------------------------------------------------------------------------
# Capabilities flags
# ---------------------------------------------------------------------------


class Capabilities(IntEnum):
    """Bitmask of peer capabilities (Grin's Capabilities struct in p2p/src/types.rs)."""

    UNKNOWN = 0
    FULL_HIST = 1 << 0
    TXHASHSET_HIST = 1 << 1
    PEER_LIST = 1 << 2
    TX_KERNEL_HASH = 1 << 3
    PIBD_HIST = 1 << 4
    BLOCK_HIST = 1 << 5
    PIBD_HIST_1 = 1 << 6

    # Convenience alias
    FULL_NODE = (
        FULL_HIST
        | TXHASHSET_HIST
        | PEER_LIST
        | TX_KERNEL_HASH
        | PIBD_HIST
        | PIBD_HIST_1
    )


# ---------------------------------------------------------------------------
# Message classes
# ---------------------------------------------------------------------------


@dataclass
class MsgError:
    """Error message."""

    msg_type = MessageType.Error
    message: str = ""

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, _encode_str(self.message))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgError":
        message, _ = _decode_str(body, 0)
        return cls(message=message)


@dataclass
class MsgHand:
    """Hand — initial handshake message sent by the connecting peer.

    Wire body (all big-endian):
        4   version       uint32  protocol version
        4   capabilities  uint32  bitmask
        8   nonce         uint64  random nonce to detect self-connections
        8   total_difficulty uint64
        7/19 sender_addr   PeerAddr
        7/19 receiver_addr PeerAddr
        N   user_agent    u64 length-prefixed UTF-8
        32  genesis_hash  bytes
    """

    msg_type = MessageType.Hand
    version: int = PROTOCOL_VERSION
    capabilities: int = int(Capabilities.FULL_NODE)
    nonce: int = 0
    genesis_block_difficulty: int = 0
    sender_addr: str = "0.0.0.0:0"
    receiver_addr: str = "0.0.0.0:0"
    user_agent: str = USER_AGENT
    genesis_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        body = struct.pack(
            ">IIQQ",
            self.version,
            self.capabilities,
            self.nonce,
            self.genesis_block_difficulty,
        )
        body += PeerAddr(self.sender_addr).serialize()
        body += PeerAddr(self.receiver_addr).serialize()
        body += _encode_len_prefixed_bytes(self.user_agent.encode("utf-8"))
        body += self.genesis_hash[:32].ljust(32, b"\x00")
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgHand":
        version, capabilities, nonce, genesis_block_difficulty = struct.unpack_from(
            ">IIQQ", body, 0
        )
        offset = 4 + 4 + 8 + 8
        sender, offset = PeerAddr.deserialize(body, offset)
        receiver, offset = PeerAddr.deserialize(body, offset)
        user_agent_bytes, offset = _decode_len_prefixed_bytes(body, offset)
        user_agent = user_agent_bytes.decode("utf-8")
        genesis_hash = body[offset : offset + 32]
        return cls(
            version=version,
            capabilities=capabilities,
            nonce=nonce,
            genesis_block_difficulty=genesis_block_difficulty,
            sender_addr=sender.addr,
            receiver_addr=receiver.addr,
            user_agent=user_agent,
            genesis_hash=genesis_hash,
        )


@dataclass
class MsgShake:
    """Shake — handshake response.

    Wire body (all big-endian): version, capabilities, total difficulty,
    user agent, and genesis hash.
    """

    msg_type = MessageType.Shake
    version: int = PROTOCOL_VERSION
    capabilities: int = int(Capabilities.FULL_NODE)
    genesis_block_difficulty: int = 0
    user_agent: str = USER_AGENT
    genesis_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        body = struct.pack(
            ">IIQ",
            self.version,
            self.capabilities,
            self.genesis_block_difficulty,
        )
        body += _encode_len_prefixed_bytes(self.user_agent.encode("utf-8"))
        body += self.genesis_hash[:32].ljust(32, b"\x00")
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgShake":
        version, capabilities, genesis_block_difficulty = struct.unpack_from(
            ">IIQ", body, 0
        )
        offset = 4 + 4 + 8
        user_agent_bytes, offset = _decode_len_prefixed_bytes(body, offset)
        user_agent = user_agent_bytes.decode("utf-8")
        genesis_hash = body[offset : offset + 32]
        return cls(
            version=version,
            capabilities=capabilities,
            genesis_block_difficulty=genesis_block_difficulty,
            user_agent=user_agent,
            genesis_hash=genesis_hash,
        )


@dataclass
class MsgPing:
    """Ping — keepalive with the sender's known total difficulty."""

    msg_type = MessageType.Ping
    total_difficulty: int = 0
    height: int = 0

    def serialize(self) -> bytes:
        body = struct.pack(">QQ", self.total_difficulty, self.height)
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgPing":
        total_difficulty, height = struct.unpack_from(">QQ", body)
        return cls(total_difficulty=total_difficulty, height=height)


@dataclass
class MsgPong:
    """Pong — response to Ping."""

    msg_type = MessageType.Pong
    total_difficulty: int = 0
    height: int = 0

    def serialize(self) -> bytes:
        body = struct.pack(">QQ", self.total_difficulty, self.height)
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgPong":
        total_difficulty, height = struct.unpack_from(">QQ", body)
        return cls(total_difficulty=total_difficulty, height=height)


@dataclass
class MsgGetPeerAddrs:
    """Request peer addresses from a peer."""

    msg_type = MessageType.GetPeerAddrs
    capabilities: int = int(Capabilities.FULL_NODE)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, struct.pack(">I", self.capabilities))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetPeerAddrs":
        (capabilities,) = struct.unpack_from(">I", body)
        return cls(capabilities=capabilities)


@dataclass
class MsgPeerAddrs:
    """List of peer addresses."""

    msg_type = MessageType.PeerAddrs
    peers: List[PeerAddr] = field(default_factory=list)

    def serialize(self) -> bytes:
        body = struct.pack(">I", len(self.peers))
        for p in self.peers:
            body += p.serialize()
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgPeerAddrs":
        (n,) = struct.unpack_from(">I", body)
        if n > MAX_PEER_ADDRS:
            raise ValueError(f"Peer address count exceeds limit: {n}")
        offset = 4
        peers = []
        for _ in range(n):
            peer, offset = PeerAddr.deserialize(body, offset)
            peers.append(peer)
        return cls(peers=peers)


@dataclass
class MsgGetHeaders:
    """Request block headers using a locator (list of known header hashes)."""

    msg_type = MessageType.GetHeaders
    locator: List[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        if len(self.locator) > 255:
            raise ValueError("Header locator count exceeds wire limit: 255")
        body = struct.pack(">B", len(self.locator))
        for h in self.locator:
            body += h[:32].ljust(32, b"\x00")
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetHeaders":
        (n,) = struct.unpack_from(">B", body)
        offset = 1
        locator = []
        for _ in range(n):
            locator.append(body[offset : offset + 32])
            offset += 32
        return cls(locator=locator)


@dataclass
class MsgHeaders:
    """Response containing consecutively serialised block headers.

    Grin encodes a big-endian u16 count followed by each ``BlockHeader``
    directly, without a per-header length prefix.
    """

    msg_type = MessageType.Headers
    # Each entry is the raw serialised bytes of a BlockHeader
    headers: List[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        if len(self.headers) > MAX_HEADERS:
            raise ValueError(f"Header count exceeds limit: {len(self.headers)}")
        body = struct.pack(">H", len(self.headers))
        for h in self.headers:
            body += h
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgHeaders":
        if len(body) < 2:
            raise ValueError("Headers message is missing its count")
        (n,) = struct.unpack_from(">H", body)
        if n > MAX_HEADERS:
            raise ValueError(f"Header count exceeds limit: {n}")
        payload = body[2:]
        serializer = Serializer()
        serializer.write(payload)
        headers = []
        for _ in range(n):
            offset = serializer.pnt
            try:
                header = BlockHeader.deserialize(serializer)
            except (IndexError, ValueError, OverflowError) as exc:
                raise ValueError("Malformed serialised block header") from exc
            raw_header = payload[offset : serializer.pnt]
            check = Serializer()
            header.serialize(check)
            if check.getvalue() != raw_header:
                raise ValueError("Malformed serialised block header")
            headers.append(raw_header)
        if serializer.pnt != len(payload):
            raise ValueError("Headers message contains trailing bytes")
        return cls(headers=headers)


@dataclass
class MsgGetBlock:
    """Request a full block by hash."""

    msg_type = MessageType.GetBlock
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetBlock":
        return cls(block_hash=body[:32])


@dataclass
class MsgGetCompactBlock:
    """Request a compact block by hash."""

    msg_type = MessageType.GetCompactBlock
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetCompactBlock":
        return cls(block_hash=body[:32])


@dataclass
class MsgTxHashSetRequest:
    """Request a TxHashSet ZIP archive at a block hash/height.

    Wire body:
        32 bytes  block_hash
        8  bytes  BE height
    """

    msg_type = MessageType.TxHashSetRequest
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    height: int = 0

    def serialize(self) -> bytes:
        body = self.block_hash[:32].ljust(32, b"\x00") + struct.pack(">Q", self.height)
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgTxHashSetRequest":
        block_hash = body[:32]
        (height,) = struct.unpack_from(">Q", body, 32)
        return cls(block_hash=block_hash, height=height)


@dataclass
class MsgTxHashSetArchive:
    """Response with TxHashSet archive metadata.

    Wire body:
        32 bytes  block_hash
        8  bytes  BE height
        8  bytes  BE bytes_len

    Archive bytes follow the message body as a streamed attachment and are not
    included in the message frame.
    """

    msg_type = MessageType.TxHashSetArchive
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    height: int = 0
    zip_bytes: bytes = b""
    bytes_len: Optional[int] = None

    def serialize(self) -> bytes:
        bytes_len = len(self.zip_bytes) if self.bytes_len is None else self.bytes_len
        body = (
            self.block_hash[:32].ljust(32, b"\x00")
            + struct.pack(">QQ", self.height, bytes_len)
        )
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgTxHashSetArchive":
        block_hash = body[:32]
        height, bytes_len = struct.unpack_from(">QQ", body, 32)
        return cls(
            block_hash=block_hash,
            height=height,
            zip_bytes=b"",
            bytes_len=bytes_len,
        )


@dataclass
class MsgBanReason:
    """Sent just before disconnecting a banned peer."""

    msg_type = MessageType.BanReason
    ban_reason: str = ""

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, _encode_str(self.ban_reason))

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgBanReason":
        message, _ = _decode_str(body, 0)
        return cls(ban_reason=message)


# ---------------------------------------------------------------------------
# PIBD segment request / response messages
# ---------------------------------------------------------------------------


@dataclass
class MsgGetOutputBitmapSegment:
    """Request a bitmap segment."""

    msg_type = MessageType.GetOutputBitmapSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        body = self.block_hash[:32].ljust(32, b"\x00")
        if self.identifier is not None:
            body += self.identifier.serialize()
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetOutputBitmapSegment":
        block_hash = body[:32]
        identifier = None
        if len(body) >= 32 + 9:
            identifier = SegmentIdentifier.deserialize(body[32 : 32 + 9])
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgOutputBitmapSegment:
    """A bitmap segment response."""

    msg_type = MessageType.OutputBitmapSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        body = self.block_hash[:32].ljust(32, b"\x00")
        if self.segment is not None:
            seg_bytes = self.segment.serialize()
            body += struct.pack("<I", len(seg_bytes)) + seg_bytes
        return pack_header(self.msg_type, body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgOutputBitmapSegment":
        block_hash = body[:32]
        segment = None
        if len(body) > 32 + 4:
            (seg_len,) = struct.unpack_from("<I", body, 32)
            if seg_len > 0:
                segment = Segment.deserialize(body[36 : 36 + seg_len])
        return cls(block_hash=block_hash, segment=segment)


def _make_get_segment_msg(
    msg_type: MessageType, block_hash: bytes, identifier: SegmentIdentifier
) -> bytes:
    """Helper to build a GetXxxSegment body."""
    body = block_hash[:32].ljust(32, b"\x00") + identifier.serialize()
    return pack_header(msg_type, body)


def _parse_get_segment_body(body: bytes) -> Tuple[bytes, SegmentIdentifier]:
    """Parse a GetXxxSegment body: 32-byte hash + 9-byte SegmentIdentifier."""
    block_hash = body[:32]
    identifier = SegmentIdentifier.deserialize(body[32 : 32 + 9])
    return block_hash, identifier


def _make_segment_response(
    msg_type: MessageType, block_hash: bytes, segment: Segment
) -> bytes:
    """Helper to build a XxxSegment response body."""
    seg_bytes = segment.serialize()
    body = (
        block_hash[:32].ljust(32, b"\x00")
        + struct.pack("<I", len(seg_bytes))
        + seg_bytes
    )
    return pack_header(msg_type, body)


def _parse_segment_response(body: bytes) -> Tuple[bytes, Optional[Segment]]:
    """Parse a XxxSegment response body."""
    if len(body) < 32:
        raise ValueError("Segment response is missing its block hash")
    block_hash = body[:32]
    if len(body) == 32:
        return block_hash, None
    if len(body) < 36:
        raise ValueError("Segment response is missing its segment length")
    (seg_len,) = struct.unpack_from("<I", body, 32)
    end = 36 + seg_len
    if len(body) < end:
        raise ValueError("Segment response is truncated")
    if len(body) > end:
        raise ValueError("Segment response has trailing bytes")
    segment = Segment.deserialize(body[36:end]) if seg_len else None
    return block_hash, segment


@dataclass
class MsgGetOutputSegment:
    """Request an output PMMR segment."""

    msg_type = MessageType.GetOutputSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        if self.identifier is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_get_segment_msg(self.msg_type, self.block_hash, self.identifier)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetOutputSegment":
        block_hash, identifier = _parse_get_segment_body(body)
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgOutputSegment:
    """Output PMMR segment response."""

    msg_type = MessageType.OutputSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        if self.segment is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_segment_response(self.msg_type, self.block_hash, self.segment)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgOutputSegment":
        block_hash, segment = _parse_segment_response(body)
        return cls(block_hash=block_hash, segment=segment)


@dataclass
class MsgGetRangeProofSegment:
    """Request a rangeproof PMMR segment."""

    msg_type = MessageType.GetRangeProofSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        if self.identifier is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_get_segment_msg(self.msg_type, self.block_hash, self.identifier)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetRangeProofSegment":
        block_hash, identifier = _parse_get_segment_body(body)
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgRangeProofSegment:
    """Rangeproof PMMR segment response."""

    msg_type = MessageType.RangeProofSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        if self.segment is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_segment_response(self.msg_type, self.block_hash, self.segment)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgRangeProofSegment":
        block_hash, segment = _parse_segment_response(body)
        return cls(block_hash=block_hash, segment=segment)


@dataclass
class MsgGetKernelSegment:
    """Request a kernel MMR segment."""

    msg_type = MessageType.GetKernelSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    identifier: Optional[SegmentIdentifier] = None

    def serialize(self) -> bytes:
        if self.identifier is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_get_segment_msg(self.msg_type, self.block_hash, self.identifier)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgGetKernelSegment":
        block_hash, identifier = _parse_get_segment_body(body)
        return cls(block_hash=block_hash, identifier=identifier)


@dataclass
class MsgKernelSegment:
    """Kernel MMR segment response."""

    msg_type = MessageType.KernelSegment
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    segment: Optional[Segment] = None

    def serialize(self) -> bytes:
        if self.segment is None:
            return pack_header(self.msg_type, self.block_hash[:32].ljust(32, b"\x00"))
        return _make_segment_response(self.msg_type, self.block_hash, self.segment)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgKernelSegment":
        block_hash, segment = _parse_segment_response(body)
        return cls(block_hash=block_hash, segment=segment)


# ---------------------------------------------------------------------------
# Compact block
# ---------------------------------------------------------------------------


@dataclass
class MsgCompactBlock:
    """A compact block sent in response to ``GetCompactBlock``.

    Wire body (all LE):
        [BlockHeader bytes]
        8  bytes  nonce            uint64
        2  bytes  num_full_outputs uint16
        2  bytes  num_full_kernels uint16
        2  bytes  num_short_ids    uint16
        [full output bytes] * num_full_outputs
        [full kernel bytes] * num_full_kernels
        [6-byte short-id]  * num_short_ids

    Note: Full output/kernel parsing requires the serializer layer from
    ``mimblewimble.blockchain`` and is therefore done lazily on access.
    """

    msg_type = MessageType.CompactBlock
    # Raw body bytes — header + nonce + short-IDs; parsed on demand.
    raw_body: bytes = field(default_factory=bytes)
    block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def serialize(self) -> bytes:
        return pack_header(self.msg_type, self.raw_body)

    @classmethod
    def deserialize(cls, body: bytes) -> "MsgCompactBlock":
        # The block hash is not transmitted separately; callers should compute
        # it from the header inside raw_body if needed.
        return cls(raw_body=body, block_hash=b"\x00" * 32)
