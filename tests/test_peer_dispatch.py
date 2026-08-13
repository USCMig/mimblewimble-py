import struct
from typing import cast

from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.connection import Connection
from mimblewimble.p2p.handshake import HandshakeResult
from mimblewimble.p2p.message import MessageType, MsgHeaders
from mimblewimble.p2p.peer import Peer
from mimblewimble.p2p.peers import NodeStorageInMemory, PeerStore
from mimblewimble.genesis import mainnet
from mimblewimble.serializer import Serializer


class _FakeConn:
    def __init__(self):
        self.peer_addr = "127.0.0.1:13414"
        self.closed = False

    def send_raw(self, data: bytes):
        return None

    def close(self):
        self.closed = True


class _FakeHandshake:
    genesis_block_difficulty = 1

    def supports_pibd(self):
        return True

    def supports_txhashset(self):
        return True


class _Adapter:
    def __init__(self):
        self.headers = []
        self.txhashset_archives = []

    def sync_block_headers(self, raw_headers):
        self.headers.extend(raw_headers)

    def txhashset_write(self, block_hash: bytes, height: int, zip_bytes: bytes):
        self.txhashset_archives.append((block_hash, height, zip_bytes))
        return True

    def txhashset_write_stream(self, block_hash, height, archive, size):
        self.txhashset_archives.append((block_hash, height, archive.read()))
        assert size == len(self.txhashset_archives[-1][2])
        return True

    def receive_bitmap_segment(self, block_hash: bytes, segment):
        return None

    def receive_output_segment(self, block_hash: bytes, segment):
        return None

    def receive_rangeproof_segment(self, block_hash: bytes, segment):
        return None

    def receive_kernel_segment(self, block_hash: bytes, segment):
        return None


def _headers_body(headers: list[bytes]) -> bytes:
    return MsgHeaders(headers=headers).serialize()[11:]


def _header_bytes(height_delta: int = 0) -> bytes:
    header = mainnet.getHeader()
    serializer = Serializer()
    header.serialize(serializer)
    raw = bytearray(serializer.getvalue())
    raw[9] = (raw[9] + height_delta) % 256
    return bytes(raw)


def test_peer_dispatch_headers_persists_via_peer_store():
    adapter = _Adapter()
    storage = NodeStorageInMemory()
    peers = PeerStore(node_storage=storage)

    peer = Peer(
        conn=cast(Connection, _FakeConn()),
        handshake=cast(HandshakeResult, _FakeHandshake()),
        adapter=cast(ChainAdapter, adapter),
        peer_store=peers,
    )

    h1 = _header_bytes()
    h2 = _header_bytes(1)
    peer._dispatch(MessageType.Headers, _headers_body([h1, h2]))

    assert adapter.headers == [h1, h2]
    stored = peers.get_headers()
    assert len(stored) == 2
    assert {stored[0].raw, stored[1].raw} == {h1, h2}


def test_peer_dispatch_single_header_persists_via_peer_store():
    adapter = _Adapter()
    storage = NodeStorageInMemory()
    peers = PeerStore(node_storage=storage)

    peer = Peer(
        conn=cast(Connection, _FakeConn()),
        handshake=cast(HandshakeResult, _FakeHandshake()),
        adapter=cast(ChainAdapter, adapter),
        peer_store=peers,
    )

    raw_header = b"single-header"
    peer._dispatch(MessageType.Header, raw_header)

    assert adapter.headers == [raw_header]
    stored = peers.get_headers()
    assert len(stored) == 1
    assert stored[0].raw == raw_header


def test_peer_dispatch_txhashset_archive_passes_streamed_attachment():
    adapter = _Adapter()
    peer = Peer(
        conn=cast(Connection, _FakeConn()),
        handshake=cast(HandshakeResult, _FakeHandshake()),
        adapter=cast(ChainAdapter, adapter),
    )
    block_hash = b"\x33" * 32
    attachment = b"PK\x03\x04archive"
    metadata = block_hash + struct.pack(">QQ", 42, len(attachment))

    peer._dispatch(MessageType.TxHashSetArchive, metadata, attachment)

    assert adapter.txhashset_archives == [(block_hash, 42, attachment)]
