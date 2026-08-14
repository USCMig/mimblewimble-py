from pathlib import Path
from types import SimpleNamespace

from mimblewimble.mmr.pibd import SyncState, SyncStatus
from mimblewimble.mmr.pibd_params import TXHASHSET_ZIP_FALLBACK_TIME_SECS
from mimblewimble.mmr.txhashset import TxHashSet
from mimblewimble.p2p import state_sync
from mimblewimble.p2p.state_sync import StateSync


class _PeerQuery:
    def __init__(self, peers):
        self._peers = peers

    def pick(self):
        return self._peers[0] if self._peers else None

    def pick_n(self, count):
        return self._peers[:count]

    def highest_difficulty(self):
        return self


class _SnapshotPeer:
    addr = "peer:3414"

    def request_txhashset(self, block_hash, height):
        self.request = (block_hash, height)


class _Peers:
    def __init__(self, snapshot_peer):
        self.snapshot_peer = snapshot_peer

    def pibd_capable(self):
        return _PeerQuery([])

    def txhashset_capable(self):
        return _PeerQuery([self.snapshot_peer])


class _Adapter:
    pass


class _Desegmenter:
    def is_complete(self):
        return False


def test_snapshot_fallback_starts_without_a_pibd_peer(tmp_path: Path, monkeypatch):
    snapshot_peer = _SnapshotPeer()
    txhashset = TxHashSet(tmp_path / "txhashset")
    txhashset.desegmenter = lambda archive, genesis: _Desegmenter()
    runner = StateSync(
        adapter=_Adapter(),
        peers=_Peers(snapshot_peer),
        sync_state=SyncState(),
        txhashset=txhashset,
        data_dir=tmp_path / "data",
    )
    archive_header = SimpleNamespace(
        height=42,
        getHash=lambda: b"\x11" * 32,
    )
    clock = iter(
        (
            100.0,
            100.0,
            100.0 + TXHASHSET_ZIP_FALLBACK_TIME_SECS + 1,
            100.0 + TXHASHSET_ZIP_FALLBACK_TIME_SECS + 1,
        )
    )
    monkeypatch.setattr(state_sync.time, "monotonic", lambda: next(clock))

    assert not runner.check_run(archive_header, None, b"\x11" * 32)
    assert runner._pibd_peer_last_seen == 100.0

    assert runner.check_run(archive_header, None, b"\x11" * 32)
    assert runner._sync_state.status is SyncStatus.TXHASHSET_DOWNLOAD
    assert snapshot_peer.request == (b"\x11" * 32, 42)

    txhashset.close()