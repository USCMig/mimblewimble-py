from mimblewimble.mmr.pibd import SyncStatus
from mimblewimble.p2p.syncer import SyncRunner


class _Peer:
    addr = "peer:3414"

    def __init__(self):
        self.requested_blocks = []

    def is_alive(self):
        return True

    def request_block(self, block_hash):
        self.requested_blocks.append(block_hash)

    def request_peer_addrs(self):
        pass


class _PeerQuery:
    def __init__(self, peer):
        self._peer = peer

    def live(self):
        return self

    def highest_difficulty(self):
        return self

    def pick(self):
        return self._peer

    def pick_n(self, count):
        return [self._peer][:count]


class _Peers:
    def __init__(self, peer):
        self._query = _PeerQuery(peer)

    def count(self):
        return 1

    def live(self):
        return self._query


class _Adapter:
    def __init__(self, block_hash):
        self.block_hash = block_hash
        self.body_sync_handler = None

    def best_height(self):
        return 1

    def get_block_hash_at_height(self, height):
        return self.block_hash if height == 1 else None

    def set_body_sync_handler(self, handler):
        self.body_sync_handler = handler

    def total_difficulty(self):
        return 0

    def get_locator(self):
        return [b"\x00" * 32]

    def request_body_completion(self):
        assert self.body_sync_handler is not None


def test_runner_body_sync_reaches_no_sync_after_block_callback(tmp_path):
    block_hash = b"\x42" * 32
    peer = _Peer()
    adapter = _Adapter(block_hash)
    runner = SyncRunner(adapter, _Peers(peer), txhashset=None, data_dir=tmp_path)
    runner.sync_state.update(SyncStatus.BODY_SYNC)

    runner.run_once()

    assert peer.requested_blocks == [block_hash]
    assert runner.get_body_sync() is not None
    assert adapter.body_sync_handler is not None

    adapter.body_sync_handler(block_hash.hex())
    runner.run_once()

    assert runner.sync_state.status is SyncStatus.NO_SYNC
    assert runner.is_done()
