from mimblewimble.mmr.segment import SegmentType
from mimblewimble.blockchain import BlockHeader, ProofOfWork
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.p2p.chain_adapter_impl import ConcreteChainAdapter
from mimblewimble.pow.blockdb import SQLiteBlockDB


def test_adapter_forwards_pibd_segments_to_active_handler():
    adapter = ConcreteChainAdapter(genesis_hash=b"\x00" * 32)
    received = []
    block_hash = b"\x01" * 32

    adapter.set_pibd_segment_handler(
        lambda segment_type, received_hash, segment: received.append(
            (segment_type, received_hash, segment)
        )
    )

    adapter.receive_bitmap_segment(block_hash, "bitmap")
    adapter.receive_output_segment(block_hash, "output")
    adapter.receive_rangeproof_segment(block_hash, "rangeproof")
    adapter.receive_kernel_segment(block_hash, "kernel")

    assert received == [
        (SegmentType.BITMAP, block_hash, "bitmap"),
        (SegmentType.OUTPUT, block_hash, "output"),
        (SegmentType.RANGEPROOF, block_hash, "rangeproof"),
        (SegmentType.KERNEL, block_hash, "kernel"),
    ]


def _make_header(height: int, total_difficulty: int) -> BlockHeader:
    return BlockHeader(
        version=5,
        height=height,
        timestamp=1_000_000 + height,
        previousBlockHash=b"\x00" * 32,
        previousRoot=b"\x00" * 32,
        outputRoot=b"\x00" * 32,
        rangeProofRoot=b"\x00" * 32,
        kernelRoot=b"\x00" * 32,
        totalKernelOffset=BlindingFactor(b"\x00" * 32),
        outputMMRSize=0,
        kernelMMRSize=0,
        totalDifficulty=total_difficulty,
        scalingDifficulty=1,
        nonce=height,
        proofOfWork=ProofOfWork(29, [0] * 42),
    )


def test_sqlite_block_db_restores_adapter_tip_after_restart(tmp_path):
    path = tmp_path / "chain.sqlite"
    first = SQLiteBlockDB(path)
    low_header = _make_header(height=4, total_difficulty=40)
    best_header = _make_header(height=5, total_difficulty=50)
    first.add_header(low_header)
    first.add_header(best_header)
    first.close()

    restored = SQLiteBlockDB(path)
    adapter = ConcreteChainAdapter(genesis_hash=b"\x00" * 32, block_db=restored)

    assert restored.get_block_header(low_header.getHash().hex()).getHash() == low_header.getHash()
    assert restored.get_header_by_height(5).getHash() == best_header.getHash()
    assert adapter.best_height() == 5
    assert adapter.total_difficulty() == 50
    assert adapter.get_locator()[0] == best_header.getHash()
    restored.close()