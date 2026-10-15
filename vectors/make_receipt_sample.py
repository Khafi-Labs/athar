"""Regenerate vectors/receipt_sample.json and receipt_sample.pub.

The key below is a PUBLIC TEST SEED (RFC 8032 test vector 1). It must never be
used to sign real receipts. Run from the repository root:

    PYTHONPATH=src:. python vectors/make_receipt_sample.py
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from athar.crypto.merkle import MerkleTree
from athar.crypto.signing import SigningKeyPair
from athar.log.anchoring import SimulatedAnchor
from athar.log.fact_log import Fact, FactLog
from athar.receipt.builder import ReceiptBuilder, RetrievalTestResult

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    key = SigningKeyPair("sample-test-key", SEED, PUB)
    ts = datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC)
    fact = Fact.create(
        subject_pseudonym="subj_sample_0001",
        purpose="kyc_verification",
        scope_description="sample scope: database, filestore, cache, search_index",
        policy_hash="11" * 32,
        surfaces_purged=4,
        salt=b"\x01" * 32,
        fact_id="00000000-0000-4000-8000-000000000001",
        timestamp=ts,
        nonce="22" * 32,
    )
    log = FactLog(merkle_tree=MerkleTree(), signing_key=key)
    idx = log.append_fact(fact)
    batch = log.batch_sign()
    token = SimulatedAnchor(signing_key=key).anchor(bytes.fromhex(batch.merkle_root))
    receipt = ReceiptBuilder.build(
        fact=fact,
        leaf_index=idx,
        inclusion_proof=log.get_inclusion_proof(idx),
        batch=batch,
        anchor_token=token,
        retrieval_test=RetrievalTestResult("2026-10-13", 4, "not_recoverable"),
        signing_key=key,
    )
    with open(os.path.join(HERE, "receipt_sample.json"), "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)
    with open(os.path.join(HERE, "receipt_sample.pub"), "w", encoding="utf-8") as f:
        f.write(key.public_key_hex + "\n")


if __name__ == "__main__":
    main()
