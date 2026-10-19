# evm-commitment-auditor

evm-commitment-auditor recomputes an EVM block's transaction trie root, receipt trie root, and log bloom from JSON-RPC responses. It checks whether an RPC provider returned data that is consistent with the commitments stored in the block header.

## Example

This was run against Ethereum mainnet through `https://eth.drpc.org`.

    $ python evm_commitment_auditor.py https://eth.drpc.org 19000000
    block 19000000 0xcf384012b91b081230cdf17a3f7dd370d8e67056058af6b272b3d54aa2714fac
    transactions: PASS (133)
    receipts: PASS
    logsBloom: PASS
    overall: PASS

A second live run used the Optimism mainnet RPC at block 2.

    $ python evm_commitment_auditor.py https://mainnet.optimism.io 2
    block 2 0x45fd6ce41bb8ebb2bccdaa92dd1619e287704cb07722039901a7eba63dea1d13
    transactions: PASS (1)
    receipts: PASS
    logsBloom: PASS
    overall: PASS

## Usage

    python evm_commitment_auditor.py RPC_URL BLOCK
    python evm_commitment_auditor.py RPC_URL BLOCK --json

`BLOCK` may be a decimal block number, a hexadecimal quantity, or `latest`, `safe`, or `finalized`. The RPC must support `eth_getBlockByNumber` with full transactions and `eth_getTransactionReceipt`.

## How it works

Transactions and receipts are serialized with Ethereum RLP. Typed receipts use the transaction type byte followed by the receipt RLP. A failed receipt status of `0x0` is encoded as the empty RLP byte string. The tool supports legacy, access-list, EIP-1559, blob, and authorization-list transaction fields. It builds the hexary Merkle Patricia Trie with the transaction or receipt index as the key and Keccak-256 as the hash function. It recomputes each log bloom before comparing the aggregate bloom with the block header.

## Tests

    python -m unittest -v

Tests do not access the network. The receipt-root test contains fixed RPC data from Ethereum mainnet block 19000000, including legacy, type 1, and type 2 receipts.
