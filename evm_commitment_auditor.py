#!/usr/bin/env python3
"""Recompute EVM transaction, receipt, and log-bloom commitments from JSON-RPC."""
import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Keccak-256, not hashlib.sha3_256.  This is the permutation from FIPS 202
# with Ethereum's original Keccak padding (domain suffix 0x01).
_RC = [
    1, 0x8082, 0x800000000000808A, 0x8000000080008000,
    0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009,
    0x8A, 0x88, 0x80008009, 0x8000000A,
    0x8000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(value, shift):
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(state):
    for rc in _RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def keccak256(data):
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - (len(padded) % rate) - 1) % rate))
    padded.append(0x80)
    state = [0] * 25
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
        if len(out) < 32:
            _keccak_f(state)
    return bytes(out[:32])


def rlp_encode(item):
    """Encode bytes or a list using Ethereum's Recursive Length Prefix."""
    if isinstance(item, int):
        item = int_to_bytes(item)
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        if len(item) <= 55:
            return bytes([0x80 + len(item)]) + item
        length = int_to_bytes(len(item))
        return bytes([0xb7 + len(length)]) + length + item
    if isinstance(item, (list, tuple)):
        payload = b"".join(rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xc0 + len(payload)]) + payload
        length = int_to_bytes(len(payload))
        return bytes([0xf7 + len(length)]) + length + payload
    raise TypeError("RLP accepts bytes, integers, or lists")


def int_to_bytes(value):
    if value < 0:
        raise ValueError("negative integer")
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def hex_bytes(value, allow_none=False):
    if value is None and allow_none:
        return b""
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("expected a 0x-prefixed hex value")
    text = value[2:]
    if len(text) % 2:
        text = "0" + text
    return bytes.fromhex(text)


def quantity(value):
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return int(value, 16)


def address(value):
    return hex_bytes(value, allow_none=True)


def access_list(value):
    return [[address(entry["address"]), [hex_bytes(k) for k in entry.get("storageKeys", [])]] for entry in (value or [])]


def authorization_list(value):
    result = []
    for entry in (value or []):
        result.append([
            quantity(entry.get("chainId")), address(entry["address"]), quantity(entry["nonce"]),
            quantity(entry.get("yParity", entry.get("v", "0x0"))),
            quantity(entry["r"]), quantity(entry["s"]),
        ])
    return result


def transaction_bytes(tx):
    """Return the exact typed or legacy transaction payload represented by tx."""
    raw = tx.get("rawTransaction") or tx.get("raw")
    if raw:
        return hex_bytes(raw)
    tx_type = quantity(tx.get("type", "0x0"))
    common = [quantity(tx["nonce"]), quantity(tx.get("gasPrice", tx.get("maxFeePerGas", "0x0"))), quantity(tx["gas"])]
    to_value = address(tx.get("to"))
    data = hex_bytes(tx.get("input", tx.get("data", "0x")))
    if tx_type == 0:
        return rlp_encode(common[:1] + [common[1], common[2], to_value, quantity(tx["value"]), data,
                                        quantity(tx["v"]), quantity(tx["r"]), quantity(tx["s"])])
    if tx_type == 1:
        payload = [quantity(tx["chainId"]), quantity(tx["nonce"]), quantity(tx["gasPrice"]),
                   quantity(tx["gas"]), to_value, quantity(tx["value"]), data, access_list(tx.get("accessList")),
                   quantity(tx.get("yParity", tx.get("v", "0x0"))), quantity(tx["r"]), quantity(tx["s"])]
    elif tx_type == 2:
        payload = [quantity(tx["chainId"]), quantity(tx["nonce"]), quantity(tx["maxPriorityFeePerGas"]),
                   quantity(tx["maxFeePerGas"]), quantity(tx["gas"]), to_value, quantity(tx["value"]), data,
                   access_list(tx.get("accessList")), quantity(tx.get("yParity", tx.get("v", "0x0"))),
                   quantity(tx["r"]), quantity(tx["s"])]
    elif tx_type == 3:
        payload = [quantity(tx["chainId"]), quantity(tx["nonce"]), quantity(tx["maxPriorityFeePerGas"]),
                   quantity(tx["maxFeePerGas"]), quantity(tx["gas"]), to_value, quantity(tx["value"]), data,
                   access_list(tx.get("accessList")), quantity(tx["maxFeePerBlobGas"]),
                   [hex_bytes(x) for x in tx.get("blobVersionedHashes", [])],
                   quantity(tx.get("yParity", tx.get("v", "0x0"))), quantity(tx["r"]), quantity(tx["s"])]
    elif tx_type == 4:
        payload = [quantity(tx["chainId"]), quantity(tx["nonce"]), quantity(tx["maxPriorityFeePerGas"]),
                   quantity(tx["maxFeePerGas"]), quantity(tx["gas"]), to_value, quantity(tx["value"]), data,
                   access_list(tx.get("accessList")), authorization_list(tx.get("authorizationList")),
                   quantity(tx.get("yParity", tx.get("v", "0x0"))), quantity(tx["r"]), quantity(tx["s"])]
    elif tx_type == 0x7e:
        # OP Stack deposit transaction envelope (type 0x7e). Deposits are
        # unsigned and are represented by their source hash and payload.
        payload = [hex_bytes(tx["sourceHash"]), address(tx["from"]), to_value,
                   quantity(tx.get("mint", "0x0")), quantity(tx["value"]), quantity(tx["gas"]),
                   b"\x01" if tx.get("isSystemTx", tx.get("isSystemTransaction", False)) else b"",
                   data]
    else:
        raise ValueError("unsupported transaction type 0x%x; supply rawTransaction if the RPC provides it" % tx_type)
    return bytes([tx_type]) + rlp_encode(payload)


def bloom_add(bloom, value):
    digest = keccak256(value)
    for offset in (0, 2, 4):
        bit = ((digest[offset] << 8) | digest[offset + 1]) & 2047
        bloom[255 - (bit >> 3)] |= 1 << (bit & 7)


def log_bloom(logs):
    bloom = bytearray(256)
    for log in logs:
        bloom_add(bloom, address(log["address"]))
        for topic in log.get("topics", []):
            bloom_add(bloom, hex_bytes(topic))
    return bytes(bloom)


def receipt_status_bytes(receipt):
    if receipt.get("status") is not None:
        # JSON-RPC quantities use 0x0 for a failed receipt. In RLP, integer
        # zero is the empty byte string, not the single byte 0x00.
        return int_to_bytes(quantity(receipt["status"]))
    if receipt.get("root") is not None:
        return hex_bytes(receipt["root"])
    raise ValueError("receipt has neither status nor post-state root")


def receipt_bytes(receipt, tx):
    status_or_root = receipt_status_bytes(receipt)
    logs = [[address(log["address"]), [hex_bytes(t) for t in log.get("topics", [])], hex_bytes(log.get("data", "0x"))]
            for log in receipt.get("logs", [])]
    payload = [status_or_root, quantity(receipt["cumulativeGasUsed"]), log_bloom(receipt.get("logs", [])), logs]
    tx_type = quantity(receipt.get("type", tx.get("type", "0x0")))
    if tx_type == 0x7e:
        # OP Stack deposit receipts extend the four EVM receipt fields.
        payload.extend([quantity(receipt["depositNonce"]),
                        quantity(receipt.get("depositReceiptVersion", "0x1"))])
    encoded = rlp_encode(payload)
    return (bytes([tx_type]) + encoded) if tx_type else encoded


def _nibbles(data):
    result = []
    for byte in data:
        result.extend((byte >> 4, byte & 15))
    return result


def _compact(path, leaf):
    odd = len(path) & 1
    flags = (2 if leaf else 0) + odd
    if odd:
        encoded = [flags] + path
    else:
        encoded = [flags, 0] + path
    output = bytearray()
    for i in range(0, len(encoded), 2):
        output.append((encoded[i] << 4) | encoded[i + 1])
    return bytes(output)


def _node_ref(encoded):
    return encoded if len(encoded) < 32 else keccak256(encoded)


def _trie_node(items):
    if len(items) == 1:
        path, value = items[0]
        return rlp_encode([_compact(path, True), value])
    common = 0
    while all(len(path) > common for path, _ in items) and len({path[common] for path, _ in items}) == 1:
        common += 1
    if common:
        child = _trie_node([(path[common:], value) for path, value in items])
        return rlp_encode([_compact(items[0][0][:common], False), _node_ref(child)])
    branches = []
    value_here = b""
    for nibble in range(16):
        group = [(path[1:], value) for path, value in items if path and path[0] == nibble]
        branches.append(_node_ref(_trie_node(group)) if group else b"")
    for path, value in items:
        if not path:
            value_here = value
            break
    return rlp_encode(branches + [value_here])


def trie_root(values):
    if not values:
        return keccak256(rlp_encode(b""))
    items = [(_nibbles(rlp_encode(index)), value) for index, value in enumerate(values)]
    return keccak256(_trie_node(items))


class RpcError(RuntimeError):
    pass


class RpcClient:
    def __init__(self, url):
        self.url = url
        self.next_id = 1

    def call(self, method, params):
        request = Request(self.url, data=json.dumps({"jsonrpc": "2.0", "id": self.next_id,
                                                       "method": method, "params": params}).encode(),
                          headers={"content-type": "application/json", "User-Agent": "evm-commitment-auditor/1.0"})
        self.next_id += 1
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RpcError(str(exc)) from exc
        if payload.get("error"):
            raise RpcError(payload["error"].get("message", "JSON-RPC error"))
        return payload.get("result")


def block_tag(value):
    if value in ("latest", "earliest", "pending", "safe", "finalized") or value.startswith("0x"):
        return value
    return hex(int(value, 10))


def audit_block(block, receipts):
    transactions = block.get("transactions", [])
    if not transactions or isinstance(transactions[0], str):
        raise ValueError("the RPC must return full transaction objects")
    tx_values = [transaction_bytes(tx) for tx in transactions]
    receipt_values = [receipt_bytes(receipt, tx) for receipt, tx in zip(receipts, transactions)]
    computed_tx = trie_root(tx_values).hex()
    computed_receipts = trie_root(receipt_values).hex()
    computed_bloom = bytearray(256)
    receipt_blooms = []
    for receipt in receipts:
        rb = log_bloom(receipt.get("logs", []))
        receipt_blooms.append(rb.hex())
        for i, byte in enumerate(rb):
            computed_bloom[i] |= byte
    expected_tx = hex_bytes(block["transactionsRoot"]).hex()
    expected_receipts = hex_bytes(block["receiptsRoot"]).hex()
    expected_bloom = hex_bytes(block["logsBloom"]).hex()
    checks = {
        "transactionsRoot": computed_tx == expected_tx,
        "receiptsRoot": computed_receipts == expected_receipts,
        "logsBloom": bytes(computed_bloom).hex() == expected_bloom,
    }
    return {
        "blockNumber": quantity(block["number"]),
        "blockHash": block.get("hash"),
        "transactionCount": len(transactions),
        "computed": {"transactionsRoot": "0x" + computed_tx, "receiptsRoot": "0x" + computed_receipts,
                     "logsBloom": "0x" + bytes(computed_bloom).hex()},
        "expected": {"transactionsRoot": block["transactionsRoot"], "receiptsRoot": block["receiptsRoot"],
                     "logsBloom": block["logsBloom"]},
        "receiptBlooms": receipt_blooms,
        "checks": checks,
        "ok": all(checks.values()),
    }


def run(url, block_ref):
    rpc = RpcClient(url)
    block = rpc.call("eth_getBlockByNumber", [block_tag(block_ref), True])
    if block is None:
        raise RpcError("block not found")
    receipts = [rpc.call("eth_getTransactionReceipt", [tx["hash"]]) for tx in block["transactions"]]
    if any(receipt is None for receipt in receipts):
        raise RpcError("a transaction receipt was not returned")
    return audit_block(block, receipts)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Recompute EVM block commitments from JSON-RPC")
    parser.add_argument("rpc_url")
    parser.add_argument("block", help="block number, 0x quantity, or latest/finalized")
    parser.add_argument("--json", action="store_true", help="print the full JSON result")
    args = parser.parse_args(argv)
    try:
        result = run(args.rpc_url, args.block)
    except (RpcError, ValueError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("block %s %s" % (result["blockNumber"], result["blockHash"]))
        print("transactions: %s (%d)" % ("PASS" if result["checks"]["transactionsRoot"] else "FAIL", result["transactionCount"]))
        print("receipts: %s" % ("PASS" if result["checks"]["receiptsRoot"] else "FAIL"))
        print("logsBloom: %s" % ("PASS" if result["checks"]["logsBloom"] else "FAIL"))
        print("overall: %s" % ("PASS" if result["ok"] else "FAIL"))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
