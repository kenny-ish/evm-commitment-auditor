import base64
import json
import pathlib
import sys
import unittest
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import evm_commitment_auditor as m

# Three real receipt responses from Ethereum mainnet block 19000000. They
# cover legacy, type 1, and type 2 receipts and include a failed status.
RECEIPT_FIXTURE = (
    'eNrtmMtuW0cMht9F6yw4nAtn8gJtN10U7arIgsNLa8SODEsOUgR591IW7DgqEsmR7SaBuDo6R4dz4cefPPN+cWViZ5fr1W/L5Xrx'
    'cgHvStEZNtCgZpMKGVolcbJeCzRsgEw6WakP8FmyQAIYmjQPZ6+LF4u3Juvl1Wrx8s/3i/U/l3bjF+LBas3r69XNzxQ/5fri+pzX'
    'Z2/tJ179sTLdPkmjJonH58u/tj5Y9cpW2/ckhmfOYyJmt67AYFWKIxnrgJ6FahPBeH+9vDyTjYd4TdWxImuahtLHbENwQusumboy'
    'j4qTyVPLUjilht1r5aJeMc9sHu5iCftMXY3U2LGk3AlxdJLBbYxkqOWLTgr3FlupjUar3mXmWBszSquVoForMEhyWrx6sVBe83ZT'
    'H2gVtM3hDSWCNfMmJvN8Ka9/5tXf2+313AsknCNN6AkziHoizk6qmUC7tZhNg9rZ20TCmGctMU9KxVluHf56fTHtahtPTMZyN9Tv'
    'ZxcWHFxc3jxsldGS5E24rvjNimV9tnxzNx0aSI2wEISL3I1TkxgtqSFITIFm7bV3rgrQN+OMlMAdNLgEuVnfPbe/vFF7tx12i9fH'
    'G9jjzpVdLN9uKHQ+X9mHF5+SB45KaRQg12kxyNBOERuekzBHXiTX4Tiek7yDoXkUfL+avFIpQuizuVeZDB1O5N2RN/aS94Ao3ycv'
    'SUnJBo9mQCliKuiYnAjbjI21PiwLzyLUp1WwEPcJmYe7z9D3r1Ya3LCeOGjKrpgtksbxYTqVC9cUOg6NlDuK9hMvt7zwU/ESFT1K'
    'aHUuTcYoM/6dFGL/qwtSdWspi2WKdsBn12pZU4ZNEGpIIeLT18inV6pHsN0ae6xSHmunzLnNnPnfzHm1yZ27HjUd2qMWU3f+2KN+'
    '6gYPdZNDKuH763RDFcKCIpEEcY29UOEhKWitfcL4cr/hlbVhoOXhCghlxCy01RxEQtY+iou463FZnLWUPtv3kgWhXrF6TiHZIbMz'
    'JEBCt3PHkLna84hNLwJENcq2RCtatUGZoeJMiSjZ57IAdrMA9paPcO5NOzCV7Jy4RbsbMykYA02caLnPZOVZG92DmXkUeo8BL9Ys'
    'PQOewNsBL+0H7/Agfwt97o3FEGkkxZ49YlrbA18vXRDqbFytYBTAecLltlo/FS7P0OYeWSCfRad2C+T3Zied/Uzi5L2J88N2lp1G'
    'Gex9dpy1zalVTGxCZLqW2FcIqd5o9XGJM2e0R8HUCbxPwSt7wevd4/suV6sVNkuND9y4ji/l0aVYrCHAUUn5OcE7mJn/XbEJOxTg'
    'fgJvB7y6H7zDg/ytdJbZhKSOkbsihUt4OC7kYxg2kzJKwRMu9w6GngSXU2f5OLZTYI/VyR/9APXZEof2nZ/uHHzCZw8+caOX+f75'
    '6asP/wI3mrAt'
)


def fixture():
    return json.loads(zlib.decompress(base64.b64decode(RECEIPT_FIXTURE)))


class CommitmentTests(unittest.TestCase):
    def test_keccak_vectors_and_table_sizes(self):
        self.assertEqual(sum(len(row) for row in m._ROT), 25)
        self.assertEqual(len(m._RC), 24)
        self.assertEqual(m._ROT[-1], [27, 20, 39, 8, 14])
        self.assertEqual(m.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(m.keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_rlp_known_values(self):
        self.assertEqual(m.rlp_encode(b"dog").hex(), "83646f67")
        self.assertEqual(m.rlp_encode([b"cat", b"dog"]).hex(), "c88363617483646f67")

    def test_real_ethereum_19000000_receipt_vectors(self):
        data = fixture()
        self.assertEqual(data["receiptsRoot"], "0x44dbbbb92e053ec5030657cf7e854062602a7dbad7890fb43c01009d1d39faf5")
        self.assertEqual([x["type"] for x in data["vectors"]], ["0x0", "0x1", "0x2", "0x2"])
        for receipt in data["vectors"]:
            encoded = m.receipt_bytes(receipt, {"type": receipt["type"]})
            self.assertTrue(encoded)
            if receipt["type"] != "0x0":
                self.assertEqual(encoded[0], int(receipt["type"], 16))

    def test_failed_receipt_status_zero_is_empty_rlp_string(self):
        failed = next(x for x in fixture()["vectors"] if x.get("status") == "0x0")
        self.assertEqual(m.receipt_status_bytes(failed), b"")
        encoded = m.receipt_bytes(failed, {"type": failed["type"]})
        self.assertEqual(encoded[0], 2)
        self.assertEqual(encoded[1], 0xf9)

    def test_empty_log_bloom(self):
        self.assertEqual(m.log_bloom([]), b"\0" * 256)


if __name__ == "__main__":
    unittest.main()
