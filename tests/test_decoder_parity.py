import unittest

from decoder_modules import nsg_geran, nsg_gmm, nsg_nas_correlation, nsg_rrc
from decoder_modules.nsg_schema_registry import SCHEMAS, registry_manifest


def gmm_wrapper(direction, payload_hex):
    payload = bytes.fromhex(payload_hex)
    return (
        bytes([2, direction, payload[1]])
        + len(payload).to_bytes(2, "little")
        + payload
        + bytes(250)
    )


class DecoderParityTest(unittest.TestCase):
    def test_registry_contains_all_java_manifest_routes(self):
        self.assertEqual(len(SCHEMAS), 37)
        self.assertEqual(
            [item["schema_id"] for item in registry_manifest()][-2:],
            [
                "geran-rr-dsds-signaling-5b2f-unversioned",
                "gprs-dsds-sm-gmm-signaling-5c30-unversioned",
            ],
        )

    def test_geran_ciphering_golden_tree(self):
        result = nsg_geran.decode_5b2f(bytes.fromhex("02803503063515"))
        rr = result["rr"]
        self.assertEqual(rr["decoder_class"], "RRCipheringModeCmd")
        self.assertEqual(rr["algorithm_name"], "A5/3")
        self.assertEqual(
            rr["decoded_fields"]["RRCipheringModeCmd"][0]["RRHeader"],
            [{"SkipInd": 0}, {"ProtDisc": 6}, {"Type": 53}],
        )

    def test_geran_paging_response_tmsi_and_imsi(self):
        tmsi = nsg_geran.decode_5b2f(
            bytes.fromhex("0200270d0627070323198005f41234abcd")
        )["rr"]
        self.assertEqual(tmsi["message"], "PAGING_RESPONSE")
        self.assertEqual(tmsi["identity"]["tmsi"], 0x1234ABCD)
        imsi = nsg_geran.decode_5b2f(
            bytes.fromhex("0200271006270103600000080910101032547698")
        )["rr"]
        self.assertEqual(imsi["identity"]["imsi_digits"], "001010123456789")

    def test_gmm_authentication_request_response_and_reject(self):
        request = nsg_gmm.decode_5c30(gmm_wrapper(
            1,
            "081213a121000102030405060708090a0b0c0d0e0f852810"
            "101112131415161718191a1b1c1d1e1f",
        ))["gmm"]
        self.assertEqual(request["ciphering_algorithm_name"], "GEA/3")
        self.assertEqual(request["ciphering_key_sequence"], 5)
        response = nsg_gmm.decode_5c30(gmm_wrapper(
            0, "08130a220102030423090300000000000000f0290405060708"
        ))["gmm"]
        self.assertEqual(response["imeisv"]["digits"], "0000000000000000")
        reject = nsg_gmm.decode_5c30(gmm_wrapper(1, "0814"))["gmm"]
        self.assertEqual(reject["message"], "AUTHENTICATION_AND_CIPHERING_REJECT")

    def test_gmm_routing_area_update_request_and_reject(self):
        request = nsg_gmm.decode_5c30(gmm_wrapper(
            0, "08085b1300621234560500000000001805f41234abcd6a0121390163"
        ))["gmm"]
        self.assertEqual(request["update_type_name"], "periodic updating")
        self.assertEqual(request["optional_elements"][0]["value"]["ptmsi"], 0x1234ABCD)
        reject = nsg_gmm.decode_5c30(gmm_wrapper(1, "080b11002a01213a01a2"))["gmm"]
        self.assertEqual(reject["gmm_cause_name"], "Network failure")
        self.assertEqual(reject["optional_elements"][0]["value"]["seconds"], 60)

    def test_rrc_release14_full_observed_tree(self):
        result = nsg_rrc.decode_rrc(5, bytes.fromhex("40068c37db1de0"))
        self.assertEqual(result["status"], "DECODED")
        self.assertEqual(result["message"], "PAGING")
        self.assertEqual(result["semantic_depth"], "full-observed-message-tree")
        identity = result["asn1_tree"]["message"][1][1]["pagingRecordList"][0]["ue-Identity"]
        self.assertEqual(identity[0], "s-TMSI")
        self.assertEqual(identity[1]["m-TMSI"], [3279794654, 32])

    def test_protected_nas_correlation_matches_java_rules(self):
        protected = {
            "index": 100, "timestamp_nanos": 1_000_000, "log_id": "0xB0EA",
            "fields": {"form": "security-protected", "direction": "MT", "nas": {
                "payload_length": 10, "security_header_type": 2,
            }},
        }
        plain = {
            "index": 101, "timestamp_nanos": 1_000_500, "log_id": "0xB0EC",
            "fields": {"form": "plain", "direction": "MT", "nas": {
                "payload_length": 4, "message": "UNKNOWN_NAS_MESSAGE",
            }},
        }
        pairs = nsg_nas_correlation.correlate([protected, plain], 2, 1_000)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0]["frame_distance"], 1)
        self.assertEqual(pairs[0]["time_distance_nanos"], 500)


if __name__ == "__main__":
    unittest.main()
