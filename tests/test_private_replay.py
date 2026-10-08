"""Optional local-only corpus checks. Never copy private captures into Git.

Set DECODER_PRIVATE_FIXTURES to the Android project's testdata/private folder.
No Android source, Java executable, Gradle, or live device is used by these tests.
"""
import json
import os
import struct
import unittest
from pathlib import Path

import dev_diag_decoder as cli
from decoder_core.capture import json_safe, UnsupportedPacket
from decoder_core.diag import routed_frames
from decoder_profiles.registry import resolve_profile
from decoder_profiles.poco_x3_surya.decoders import ReferenceDecoders
from decoder_profiles.mi_11_lite_lisa.decoders import LisaDecoders
from decoder_modules.nsg_rrc import decode_rrc

FIXTURES=os.environ.get('DECODER_PRIVATE_FIXTURES')


@unittest.skipUnless(FIXTURES,'optional private corpus not configured')
class PrivateReplayTests(unittest.TestCase):
    def setUp(self):self.root=Path(FIXTURES)

    def test_poco_37_frozen_golden_results(self):
        vectors=json.loads((self.root/'nsg-golden-vectors.json').read_text(encoding='utf-8'))['vectors']
        self.assertEqual(len(vectors),37)
        for row in vectors:
            with self.subTest(schema=row['schema_id']):
                body=bytes.fromhex(row['body_hex'])+bytes(row.get('zero_pad_bytes',0))
                log_id=int(row['log_id'],16) if isinstance(row['log_id'],str) else row['log_id']
                schema,value=ReferenceDecoders().decode(bytes(24)+body+bytes(2),log_id)
                value=json_safe(value)
                if log_id==0xb0c0 and 'rrc' not in row['expected']:value.pop('rrc',None)
                self.assertEqual(schema,row['schema_id'])
                self.assertEqual(value,row['expected'])

    def test_poco_258_rrc_trees(self):
        transports={'BCCH-DL-SCH':2,'PCCH':5,'DL-CCCH':6,'DL-DCCH':7,'UL-CCCH':8,'UL-DCCH':9}
        count=0
        for line in (self.root/'poco-x3-rrc-corpus.tsv').read_text(encoding='utf-8').splitlines():
            if not line or line.startswith('#'):continue
            transport,payload,message,tree=line.split('\t')
            value=decode_rrc(transports[transport.replace('_','-')],bytes.fromhex(payload))
            self.assertEqual(value['message'],message)
            self.assertEqual(value['asn1_tree'],json.loads(tree));count+=1
        self.assertEqual(count,258)

    def test_lisa_32_frozen_locators(self):
        root=self.root/'mi11-lite'
        metadata=json.loads((root/'phase7.1.1/vector-metadata-v1.json').read_text(encoding='utf-8'))
        successful=unsupported=0
        for row in metadata['routes']:
            data=(root/row['file']).read_bytes();cursor=64
            for index in range(row['container_record_index']+1):
                length=struct.unpack_from('<I',data,cursor+12)[0]
                payload=data[cursor+24:cursor+24+length];cursor+=24+length
            frame,log_id,_=next(routed_frames(payload))
            self.assertIsNone(frame.failure)
            self.assertEqual(log_id,int(row['log_id'],16))
            try:LisaDecoders().decode(frame,log_id);successful+=1
            except UnsupportedPacket:unsupported+=1
        self.assertEqual((successful,unsupported),(23,9))

    def test_real_pxdg_captures(self):
        # Both explicitly selected profiles; capture absence never changes selection.
        poco=self.root/'phase10.8-step3/phase10.1-smoke.pxdg'
        lisa=self.root/'mi11-lite/follow-up/preexisting-app-captures/capture-20260913T120409Z-d2338b48.pxdg'
        for profile,capture in (('surya',poco),('lisa',lisa)):
            with self.subTest(profile=profile):
                events=cli.decode_capture(capture,profile=resolve_profile(profile))
                self.assertGreater(events[-1]['decoded'],0)
                self.assertEqual(events[-1]['malformed'],0)
                self.assertEqual(events[-1]['device']['selection_mode'],'explicit')


if __name__=='__main__':unittest.main()
