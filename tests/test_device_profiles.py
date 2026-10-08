"""Public synthetic vectors only. These tests require neither Android nor Java."""
import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

import dev_diag_decoder as cli
from decoder_core.capture import UnsupportedPacket, CaptureFormatError, iter_pxdg
from decoder_core.diag import crc16, routed_frames
from decoder_profiles.registry import resolve_profile, registered_profiles
from decoder_profiles.base import DeviceProfile, Schema
from decoder_core.dispatcher import RoutedSchemaDispatcher
from decoder_profiles.mi_11_lite_lisa.schemas import SCHEMAS, ROUTES
from decoder_profiles.mi_11_lite_lisa.decoders import LisaDecoders
from decoder_modules import eps_nas, nr_rrc

VECTORS=json.loads((Path(__file__).parent/'vectors/lisa_golden.json').read_text(encoding='utf-8'))['vectors']


def routed(log_id, body, wrapper='multi-radio-v1', radio=1, peripheral=1):
    header=bytes((0x10,0))+struct.pack('<HHH',len(body)+12,len(body)+12,log_id)+bytes(8)
    if wrapper!='direct':header=bytes((0x98,1,0,0))+struct.pack('<I',radio)+header
    frame=header+body
    frame+=struct.pack('<H',crc16(frame))
    escaped=bytearray()
    for value in frame:
        escaped.extend((0x7d,value^0x20) if value in (0x7d,0x7e) else (value,))
    escaped.append(0x7e)
    return struct.pack('<III',32,peripheral,len(escaped))+escaped


def capture(*payloads):
    return struct.pack('<4sHHII',b'PXDG',1,16,0,0)+b''.join(
        struct.pack('<IIQ',len(p),0,index)+p for index,p in enumerate(payloads))


class ProfileTests(unittest.TestCase):
    def test_new_profile_needs_no_cli_or_capture_changes(self):
        schemas=(Schema('example-v3',0xabcd,3,frozenset((1,)),'Example signal',
            decoder=lambda schema,body: ({'value':body[0]},[])),)
        profile=DeviceProfile(profile_id='example-phone',model='Example Phone',codename='example',
            aliases=('example',),chipset='test modem',validated_scope={'firmware':'reference only'},
            capture_formats=('PXDG_V1',),signal_names={0xabcd:'Example signal'},schemas=schemas,
            adapter_factory=RoutedSchemaDispatcher,limitations=())
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture';path.write_bytes(capture(routed(0xabcd,b'\x03')))
            with patch('decoder_profiles.registry.registered_profiles',return_value=(profile,)):
                with patch.object(cli,'PROJECT_ROOT',Path(directory)),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main([str(path),'--device','example']),0)
            result=json.loads(next(Path(directory).glob('*.json')).read_text(encoding='utf-8'))
        self.assertEqual(result['device']['profile_id'],'example-phone')
        self.assertEqual(result['packets'][0]['fields'],{'value':3})

    def test_list_profiles_without_capture_or_dependencies(self):
        stdout=io.StringIO()
        with patch('subprocess.run',side_effect=AssertionError('runtime must not use Java')):
            with redirect_stdout(stdout):self.assertEqual(cli.main(['--list-devices']),0)
        for profile in registered_profiles():
            self.assertIn(profile.profile_id,stdout.getvalue())
            self.assertIn(profile.model,stdout.getvalue())
            self.assertIn(profile.codename,stdout.getvalue())
            for alias in profile.aliases:
                self.assertIs(resolve_profile(alias.upper()),profile)

    def test_device_is_required_and_auto_is_not_a_profile(self):
        for args in ([],['capture.pxdg'],['capture.pxdg','--device','auto'],['--device','lisa']):
            with self.subTest(args=args),redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as error:
                cli.main(args)
            self.assertEqual(error.exception.code,2)

    def test_each_registered_lisa_route_matches_android_golden_fields(self):
        self.assertEqual({int(v['log_id'],16) for v in VECTORS},set(ROUTES))
        for vector in VECTORS:
            with self.subTest(route=vector['name']):
                log_id=int(vector['log_id'],16);body=bytes.fromhex(vector['body_hex'])
                frame,actual_id,valid=next(routed_frames(routed(log_id,body,vector['wrapper'])))
                self.assertTrue(valid);self.assertEqual(actual_id,log_id)
                if vector['expected']['status']=='UNSUPPORTED':
                    with self.assertRaises(UnsupportedPacket):LisaDecoders().decode(frame,log_id)
                else:
                    schema,fields=LisaDecoders().decode(frame,log_id)
                    self.assertEqual(schema,vector['name'])
                    self.assertEqual(fields,vector['expected']['fields'])
                    self.assertEqual(frame.metadata['decode_warnings'],vector['expected']['warnings'])

    def test_signaling_families_match_android_golden_fields(self):
        vectors=json.loads((Path(__file__).parent/'vectors/lisa_signaling_golden.json').read_text(encoding='utf-8'))['vectors']
        for vector in vectors:
            with self.subTest(name=vector['name']):
                log_id=int(vector['log_id'],16)
                record,_,_=next(routed_frames(routed(log_id,bytes.fromhex(vector['body_hex']),vector['wrapper'])))
                self.assertEqual(vector['expected']['status'],'SUCCESS')
                _,fields=LisaDecoders().decode(record,log_id)
                self.assertEqual(fields,vector['expected']['fields'])

    def test_every_route_rejects_neighbor_version_wrong_wrapper_and_radio2(self):
        for vector in VECTORS:
            log_id=int(vector['log_id'],16);body=bytearray.fromhex(vector['body_hex'])
            for version,wrapper,radio in ((body[0]+1,vector['wrapper'],1),
                (body[0],'direct' if vector['wrapper']!='direct' else 'multi-radio-v1',1),
                (body[0],vector['wrapper'],2)):
                if radio==2 and vector['wrapper']=='direct':continue
                with self.subTest(id=vector['log_id'],version=version,wrapper=wrapper,radio=radio):
                    edited=bytes((version%256,))+body[1:]
                    frame,_,_=next(routed_frames(routed(log_id,edited,wrapper,radio)))
                    with self.assertRaises(UnsupportedPacket):LisaDecoders().decode(frame,log_id)

    def test_each_route_rejects_truncated_body(self):
        for vector in VECTORS:
            with self.subTest(id=vector['log_id']):
                log_id=int(vector['log_id'],16)
                frame,_,_=next(routed_frames(routed(log_id,bytes.fromhex(vector['body_hex'])[:1],vector['wrapper'])))
                with self.assertRaises(ValueError) as error:LisaDecoders().decode(frame,log_id)
                self.assertNotIsInstance(error.exception,UnsupportedPacket)

    def test_nested_versions_are_not_guessed(self):
        for log_id,offset in ((0xb061,5),(0xb062,5),(0xb064,5),(0xb092,5),(0xb0b3,5),(0xb193,5)):
            vector=next(v for v in VECTORS if int(v['log_id'],16)==log_id)
            body=bytearray.fromhex(vector['body_hex']);body[offset]+=1
            frame,_,_=next(routed_frames(routed(log_id,body)))
            with self.subTest(id=log_id),self.assertRaises(UnsupportedPacket):LisaDecoders().decode(frame,log_id)

    def test_packet_failures_do_not_stop_later_packets(self):
        good=routed(0x5b2f,bytes.fromhex('01803503063515'))
        bad_crc=bytearray(good);bad_crc[-2]^=1
        bad_reserved=bytearray(good);bad_reserved[14]=1
        # Rebuild CRC-valid malformed nested count separately from framing errors.
        packets=[good,bytes(bad_crc),routed(0xffff,b'\x01'),routed(0x5b2f,b'\x01'),
                 routed(0x5b2f,bytes.fromhex('01803503063515'),radio=2),good]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'arbitrary.extension';path.write_bytes(capture(*packets))
            events=cli.decode_capture(path,profile=resolve_profile('lisa'))
        self.assertEqual([e['status'] for e in events[:-1]],['SUCCESS','MALFORMED','UNSUPPORTED','MALFORMED','UNSUPPORTED','SUCCESS'])
        self.assertEqual(events[-1]['decoded'],2)
        self.assertEqual(events[1]['warnings'][0]['message'],'ValueError: routed-checksum-mismatch')

    def test_strict_routed_structure(self):
        valid=routed(0x5b2f,bytes.fromhex('01803503063515'))
        variants=[valid[:-1],valid+b'\x00',valid[:8]+struct.pack('<I',999)+valid[12:]]
        for packet in variants:
            record,_,_=next(routed_frames(packet))
            self.assertIsNotNone(record.failure)
        record,_,_=next(LisaDecoders().frames(routed(0x5b2f,b'\x01',peripheral=2)))
        self.assertIsInstance(record.failure,UnsupportedPacket)

    def test_explicit_profile_metadata_timestamp_default_root_no_packet_print(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'capture.pxdg'
            path.write_bytes(capture(routed(0x5b2f,bytes.fromhex('01803503063515'))))
            stdout,stderr=io.StringIO(),io.StringIO()
            with patch.object(cli,'PROJECT_ROOT',root/'project'),patch.object(cli,'utc_filename_timestamp',return_value='20261008T120000000000Z'):
                with redirect_stdout(stdout),redirect_stderr(stderr):self.assertEqual(cli.main([str(path),'--device','lisa']),0)
            output=root/'project/capture.pxdg.decoded-20261008T120000000000Z.json'
            document=json.loads(output.read_text(encoding='utf-8'))
        self.assertEqual(document['device']['profile_id'],'mi-11-lite-lisa')
        self.assertEqual(document['device']['selection_mode'],'explicit')
        self.assertEqual(document['device']['codename'],'lisa')
        self.assertNotIn('confidence',json.dumps(document))
        self.assertNotIn('CIPHERING_MODE_COMMAND',stdout.getvalue())
        self.assertIn('found=1 decoded=1',stdout.getvalue())
        self.assertIn('Decoding:',stderr.getvalue())

    def test_absent_metadata_or_signals_do_not_reject_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'empty';path.write_bytes(capture())
            events=cli.decode_capture(path,profile=resolve_profile('lisa'))
        self.assertEqual(events[-1]['decoded'],0)
        self.assertIn('selected profile may not match',events[-1]['warnings'][0])

    def test_raw_routed_input_ignores_filename_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture.txt';path.write_bytes(routed(0x5b2f,bytes.fromhex('01803503063515')))
            events=cli.decode_capture(path,profile=resolve_profile('lisa'))
        self.assertEqual(events[-1]['decoded'],1)

    def test_profile_mismatch_is_not_a_model_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture';path.write_bytes(capture(routed(0x5b2f,bytes.fromhex('01803503063515'))))
            events=cli.decode_capture(path,profile=resolve_profile('surya'))
        self.assertEqual(events[-1]['decoded'],0)
        self.assertIn('selected profile may not match',events[-1]['warnings'][0])

    def test_container_boundaries(self):
        for value in (b'PXDG',capture()[:-1],capture(b'abc')[:-1]):
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'capture';path.write_bytes(value)
                with self.assertRaises(CaptureFormatError):list(iter_pxdg(path))


class SharedProtocolTests(unittest.TestCase):
    def test_nas_supplemental_length_and_direction(self):
        self.assertEqual(eps_nas.decode(bytes.fromhex('0201d011'),'MO')['message'],'PDN_CONNECTIVITY_REQUEST')
        with self.assertRaises(ValueError):eps_nas.decode(bytes.fromhex('0201d011'),'MT')
        with self.assertRaises(ValueError):eps_nas.decode(bytes.fromhex('07430010'),'MO')
        with self.assertRaises(ValueError):eps_nas.decode(bytes.fromhex('0201d091'),'MO')

    def test_nas_security_envelope_remains_opaque_without_keys(self):
        fields=eps_nas.decode(bytes.fromhex('270102030405aabb'),'MT')
        self.assertEqual(fields['decode_scope'],'security envelope only; inner NAS is ciphered')
        self.assertNotIn('inner_nas',fields)
        with self.assertRaises(ValueError):eps_nas.decode(bytes.fromhex('170102030405'),'MT')

    def test_nr_shared_uper_engine_and_unknown_roots(self):
        self.assertEqual(nr_rrc.decode(25,b'\0')['asn1_root'],'RadioBearerConfig')
        with self.assertRaises(UnsupportedPacket):nr_rrc.decode(99,b'\0')
        with self.assertRaises(ValueError):nr_rrc.decode(25,b'')


if __name__=='__main__':unittest.main()
