"""Finite local OCI material profile: exact bytes, no registry or extraction."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'reference/das-v1.5/controller.py'
spec=importlib.util.spec_from_file_location('cadence_image_material',PATH)
controller=importlib.util.module_from_spec(spec);sys.modules[spec.name]=controller;spec.loader.exec_module(controller)
INDEX='application/vnd.oci.image.index.v1+json'
MANIFEST='application/vnd.oci.image.manifest.v1+json'
CONFIG='application/vnd.oci.image.config.v1+json'
LAYER='application/vnd.oci.image.layer.v1.tar+gzip'


def raw_json(value):return json.dumps(value,separators=(',',':')).encode()
def sha(value):return 'sha256:'+hashlib.sha256(value).hexdigest()
def descriptor(raw,kind):return dict(mediaType=kind,digest=sha(raw),size=len(raw))


def layer(files):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:') as archive:
        for name,raw in files.items():
            member=tarfile.TarInfo(name);member.size=len(raw);member.mode=0o644
            archive.addfile(member,io.BytesIO(raw))
    raw=stream.getvalue();return gzip.compress(raw,mtime=0),sha(raw)


def layout(base=None,mutate=None):
    """A two-layer whiteout fixture; optionally extend actual local base layers."""
    first,first_diff=layer({'das-test/keep.txt':b'kept','das-test/delete.txt':b'deleted',
                           'das-test/opaque/old.txt':b'old','candidate/lower.txt':b'hidden'})
    second,second_diff=layer({'das-test/.wh.delete.txt':b'',
                             'das-test/opaque/.wh..wh..opq':b'',
                             'das-test/opaque/new.txt':b'new'})
    if base is None:
        blobs={};config=dict(os='linux',architecture='amd64',config={},rootfs=dict(type='layers',diff_ids=[]));layers=[]
    else:
        blobs,config,layers=copy.deepcopy(base)
    for raw in (first,second):blobs['blobs/sha256/'+sha(raw)[7:]]=raw
    layers+= [descriptor(first,LAYER),descriptor(second,LAYER)]
    config['rootfs']['diff_ids']+=[first_diff,second_diff]
    if 'history' in config:config['history']+=[dict(created_by='TEST retained layer'),dict(created_by='TEST whiteout layer')]
    manifest=dict(schemaVersion=2,mediaType=MANIFEST,config={},layers=layers)
    if mutate:mutate(config,manifest,blobs)
    config_raw=raw_json(config);manifest['config']=descriptor(config_raw,CONFIG)
    manifest_raw=raw_json(manifest);child=descriptor(manifest_raw,MANIFEST)
    child['platform']=dict(os='linux',architecture='amd64')
    # An unavailable optional extension must not force fetching or interpreting it.
    index=dict(schemaVersion=2,mediaType=INDEX,manifests=[child,dict(mediaType='application/x-TEST-unselected',digest='future:unknown',size=0,platform=dict(os='unknown',architecture='unknown'))])
    blobs.update({'blobs/sha256/'+sha(config_raw)[7:]:config_raw,
                  'blobs/sha256/'+sha(manifest_raw)[7:]:manifest_raw,
                  'index.json':raw_json(index),'oci-layout':raw_json(dict(imageLayoutVersion='1.0.0'))})
    return blobs,child['digest']


def write_layout(path,files):
    with tarfile.open(path,'w:') as archive:
        for name,raw in files.items():
            member=tarfile.TarInfo(name);member.size=len(raw);member.mode=0o600
            archive.addfile(member,io.BytesIO(raw))
    path.chmod(0o600)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ImageMaterialInputs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='das-image-input-');self.path=Path(self.temp.name)/'layout.tar'
    def tearDown(self):self.temp.cleanup()
    def bind(self,files,child):
        return controller.image_material_binding(controller.ImageMaterial(str(self.path),write_layout(self.path,files),child))
    def test_native_bytes_and_unselected_extensions_are_preserved(self):
        files,child=layout();bound=self.bind(files,child)
        self.assertEqual(bound['childDigest'],child)
        self.assertEqual(bound['indexDigest'],sha(files['index.json']))
        self.assertEqual([r['diffId'] for r in bound['layers']],json.loads(files['blobs/sha256/'+bound['configDigest'][7:]])['rootfs']['diff_ids'])
        self.assertEqual(len(bound['layers']),2)
        self.assertEqual(set(self.path.parent.iterdir()),{self.path},'parser extracted untrusted layer members')
    def test_other_platform_child_and_ambiguous_selection_refuse(self):
        for variant in ('wrong-child','other-platform','duplicate','selected-unknown','unknown-index','float-version'):
            with self.subTest(variant=variant):
                files,child=layout();index=json.loads(files['index.json'])
                if variant=='wrong-child':child='sha256:'+'0'*64
                elif variant=='other-platform':index['manifests'][0]['platform']['architecture']='arm64'
                elif variant=='duplicate':index['manifests'].append(copy.deepcopy(index['manifests'][0]))
                elif variant=='selected-unknown':index['manifests'][0]['mediaType']='application/x-TEST-unsupported'
                elif variant=='unknown-index':index['mediaType']='application/x-TEST-index'
                else:index['schemaVersion']=2.0
                files['index.json']=raw_json(index)
                with self.assertRaises(controller.ReferenceError):self.bind(files,child)
    def test_layer_order_diff_ids_platform_and_implicit_volumes_refuse(self):
        changes=(lambda c,m,b:m['layers'].reverse(),
                 lambda c,m,b:c['rootfs']['diff_ids'].__setitem__(0,'sha256:'+'0'*64),
                 lambda c,m,b:c.update(architecture='arm64'),
                 lambda c,m,b:c['config'].update(Volumes={'/candidate':{}}),
                 lambda c,m,b:m['layers'][0].update(mediaType='application/x-TEST-layer'),
                 lambda c,m,b:m['layers'][0].update(size=True),
                 lambda c,m,b:c['rootfs']['diff_ids'].pop(),
                 lambda c,m,b:m.update(schemaVersion=2.0))
        for change in changes:
            with self.subTest(change=changes.index(change)):
                files,child=layout(mutate=change)
                with self.assertRaises(controller.ReferenceError):self.bind(files,child)
    def test_blob_substitution_truncation_missing_and_duplicate_json_refuse(self):
        for variant in ('substituted','missing','truncated','json-duplicate'):
            with self.subTest(variant=variant):
                files,child=layout();name='blobs/sha256/'+child[7:]
                if variant=='substituted':files[name]+=b' '
                elif variant=='missing':del files[name]
                elif variant=='truncated':files[name]=files[name][:-1]
                else:files['index.json']=b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}'
                with self.assertRaises(controller.ReferenceError):self.bind(files,child)
    def test_archive_duplicates_links_traversal_and_oversize_refuse(self):
        for name,kind in (('index.json',tarfile.REGTYPE),('alias',tarfile.SYMTYPE),('../escape',tarfile.REGTYPE)):
            with self.subTest(name=name):
                files,child=layout();write_layout(self.path,files)
                with tarfile.open(self.path,'a:') as archive:
                    member=tarfile.TarInfo(name);member.type=kind;member.linkname='/etc/passwd'
                    archive.addfile(member)
                with self.assertRaises(controller.ReferenceError):
                    controller.image_material_binding(controller.ImageMaterial(str(self.path),hashlib.sha256(self.path.read_bytes()).hexdigest(),child))
        with self.path.open('wb') as stream:stream.truncate(192*1024*1024+1)
        with self.assertRaisesRegex(controller.ReferenceError,'custody or archive bound'):
            controller.image_material_binding(controller.ImageMaterial(str(self.path),'0'*64,'sha256:'+'0'*64))
    def test_archive_hash_custody_and_compressed_integrity_refuse(self):
        files,child=layout();approved=write_layout(self.path,files)
        with self.assertRaisesRegex(controller.ReferenceError,'archive digest differs'):
            controller.image_material_binding(controller.ImageMaterial(str(self.path),'0'*64,child))
        self.path.chmod(0o666)
        with self.assertRaisesRegex(controller.ReferenceError,'custody'):
            controller.image_material_binding(controller.ImageMaterial(str(self.path),approved,child))
        files,child=layout(mutate=lambda c,m,b:b.__setitem__('blobs/sha256/'+m['layers'][0]['digest'][7:],b'bad gzip'))
        with self.assertRaises(controller.ReferenceError):self.bind(files,child)
        # Rebind the compressed blob so only the gzip CRC, rather than its native
        # digest, can detect damage to the selected layer's uncompressed bytes.
        def corrupt_crc(config,manifest,blobs):
            original=blobs['blobs/sha256/'+manifest['layers'][0]['digest'][7:]]
            raw=original[:-8]+bytes([original[-8]^1])+original[-7:]
            manifest['layers'][0]=descriptor(raw,LAYER)
            blobs['blobs/sha256/'+sha(raw)[7:]]=raw
        files,child=layout(mutate=corrupt_crc)
        with self.assertRaises(controller.ReferenceError):self.bind(files,child)


@unittest.skipUnless(os.environ.get('CADENCE_DAS_V15_REFERENCE_CONFIG')
    and os.environ.get('DAS_V15_IMAGE_MATERIAL_CONFIG'),
    'actual pinned reference engine and owned OCI material approval required')
class NativeImageMaterial(unittest.TestCase):
    def setUp(self):
        reference=importlib.import_module(
            ('.test_das_v15_reference' if __package__ else 'test_das_v15_reference'),
            package=__package__ or None)
        reference.NativeReference.setUp(self)
        self.keep_driver_evidence=reference.NativeReference.keep_driver_evidence.__get__(self)
        approval_path=Path(os.environ['DAS_V15_IMAGE_MATERIAL_CONFIG'])
        self.assertEqual(approval_path.stat().st_uid,os.getuid())
        self.assertEqual(approval_path.stat().st_mode&0o077,0)
        self.approval=json.loads(approval_path.read_text())
        self.assertEqual(set(self.approval),{'archive_path','archive_sha256','child_digest'})
        # Construct using the controller module actually installed by the fixture.
        self.material=reference.controller.ImageMaterial(**self.approval)
        self.control.image_material=self.material
        self.control_module=reference.controller
    def tearDown(self):
        self.control.close();self.directory.cleanup()
    def test_selected_child_and_layers_match_actual_runtime_and_mount(self):
        self.root.joinpath('run.py').write_text("print('TEST actual selected child')\n")
        self.root.joinpath('run.py').chmod(0o644)
        calls=[];inspections=[];actual_call=self.control._call;actual_inspect=self.control._inspect
        def call(arguments,**options):calls.append(list(arguments));return actual_call(arguments,**options)
        def inspect(identifier):
            value=actual_inspect(identifier);inspections.append(value);return value
        with patch.object(self.control,'_call',side_effect=call),patch.object(self.control,'_inspect',side_effect=inspect):
            observation=self.control.run(self.root,expected_snapshot=self.control_module.snapshot(self.root))
        self.assertIsNone(observation['failureType'],observation)
        self.assertTrue(observation['domainTerminated'])
        self.assertEqual(observation['candidateStdout'],b'TEST actual selected child\n')
        self.assertEqual(observation['selectedImageId'],self.approval['child_digest'])
        self.assertEqual(observation['imageMaterialBinding']['childDigest'],self.approval['child_digest'])
        created=inspections[0];self.assertEqual(created['Image'],self.control.config.image_id)
        self.assertEqual(created['ImageManifestDescriptor']['digest'],self.approval['child_digest'])
        self.assertEqual(created['Mounts'][0]['Source'],str(self.root))
        self.assertFalse(created['Mounts'][0]['RW'])
        create=[a for a in calls if a[:2]==['container','create']];self.assertEqual(len(create),1)
        self.assertEqual(create[0][create[0].index('--platform')+1],'linux/amd64')
        self.keep_driver_evidence('image-child-runtime.json',[(None,observation)],dict(
            approval=self.approval,engineCalls=calls,actualCreateInspection=created))
    def test_mismatched_approval_refuses_before_container_creation(self):
        self.root.joinpath('run.py').write_text("raise RuntimeError('TEST must not run')\n")
        self.root.joinpath('run.py').chmod(0o644)
        before=[];actual_call=self.control._call
        def call(arguments,**options):before.append(list(arguments));return actual_call(arguments,**options)
        with patch.object(self.control,'_call',side_effect=call):
            for values in (dict(self.approval,child_digest='sha256:'+'0'*64),
                           dict(self.approval,archive_sha256='0'*64)):
                with self.subTest(values=values):
                    self.control.image_material=self.control_module.ImageMaterial(**values)
                    with self.assertRaises(self.control_module.ReferenceError):
                        self.control.run(self.root,expected_snapshot=self.control_module.snapshot(self.root))
        self.assertFalse(any(a[:2]==['container','create'] for a in before))
        # No fabricated successful native observation for the refused path.
        destination=os.environ.get('DAS_V15_DRIVER_EVIDENCE_DIR')
        if destination:
            Path(destination,'image-before-create-refusal.json').write_text(json.dumps(dict(
                approval=self.approval,engineCalls=before,containerCreates=0,
                originalCandidatesExecuted=0,productAcceptance='not_run'),indent=2)+'\n')
    def test_actual_whiteout_opaque_directory_and_readonly_mount_overlay(self):
        path=os.environ.get('DAS_V15_IMAGE_WHITEOUT_CONFIG')
        self.assertTrue(path,'owned two-layer native whiteout fixture required')
        owned=json.loads(Path(path).read_text());self.assertEqual(set(owned),set(self.approval))
        material=self.control_module.ImageMaterial(**owned)
        binding=self.control_module.image_material_binding(material)
        # Load only this prebound owned fixture; no tag, registry or shared-image
        # deletion. Native Docker interprets layers/whiteouts, not our parser.
        code,stdout,stderr=self.control._call(['image','load','--input',owned['archive_path']],timeout=20)
        self.assertEqual(code,0,(stdout,stderr))
        old_config=self.control.config
        self.control.config=self.control_module.EngineConfig(old_config.cli,old_config.cli_sha256,
            old_config.socket_path,owned['child_digest'],old_config.daemon_id)
        self.control.image_material=material
        self.root.joinpath('run.py').write_text("""from pathlib import Path
assert Path('/das-test/keep.txt').read_bytes()==b'kept'
assert not Path('/das-test/delete.txt').exists()
assert not Path('/das-test/opaque/old.txt').exists()
assert Path('/das-test/opaque/new.txt').read_bytes()==b'new'
assert not Path('/candidate/lower.txt').exists()
assert Path('/candidate/run.py').is_file()
try:Path('/candidate/forbidden').write_bytes(b'bad')
except PermissionError:pass
except OSError as exc:
 assert exc.errno==30
else:raise RuntimeError('readonly mount was writable')
print('TEST native whiteout and mount overlay passed')
""")
        self.root.joinpath('run.py').chmod(0o644)
        inspections=[];actual=self.control._inspect
        def inspect(identifier):
            value=actual(identifier);inspections.append(value);return value
        with patch.object(self.control,'_inspect',side_effect=inspect):
            observation=self.control.run(self.root,expected_snapshot=self.control_module.snapshot(self.root))
        self.assertIsNone(observation['failureType'],observation)
        self.assertTrue(observation['domainTerminated'])
        self.assertEqual(observation['candidateStdout'],b'TEST native whiteout and mount overlay passed\n')
        self.assertEqual(observation['imageMaterialBinding'],binding)
        self.assertEqual(inspections[0]['Image'],owned['child_digest'])
        self.assertFalse(inspections[0]['Mounts'][0]['RW'])
        self.keep_driver_evidence('image-whiteout-runtime.json',[(None,observation)],dict(
            approval=owned,nativeLoadExit=code,loadStdout=stdout.hex(),loadStderr=stderr.hex(),
            actualCreateInspection=inspections[0],expectedKept=True,expectedDeleted=True,
            expectedOpaqueOldRemoved=True,expectedNewPresent=True,expectedLowerHiddenByMount=True))


if __name__=='__main__':unittest.main()
