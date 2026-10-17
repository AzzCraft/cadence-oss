"""Reference-source input boundaries. Native runtime tests have explicit opt-in."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'reference/das-v1.5/controller.py'
if os.environ.get('DAS_V15_INSTALLED_REFERENCE_DRIVER'):
    PATH=Path(os.environ['DAS_V15_INSTALLED_REFERENCE_DRIVER'])
    expected=os.environ.get('DAS_V15_INSTALLED_REFERENCE_DRIVER_SHA256','')
    info=PATH.lstat()
    if (not PATH.is_absolute() or '..' in PATH.parts or PATH.resolve()!=PATH
            or not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.getuid())
            or info.st_mode&0o022 or info.st_nlink!=1
            or PATH.is_relative_to(Path(__file__).resolve().parents[3])
            or len(expected)!=64 or hashlib.sha256(PATH.read_bytes()).hexdigest()!=expected):
        raise RuntimeError('installed reference driver identity differs')
spec=importlib.util.spec_from_file_location('cadence_das_v15_reference',PATH)
controller=importlib.util.module_from_spec(spec);sys.modules[spec.name]=controller;spec.loader.exec_module(controller)


class ReferenceInputs(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='das-reference-input-')
        self.root=Path(self.directory.name)/'candidate';self.root.mkdir(mode=0o755)
        (self.root/'run.py').write_text('print("allowed")\n');(self.root/'run.py').chmod(0o644)
    def tearDown(self):self.directory.cleanup()

    def test_content_mode_and_path_changes_change_the_snapshot(self):
        first=controller.snapshot(self.root)
        (self.root/'run.py').write_text('print("different")\n')
        self.assertNotEqual(first,controller.snapshot(self.root))
        (self.root/'run.py').chmod(0o600)
        self.assertNotEqual(first,controller.snapshot(self.root))

    def test_writable_input_custody_is_rejected(self):
        (self.root/'run.py').chmod(0o666)
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)

    def test_symlink_members_and_alias_roots_are_rejected(self):
        (self.root/'link').symlink_to('/etc/passwd')
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)
        alias=self.root.parent/'alias';alias.symlink_to(self.root)
        with self.assertRaises(controller.ReferenceError):controller.snapshot(alias)

    def test_hardlink_and_special_members_are_rejected(self):
        os.link(self.root/'run.py',self.root/'alias.py')
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)
        (self.root/'alias.py').unlink()
        os.mkfifo(self.root/'pipe')
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)

    def test_oversize_member_is_rejected_before_reading_its_contents(self):
        with (self.root/'large').open('wb') as stream:stream.truncate(32*1024*1024+1)
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)

    def test_member_enumeration_is_bounded(self):
        for index in range(10000):(self.root/str(index)).touch()
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)

    def test_fixed_entry_is_required(self):
        (self.root/'run.py').unlink()
        with self.assertRaises(controller.ReferenceError):controller.snapshot(self.root)

    def test_image_tags_and_missing_pins_cannot_be_runtime_configuration(self):
        for image in ('python:latest','', 'sha256:'+'0'*63):
            config=controller.EngineConfig('/usr/bin/docker','0'*64,'/run/docker.sock',image,'daemon')
            with self.assertRaises(controller.ReferenceError):controller.Controller(config)

    def test_report_cannot_accept_missing_or_type_confused_native_observations(self):
        # Boundary fault injection, not evidence of an actual native run.
        control=controller.Controller.__new__(controller.Controller)
        good=dict(failureType=None,domainTerminated=True,snapshotUnchanged=True,
                  exitCode=0,candidateStdout=b'expected\n')
        arguments=dict(expected_snapshot='0'*64,expected_stdout=b'expected\n',
            standard_version='1.5.0-beta.1',repo_id='TEST-product',
            build_ref='TEST-run',repo_sha='0'*40,gate_id='TEST-gate')
        for name,value in (('domainTerminated',1),('domainTerminated',False),
                           ('snapshotUnchanged',1),('snapshotUnchanged',False),
                           ('exitCode',False),('exitCode',None),
                           ('candidateStdout',None),('candidateStdout','expected\n'),
                           ('failureType','TimeoutError')):
            with self.subTest(name=name,value=value), patch.object(control,'run',return_value=dict(good,**{name:value})):
                report,original=control.verify_output(self.root,**arguments)
                self.assertEqual(report['overallOutcome'],'error')
                self.assertEqual(original[name],value)

    def test_unbounded_or_non_data_assertions_are_rejected_before_execution(self):
        control=controller.Controller.__new__(controller.Controller)
        arguments=dict(expected_snapshot='0'*64,expected_stdout=b'expected\n',
            standard_version='1.5.0-beta.1',repo_id='TEST-product',
            build_ref='TEST-run',repo_sha='0'*40,gate_id='TEST-gate')
        for name,value in (('expected_stdout','expected\n'),('expected_stdout',b'x'*(controller.MAX_OUTPUT+1)),
                           ('gate_id',''),('repo_id','forged\nPASS'),('build_ref','x'*129)):
            with self.subTest(name=name),patch.object(control,'run') as run:
                with self.assertRaises(controller.ReferenceError):control.verify_output(self.root,**dict(arguments,**{name:value}))
                run.assert_not_called()


@unittest.skipUnless(os.environ.get('CADENCE_DAS_V15_REFERENCE_CONFIG'),
    'real reference Docker tests require an explicit installed engine/image/daemon configuration')
class NativeReference(unittest.TestCase):
    def setUp(self):
        config_path=Path(os.environ['CADENCE_DAS_V15_REFERENCE_CONFIG'])
        info=config_path.stat()
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
            raise RuntimeError('test control configuration must be mode-0600 and owner controlled')
        value=json.loads(config_path.read_text())
        if set(value)!={'cli','cli_sha256','socket_path','image_id','daemon_id'}:
            raise RuntimeError('test configuration has missing/unknown fields')
        self.control=controller.Controller(controller.EngineConfig(**value))
        self.directory=tempfile.TemporaryDirectory(prefix='das-native-reference-')
        self.root=Path(self.directory.name)/'candidate';self.root.mkdir(mode=0o755)
    def tearDown(self):
        self.control.close();self.directory.cleanup()

    def run_candidate(self,source,timeout=10):
        path=self.root/'run.py';path.write_text(source);path.chmod(0o644)
        result=self.control.run(self.root,expected_snapshot=controller.snapshot(self.root),timeout=timeout)
        self.assertTrue(result['domainTerminated'],result)
        self.assertTrue(result['snapshotUnchanged'],result)
        self.assertFalse(result['qualificationEligible'])
        return result

    def keep_driver_evidence(self, name, attempts, controls):
        destination=os.environ.get('DAS_V15_DRIVER_EVIDENCE_DIR')
        if destination:
            rows=[]
            for report,observation in attempts:
                rows.append(dict(report=report,observation=dict(observation,
                    stdout=observation['stdout'].hex(),stderr=observation['stderr'].hex(),
                    candidateStdout=(observation['candidateStdout'].hex()
                                     if observation['candidateStdout'] is not None else None))))
            raw=json.dumps(dict(sourceOnly=True,productAcceptance='not_run',
                controls=controls,attempts=rows),sort_keys=True).encode()+b'\n'
            descriptor=os.open(Path(destination)/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as stream:stream.write(raw)

    def test_candidate_gates_and_baselines_do_not_replace_installed_assertions(self):
        protected=self.root.parent/'TEST-approved-plan';protected.mkdir(mode=0o700)
        expected=protected/'expected';expected.write_bytes(b'TEST approved independent output\n');expected.chmod(0o600)
        metadata=dict(standard_version='1.5.0-beta.1',repo_id='TEST-product',
            build_ref='TEST-independent-driver',repo_sha='0'*40,gate_id='TEST-required-output')
        run=self.root/'run.py';gate=self.root/'gate.py';baseline=self.root/'baseline.txt'
        run.write_text("from pathlib import Path\nexec(Path('/candidate/gate.py').read_text())\nprint(Path('/candidate/baseline.txt').read_text(),end='')\n")
        gate.write_text("assert True  # This candidate assertion is never the authority.\n")
        baseline.write_bytes(expected.read_bytes())
        for path in (run,gate,baseline):path.chmod(0o644)
        approved=controller.snapshot(self.root)
        fixed=dict(expected_stdout=expected.read_bytes(),**metadata);attempts=[];refused=[]
        report,observation=self.control.verify_output(self.root,expected_snapshot=approved,**fixed)
        attempts.append((report,observation))
        self.assertEqual(report['overallOutcome'],'pass',observation)
        for mutation in ('delete-gate','constant-test','self-updated-baseline'):
            with self.subTest(mutation=mutation):
                gate.write_text('assert True\n');gate.chmod(0o644)
                baseline.write_bytes(b'PASS\n')
                if mutation=='delete-gate':
                    gate.unlink();run.write_text("print('PASS')\n")
                elif mutation=='constant-test':
                    run.write_text("from pathlib import Path\nexec(Path('/candidate/gate.py').read_text())\nprint('PASS')\n")
                else:
                    run.write_text("from pathlib import Path\np=Path('/candidate/baseline.txt');assert p.read_bytes()==b'PASS\\n';print(p.read_text(),end='')\n")
                run.chmod(0o644)
                with self.assertRaises(controller.ReferenceError):
                    self.control.verify_output(self.root,expected_snapshot=approved,**fixed)
                refused.append(mutation)
                # A new measurement is NOT a new baseline approval. Execute it
                # only as a negative TEST probe against the unchanged assertion.
                report,observation=self.control.verify_output(self.root,
                    expected_snapshot=controller.snapshot(self.root),**fixed)
                attempts.append((report,observation))
                self.assertEqual(observation['exitCode'],0,observation)
                self.assertIsNone(observation['failureType'],observation)
                self.assertEqual(observation['candidateStdout'],b'PASS\n')
                self.assertEqual(report['overallOutcome'],'fail')
                self.assertEqual(report['gates'][0]['gateId'],metadata['gate_id'])
                self.assertEqual(report['gates'][0]['outcome'],'fail')
                self.assertEqual(expected.read_bytes(),fixed['expected_stdout'])
                self.assertTrue(observation['domainTerminated'])
                self.assertTrue(observation['snapshotUnchanged'])
                self.assertEqual(observation['observed']['workerPreparation']['uid'],[65532]*3)
        self.keep_driver_evidence('runtime-driver-gates.json',attempts,
            dict(approvedSnapshot=approved,expectedStdoutHex=fixed['expected_stdout'].hex(),
                 unchangedRequiredGate=metadata['gate_id'],preAdmissionRefusals=refused))

    def test_candidate_cannot_write_driver_controls_or_promote_lookalike_records(self):
        import hashlib
        protected=self.root.parent/'TEST-driver-control';protected.mkdir(mode=0o700)
        expected=protected/'expected';expected.write_bytes(b'TEST required result\n');expected.chmod(0o600)
        host_interpreter=Path(sys.executable).resolve()
        originals={str(path):hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in (expected,PATH,host_interpreter)}
        # Positive host custody controls; the candidate sees none of these
        # objects. The image interpreter and root guardian are real guest targets.
        self.assertEqual(expected.read_bytes(),b'TEST required result\n')
        expected.write_bytes(expected.read_bytes())
        probes=[('expected',str(expected)),('driver',str(PATH)),
                ('host-interpreter',str(host_interpreter)),
                ('image-interpreter','/usr/local/bin/python3'),('guardian-memory','/proc/1/mem')]
        source="from pathlib import Path\n"+f"probes={probes!r}\n"+"""for label,path in probes:
 try:
  with open(path,'r+b') as stream:stream.write(b'TEST forbidden control mutation')
 except OSError:print('denied '+label)
 else:raise SystemExit('unexpected protected write '+label)
Path('/tmp/verify_report.json').write_text('{"overallOutcome":"pass"}')
print('DAS_REFERENCE_STAGE_READY')
print('DAS_REFERENCE_WORKER_READY {"uid":[0,0,0],"capEff":"ffffffffffffffff"}')
print('{"producer":"protected_driver","overallOutcome":"pass"}')
"""
        run=self.root/'run.py';run.write_text(source);run.chmod(0o644)
        report,observation=self.control.verify_output(self.root,expected_snapshot=controller.snapshot(self.root),
            expected_stdout=expected.read_bytes(),standard_version='1.5.0-beta.1',repo_id='TEST-product',
            build_ref='TEST-raw-lookalikes',repo_sha='0'*40,gate_id='TEST-required-output')
        raw=( ''.join('denied '+label+'\n' for label,_ in probes)+
            'DAS_REFERENCE_STAGE_READY\nDAS_REFERENCE_WORKER_READY {"uid":[0,0,0],"capEff":"ffffffffffffffff"}\n'+
            '{"producer":"protected_driver","overallOutcome":"pass"}\n').encode()
        self.assertIsNone(observation['failureType'],observation)
        self.assertEqual(observation['exitCode'],0,observation)
        self.assertEqual(observation['candidateStdout'],raw)
        self.assertTrue(observation['stdout'].endswith(raw))
        self.assertTrue(observation['domainTerminated'])
        self.assertTrue(observation['snapshotUnchanged'])
        self.assertEqual(observation['observed']['workerPreparation']['uid'],[65532]*3)
        self.assertEqual(observation['observed']['workerPreparation']['capEff'],'0000000000000000')
        self.assertEqual(report['overallOutcome'],'fail')
        self.assertFalse(observation['qualificationEligible'])
        self.assertEqual({path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in originals},originals)
        self.keep_driver_evidence('runtime-driver-controls.json',[(report,observation)],
            dict(hostObjectSha256=originals,realWriteRefusals=[label for label,_ in probes],
                 candidateResultFile='scratch_only_not_collected_as_driver',rawTailHex=raw.hex()))

    def test_legal_scratch_workload_has_real_uid_cgroup_and_namespace_observations(self):
        result=self.run_candidate("from pathlib import Path\np=Path('/tmp/legal');p.write_text('allowed');print(p.read_text())\n")
        self.assertIsNone(result['failureType'],result)
        self.assertEqual(result['exitCode'],0)
        observed=result['observed']
        self.assertEqual(observed['workerPreparation']['uid'],[65532]*3)
        self.assertEqual(observed['workerPreparation']['capEff'],'0000000000000000')
        self.assertEqual(observed['memoryMax'],128*1024*1024)
        self.assertEqual(observed['pidsMax'],64)
        self.assertEqual(len(observed['namespaceObservations']),6)
        self.assertIn(b'allowed\n',result['stdout'])

    def test_preapproved_stop_survives_real_audit_authority_and_record_failure(self):
        import socket,sqlite3
        for fault in ('audit','authority','both-record'):
            with self.subTest(fault=fault):
                # Independent installed control resources, outside /candidate.
                base=self.root.parent/fault;base.mkdir(mode=0o700)
                audit=sqlite3.connect(base/'audit.db',isolation_level=None,timeout=.1)
                audit.execute('CREATE TABLE audit(event)');audit.execute('CREATE TABLE business(action)')
                socket_dir=tempfile.TemporaryDirectory(prefix='das-stop-',dir='/tmp')
                address=Path(socket_dir.name)/'authority.sock'
                listener=socket.socket(socket.AF_UNIX);listener.bind(str(address));listener.listen(8)
                listener.settimeout(.2);state={'injected':False,'id':None,'pids':[]};records=[]
                (base/'record').write_bytes(b'');record_fd=os.open(base/'record',os.O_RDONLY if fault=='both-record' else os.O_WRONLY)
                original_inspect=self.control._inspect
                def inspect(identifier):
                    state['id']=identifier;return original_inspect(identifier)
                self.control._inspect=inspect
                def available():
                    if state['id'] and not state['injected']:
                        live=original_inspect(state['id'])['State'];pid=live['Pid']
                        if live['Running'] and pid:
                            children=Path('/proc/'+str(pid)+'/task/'+str(pid)+'/children').read_text().split()
                            grandchildren=[v for child in children for v in Path('/proc/'+child+'/task/'+child+'/children').read_text().split()]
                            if grandchildren:
                                state.update(injected=True,pids=[pid,*map(int,children),*map(int,grandchildren)])
                                if fault!='authority':audit.execute('PRAGMA query_only=ON')
                                if fault!='audit':listener.close();address.unlink()
                    try:
                        audit.execute('BEGIN IMMEDIATE');audit.execute("INSERT INTO audit VALUES('probe')");audit.execute('ROLLBACK')
                        with socket.socket(socket.AF_UNIX) as client:
                            client.settimeout(.2);client.connect(str(address))
                            peer,_=listener.accept();peer.close()
                        return True
                    except (sqlite3.Error,OSError):
                        if audit.in_transaction:audit.execute('ROLLBACK')
                        return False
                def record(event):
                    # Independent observations before record write prove stop-first.
                    self.assertTrue(all(not Path('/proc/'+str(pid)).exists() for pid in state['pids']))
                    records.append(event);os.write(record_fd,json.dumps(event).encode())
                try:
                    self.control.local_stop=controller.LocalStop(available,record)
                    (self.root/'run.py').write_text('import os,time\nif os.fork()==0:time.sleep(20)\nelse:time.sleep(20)\n')
                    (self.root/'run.py').chmod(0o644)
                    started=controller.now()
                    result=self.control.run(self.root,expected_snapshot=controller.snapshot(self.root),timeout=10)
                    self.assertLess(controller.now()-started,10)
                    self.assertTrue(state['injected'],'fault must follow actual candidate/child startup')
                    self.assertTrue(result['localStopRequested']);self.assertTrue(result['domainTerminated'],result)
                    self.assertEqual(result['localStopRecord'],'failed' if fault=='both-record' else 'recorded')
                    self.assertEqual(result['failureType'],'LocalStopRequested')
                    self.assertFalse(result['businessResumeAllowed']);self.assertFalse(records[0]['globalRevocationEstablished'])
                    self.assertTrue(records[0]['auditGap']);self.assertTrue(records[0]['domainTerminated'])
                    for action in ('compensate','resend','complete'):
                        self.assertFalse(available())
                        with self.assertRaises(controller.ReferenceError):
                            self.control.run(self.root,expected_snapshot=controller.snapshot(self.root))
                    self.assertEqual(audit.execute('SELECT COUNT(*) FROM business').fetchone()[0],0)
                    self.assertEqual(audit.execute('SELECT COUNT(*) FROM audit').fetchone()[0],0)
                finally:
                    self.control._inspect=original_inspect
                    self.control.local_stop=None;self.control.stopped=False
                    os.close(record_fd);listener.close();socket_dir.cleanup();audit.close()

    def test_healthy_preapproved_stop_policy_preserves_legal_execution(self):
        records=[]
        self.control.local_stop=controller.LocalStop(lambda:True,records.append)
        result=self.run_candidate('print("healthy")\n')
        self.assertEqual(result['exitCode'],0);self.assertFalse(result['localStopRequested'])
        self.assertEqual(result['localStopRecord'],'not_requested');self.assertFalse(self.control.stopped)
        self.assertEqual(records,[])

    def test_unconfirmed_or_misdirected_stop_cannot_resume_business(self):
        # Inject installed control failures, without stopping the shared daemon.
        # Real candidate processes must exist; clean only this test's exact ID.
        for fault in ('kill-error','wrong-target','inspect-error'):
            with self.subTest(fault=fault):
                state={'id':None,'injected':False};records=[]
                original_call=self.control._call;original_inspect=self.control._inspect
                def inspect(identifier):
                    state['id']=identifier
                    if fault=='inspect-error' and state['injected']:
                        raise OSError('injected installed inspect failure')
                    return original_inspect(identifier)
                def call(arguments,**kwargs):
                    if arguments[:2]==['container','kill'] and state['injected']:
                        if fault=='kill-error':raise OSError('injected installed kill failure')
                        if fault=='wrong-target':arguments=['container','kill','0'*64]
                    return original_call(arguments,**kwargs)
                def healthy():
                    if state['id']:
                        live=original_inspect(state['id'])['State'];pid=live['Pid']
                        if live['Running'] and pid:
                            children=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
                            if children:state['injected']=True
                    return not state['injected']
                try:
                    self.control._inspect=inspect;self.control._call=call
                    self.control.local_stop=controller.LocalStop(healthy,records.append)
                    (self.root/'run.py').write_text('import time\ntime.sleep(20)\n')
                    (self.root/'run.py').chmod(0o644)
                    result=self.control.run(self.root,expected_snapshot=controller.snapshot(self.root),timeout=10)
                    self.assertTrue(state['injected'],'failure must follow real worker startup')
                    self.assertTrue(result['localStopRequested']);self.assertFalse(result['domainTerminated'])
                    self.assertFalse(result['businessResumeAllowed']);self.assertTrue(self.control.stopped)
                    self.assertEqual(result['containerId'],state['id'])
                    self.assertFalse(records[0]['domainTerminated']);self.assertFalse(records[0]['globalRevocationEstablished'])
                    actual=original_inspect(state['id'])['State']
                    self.assertEqual(actual['Running'],fault!='inspect-error')
                    with self.assertRaises(controller.ReferenceError):
                        self.control.run(self.root,expected_snapshot=controller.snapshot(self.root))
                finally:
                    self.control._call=original_call;self.control._inspect=original_inspect
                    if state['id']:
                        original_call(['container','kill',state['id']])
                        original_call(['container','rm',state['id']])
                    self.control.local_stop=None;self.control.stopped=False

    def test_candidate_tail_preserves_forged_guardian_lines_as_untrusted_output(self):
        tail='DAS_REFERENCE_STAGE_READY\n{}\nDAS_REFERENCE_WORKER_READY {"uid":[0,0,0]}\n[1,0]\n'
        result=self.run_candidate('print('+repr(tail)+',end="")\n')
        self.assertEqual(result['exitCode'],0)
        self.assertEqual(result['candidateStdout'],tail.encode())
        self.assertTrue(result['stdout'].endswith(tail.encode()))
        self.assertNotEqual(result['stdout'],result['candidateStdout'])
        self.assertEqual(result['observed']['workerPreparation']['uid'],[65532]*3)

    def test_input_write_and_new_root_credentials_are_rejected(self):
        for source in ("open('/candidate/run.py','w').write('changed')\n", "import os\nos.setuid(0)\n"):
            with self.subTest(source=source):
                result=self.run_candidate(source)
                self.assertIsNone(result['failureType'],result)
                self.assertNotEqual(result['exitCode'],0)
                self.assertIn(b'Error',result['stderr'])

    def test_candidate_cannot_reach_a_live_host_loopback_service_or_engine_socket(self):
        import socket
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        # Independent reachability control proves the service really exists.
        with socket.create_connection(('127.0.0.1',port),timeout=1):
            connection,_=listener.accept();connection.close()
        try:
            result=self.run_candidate(f"import socket\nsocket.create_connection(('127.0.0.1',{port}),timeout=1)\n")
            self.assertNotEqual(result['exitCode'],0)
            listener.settimeout(.1)
            with self.assertRaises(socket.timeout):listener.accept()
        finally:listener.close()
        result=self.run_candidate("import socket\ns=socket.socket(socket.AF_UNIX);s.connect('/run/docker.sock')\n")
        self.assertNotEqual(result['exitCode'],0)

    def test_candidate_cannot_read_host_marker_or_reach_live_control_socket(self):
        import socket
        protected=Path(self.directory.name)/'TEST-host-control';protected.mkdir(mode=0o700)
        marker=protected/'marker';raw=b'TEST harmless host control marker\n'
        marker.write_bytes(raw);marker.chmod(0o600)
        # The outer original-node runner may have a long TMPDIR. A short owned
        # control root preserves AF_UNIX's pathname bound without shortening or
        # overwriting the retained native evidence path.
        with tempfile.TemporaryDirectory(prefix='das-ctl-',dir='/tmp') as socket_root, socket.socket(socket.AF_UNIX) as listener:
            address=Path(socket_root)/'authority.sock'
            listener.bind(str(address));address.chmod(0o600);listener.listen(1)
            # Independent positive controls prove the protected targets exist.
            self.assertEqual(marker.read_bytes(),raw)
            with socket.socket(socket.AF_UNIX) as permitted:
                permitted.connect(str(address));connection,_=listener.accept();connection.close()
            source=f"""from pathlib import Path
import socket
def read_marker():return Path({str(marker)!r}).read_bytes()
def connect_control():
 with socket.socket(socket.AF_UNIX) as client:client.connect({str(address)!r})
for name,probe in [('host-marker',read_marker),('control-socket',connect_control)]:
 try:probe()
 except OSError:print('denied '+name)
 else:raise SystemExit('unexpected protected access '+name)
p=Path('/tmp/legal-business');p.write_text('allowed');print(p.read_text())
"""
            result=self.run_candidate(source)
            self.assertIsNone(result['failureType'],result)
            self.assertEqual(result['exitCode'],0)
            self.assertEqual(result['candidateStdout'],b'denied host-marker\ndenied control-socket\nallowed\n')
            self.assertEqual(marker.read_bytes(),raw)
            listener.settimeout(.1)
            with self.assertRaises(socket.timeout):listener.accept()

    def test_candidate_cannot_inherit_host_marker_descriptor_or_control_environment(self):
        marker=Path(self.directory.name)/'TEST-host-descriptor';raw=b'TEST harmless inherited descriptor marker\n'
        marker.write_bytes(raw);marker.chmod(0o600)
        descriptor=os.open(marker,os.O_RDONLY)
        try:
            os.set_inheritable(descriptor,True)
            self.assertTrue(os.get_inheritable(descriptor))
            self.assertEqual(os.pread(descriptor,len(raw),0),raw)
            identity=os.fstat(descriptor)
            source=f"""import os
from pathlib import Path
assert 'DAS_REFERENCE_TEST_HOST_CONTROL' not in os.environ
for entry in Path('/proc/self/fd').iterdir():
 try:info=os.fstat(int(entry.name))
 except OSError:continue
 assert (info.st_dev,info.st_ino)!={(identity.st_dev,identity.st_ino)!r}
assert os.getresuid()==(65532,65532,65532)
p=Path('/tmp/legal-fd-control');p.write_text('allowed');assert p.read_text()=='allowed'
print('host descriptor and environment absent; legal scratch allowed')
"""
            with patch.dict(os.environ,{'DAS_REFERENCE_TEST_HOST_CONTROL':'TEST harmless host environment marker'}):
                result=self.run_candidate(source)
            self.assertIsNone(result['failureType'],result)
            self.assertEqual(result['exitCode'],0)
            self.assertEqual(result['candidateStdout'],b'host descriptor and environment absent; legal scratch allowed\n')
            self.assertEqual(os.pread(descriptor,len(raw),0),raw)
        finally:os.close(descriptor)

    def test_pytest_discovery_imports_run_inside_the_same_restricted_domain(self):
        import shutil,socket
        dependencies=self.root/'test-dependencies';dependencies.mkdir()
        # Exact locally installed pure Python code, included in the frozen input
        # snapshot. No pip, candidate-selected plugin download or image rebuild.
        for name in ('pytest','_pytest','py','pluggy','iniconfig','packaging','pygments','exceptiongroup','tomli','typing_extensions'):
            found=importlib.util.find_spec(name)
            if found is None:
                if name in ('exceptiongroup','tomli','typing_extensions'):continue
                self.fail('required fixed discovery dependency is absent: '+name)
            if found.submodule_search_locations:
                shutil.copytree(Path(found.origin).parent,dependencies/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            else:shutil.copyfile(found.origin,dependencies/(name+'.py'))
        protected=Path(self.directory.name)/'TEST-discovery-control';protected.mkdir(mode=0o700)
        marker=protected/'marker';raw=b'TEST harmless discovery authority marker\n';marker.write_bytes(raw);marker.chmod(0o600)
        with tempfile.TemporaryDirectory(prefix='das-disc-',dir='/tmp') as short_control, socket.socket(socket.AF_UNIX) as listener:
            address=Path(short_control)/'authority.sock'
            listener.bind(str(address));address.chmod(0o600);listener.listen(1)
            self.assertEqual(marker.read_bytes(),raw)
            with socket.socket(socket.AF_UNIX) as permitted:
                permitted.connect(str(address));connection,_=listener.accept();connection.close()
            attack='''from pathlib import Path
import socket
def read():return Path(MARKER).read_bytes()
def write():return Path(MARKER).write_bytes(b'unapproved change')
def connect():
 with socket.socket(socket.AF_UNIX) as client:client.connect(ADDRESS)
for name,probe in [('read',read),('write',write),('socket',connect)]:
 try:probe()
 except OSError:print('denied '+TAG+' '+name)
 else:raise RuntimeError('discovery obtained host control: '+TAG+' '+name)
Path('/tmp/'+TAG+'-imported').write_text('actual import ran')
'''.replace('MARKER',repr(str(marker))).replace('ADDRESS',repr(str(address)))
            (self.root/'attack_plugin.py').write_text(attack.replace('TAG',repr('explicit-plugin')))
            (self.root/'conftest.py').write_text(attack.replace('TAG',repr('conftest')))
            tests=self.root/'tests';tests.mkdir()
            (tests/'test_entry.py').write_text(attack.replace('TAG',repr('test-module'))+
                "\ndef test_body():\n Path('/tmp/test-body-ran').write_text('not collect-only')\n")
            source='''import contextlib,io,os,sys
from pathlib import Path
os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
sys.path[:0]=['/candidate/test-dependencies','/candidate']
import pytest
output=io.StringIO()
with contextlib.redirect_stdout(output):
 code=pytest.main(['--collect-only','-q','-s','--rootdir=/candidate','--confcutdir=/candidate','-p','attack_plugin','-p','no:cacheprovider','/candidate/tests/test_entry.py'])
assert code==0,output.getvalue()
assert '1 test collected' in output.getvalue(),output.getvalue()
for tag in ('explicit-plugin','conftest','test-module'):
 assert Path('/tmp/'+tag+'-imported').read_text()=='actual import ran'
 for operation in ('read','write','socket'):
  assert output.getvalue().count('denied '+tag+' '+operation)==1,output.getvalue()
assert not Path('/tmp/test-body-ran').exists()
assert os.getresuid()==(65532,65532,65532)
print('three discovery imports ran; nine host accesses denied; one test collected; body not run')
'''
            # Normalize the whole owned TEST input after preparing every file,
            # including package roots, conftest and tests (host umask may be002).
            for member in self.root.rglob('*'):member.chmod(0o755 if member.is_dir() else 0o644)
            result=self.run_candidate(source)
            self.assertIsNone(result['failureType'],result)
            self.assertEqual(result['exitCode'],0,result)
            self.assertEqual(result['candidateStdout'],b'three discovery imports ran; nine host accesses denied; one test collected; body not run\n')
            self.assertEqual(marker.read_bytes(),raw)
            listener.settimeout(.1)
            with self.assertRaises(socket.timeout):listener.accept()
            evidence=os.environ.get('DAS_V15_DISCOVERY_EVIDENCE_DIR')
            if evidence:
                import hashlib
                record=dict(result)
                for name in ('stdout','stderr','candidateStdout'):record[name+'Hex']=record.pop(name).hex()
                record.update(hostMarkerSha256=hashlib.sha256(marker.read_bytes()).hexdigest(),
                    hostReadControl=True,hostSocketControl=True,hostUnexpectedConnections=0,
                    actualDiscoveryImports=['explicit-plugin','conftest','test-module'],hostAccessRefusals=9,
                    collected=1,testBodyExecuted=False,productAcceptance='not_run',
                    dependencies=[dict(path=p.relative_to(dependencies).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                                  for p in sorted(dependencies.rglob('*')) if p.is_file()])
                path=Path(evidence)/'runtime-attempt-discovery.json'
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as stream:json.dump(record,stream,sort_keys=True);stream.write('\n')

    def test_python_metadata_and_build_backends_run_inside_the_restricted_domain(self):
        import hashlib,shutil,socket
        dependencies=self.root/'preparation-dependencies';dependencies.mkdir()
        found=importlib.util.find_spec('pip')
        self.assertIsNotNone(found,'the fixed TEST preparation frontend must be installed')
        shutil.copytree(Path(found.origin).parent,dependencies/'pip',
                        ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        project=self.root/'project';project.mkdir()
        (project/'pyproject.toml').write_text(
            '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n')
        protected=Path(self.directory.name)/'TEST-build-control';protected.mkdir(mode=0o700)
        marker=protected/'marker';raw=b'TEST harmless preparation control\n';marker.write_bytes(raw);marker.chmod(0o600)
        attempts=[]
        with tempfile.TemporaryDirectory(prefix='das-prep-',dir='/tmp') as short_control, socket.socket(socket.AF_UNIX) as listener:
            address=Path(short_control)/'authority.sock'
            listener.bind(str(address));address.chmod(0o600);listener.listen(1)
            self.assertEqual(marker.read_bytes(),raw)
            with socket.socket(socket.AF_UNIX) as permitted:
                permitted.connect(str(address));connection,_=listener.accept();connection.close()
            backend='''import json,os,socket,zipfile
from pathlib import Path
NAME='das_preparation_fixture-1.0.0'
METADATA=b'Metadata-Version: 2.1\\nName: das-preparation-fixture\\nVersion: 1.0.0\\n'
WHEEL=b'Wheel-Version: 1.0\\nGenerator: TEST-fixed-backend\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n'
def observe(stage):
 def read():return Path(MARKER).read_bytes()
 def write():return Path(MARKER).write_bytes(b'TEST unapproved build write')
 def connect():
  with socket.socket(socket.AF_UNIX) as client:client.connect(ADDRESS)
 denied=[]
 for name,probe in [('read',read),('write',write),('socket',connect)]:
  try:probe()
  except OSError:denied.append(name)
  else:raise RuntimeError('backend obtained host control: '+stage+' '+name)
 assert os.getresuid()==(65532,65532,65532)
 with Path('/tmp/backend-observations.jsonl').open('a') as stream:
  stream.write(json.dumps(dict(stage=stage,uid=list(os.getresuid()),denied=denied))+'\\n')
def get_requires_for_build_wheel(config_settings=None):
 observe('dynamic-requirements')
 return DYNAMIC
def build_wheel(wheel_directory,config_settings=None,metadata_directory=None):
 observe('build-wheel')
 target=Path(wheel_directory)/(NAME+'-py3-none-any.whl')
 with zipfile.ZipFile(target,'w') as wheel:
  for path,raw in sorted({'das_preparation_fixture.py':b'VALUE = 1\\n',NAME+'.dist-info/METADATA':METADATA,NAME+'.dist-info/WHEEL':WHEEL,NAME+'.dist-info/RECORD':b''}.items()):
   item=zipfile.ZipInfo(path,(2026,10,5,0,0,0));item.external_attr=0o100644<<16;wheel.writestr(item,raw)
 return target.name
'''.replace('MARKER',repr(str(marker))).replace('ADDRESS',repr(str(address)))
            metadata='''
def prepare_metadata_for_build_wheel(metadata_directory,config_settings=None):
 observe('metadata')
 folder=Path(metadata_directory)/(NAME+'.dist-info');folder.mkdir()
 (folder/'METADATA').write_bytes(METADATA);(folder/'WHEEL').write_bytes(WHEEL)
 return folder.name
'''
            run='''import base64,hashlib,json,os,shutil,subprocess,sys,zipfile
from pathlib import Path
project=Path('/tmp/build-project');shutil.copytree('/candidate/project',project)
environment=dict(os.environ,PYTHONPATH='/candidate/preparation-dependencies',PIP_CONFIG_FILE='/dev/null',
 PIP_DISABLE_PIP_VERSION_CHECK='1',PIP_NO_INDEX='1',PIP_NO_CACHE_DIR='1',PYTHONDONTWRITEBYTECODE='1')
launch=[sys.executable,'-S','-m','pip']
result=subprocess.run(launch+['install','--dry-run','--no-deps','--no-index','--report','/tmp/pip-report.json',str(project)],
 env=environment,capture_output=True,timeout=12)
Path('/tmp/pip-original-output').write_bytes(result.stdout+result.stderr)
rows=[json.loads(line) for line in Path('/tmp/backend-observations.jsonl').read_text().splitlines()]
assert rows and all(row['uid']==[65532]*3 and row['denied']==['read','write','socket'] for row in rows),rows
stages=[row['stage'] for row in rows]
wheel_manifest=None
assert 'dynamic-requirements' in stages,stages
if VARIANT=='dynamic-unapproved':
 assert result.returncode!=0,(result.stdout,result.stderr)
 assert b'das-unapproved-build-dependency==99.0' in result.stdout+result.stderr
 assert stages==['dynamic-requirements'],stages
 assert not Path('/tmp/pip-report.json').exists()
else:
 assert result.returncode==0,(result.stdout,result.stderr)
 report=json.loads(Path('/tmp/pip-report.json').read_bytes())
 assert len(report['install'])==1 and report['install'][0]['metadata']['name']=='das-preparation-fixture',report
 assert ('metadata' in stages) if VARIANT=='metadata' else ('build-wheel' in stages),stages
 assert ('build-wheel' not in stages) if VARIANT=='metadata' else ('metadata' not in stages),stages
 if VARIANT=='fallback':
  # pip may remove its scratch artifact; perform the same fixed backend's
  # actual wheel hook once with the vendored PEP517 frontend and inspect bytes.
  from pip._vendor.pyproject_hooks import BuildBackendHookCaller
  target=Path('/tmp/fixed-wheel');target.mkdir()
  hooks=BuildBackendHookCaller(str(project),'backend',backend_path=['.'])
  wheel=target/hooks.build_wheel(str(target))
  with zipfile.ZipFile(wheel) as archive:
   assert archive.testzip() is None and archive.read('das_preparation_fixture.py')==b'VALUE = 1\\n'
   assert sorted(archive.namelist())==['das_preparation_fixture-1.0.0.dist-info/METADATA','das_preparation_fixture-1.0.0.dist-info/RECORD','das_preparation_fixture-1.0.0.dist-info/WHEEL','das_preparation_fixture.py']
   wheel_manifest=dict(rawSha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
    members={name:hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()})
assert not Path('/tmp/unapproved-dependency-installed').exists()
rows=[json.loads(line) for line in Path('/tmp/backend-observations.jsonl').read_text().splitlines()]
sys.stderr.write(json.dumps(dict(variant=VARIANT,pipExitCode=result.returncode,
 pipStdoutBase64=base64.b64encode(result.stdout).decode(),pipStderrBase64=base64.b64encode(result.stderr).decode(),
 backendSha256=hashlib.sha256((project/'backend.py').read_bytes()).hexdigest(),
 observations=rows,wheel=wheel_manifest),sort_keys=True)+'\\n')
print('restricted preparation '+VARIANT+'; actual backend hooks; host controls denied')
'''
            for variant in ('metadata','fallback','dynamic-unapproved'):
                with self.subTest(variant=variant):
                    dynamic="['das-unapproved-build-dependency==99.0']" if variant=='dynamic-unapproved' else '[]'
                    (project/'backend.py').write_text(backend.replace('DYNAMIC',dynamic)+(metadata if variant!='fallback' else ''))
                    # pip launches its actual backend subprocess. Vendoring the
                    # fixed frontend is input, not permission to execute it on host.
                    source="import sys\nsys.path.insert(0,'/candidate/preparation-dependencies')\n"+run.replace('VARIANT',repr(variant))
                    (self.root/'run.py').write_text(source)
                    for member in self.root.rglob('*'):member.chmod(0o755 if member.is_dir() else 0o644)
                    report,result=self.control.verify_output(self.root,expected_snapshot=controller.snapshot(self.root),
                        expected_stdout=('restricted preparation '+variant+'; actual backend hooks; host controls denied\n').encode(),
                        standard_version='1.5.0-beta.1',repo_id='cadence-oss',build_ref='TEST-preparation',
                        repo_sha='0'*40,gate_id='TEST-backend-preparation',timeout=18)
                    attempts.append((report,result))
                    self.assertEqual(report['overallOutcome'],'pass',result)
                    original=json.loads(result['stderr'])
                    self.assertEqual(original['variant'],variant)
                    self.assertEqual(original['backendSha256'],hashlib.sha256((project/'backend.py').read_bytes()).hexdigest())
                    self.assertEqual(original['pipExitCode']!=0,variant=='dynamic-unapproved')
                    self.assertTrue(all(row['uid']==[65532]*3 and row['denied']==['read','write','socket']
                                        for row in original['observations']))
                    if variant=='fallback':
                        self.assertEqual(original['wheel']['members']['das_preparation_fixture.py'],hashlib.sha256(b'VALUE = 1\n').hexdigest())
                        self.assertEqual([row['stage'] for row in original['observations']],['dynamic-requirements','build-wheel','build-wheel'])
                    elif variant=='metadata':
                        self.assertEqual([row['stage'] for row in original['observations']],['dynamic-requirements','metadata'])
                        self.assertIsNone(original['wheel'])
                    else:
                        self.assertEqual([row['stage'] for row in original['observations']],['dynamic-requirements'])
                        self.assertIsNone(original['wheel'])
                    self.assertEqual(result['observed']['workerPreparation']['uid'],[65532]*3)
                    self.assertTrue(result['domainTerminated']);self.assertEqual(marker.read_bytes(),raw)
                    listener.settimeout(.1)
                    with self.assertRaises(socket.timeout):listener.accept()
            self.keep_driver_evidence('runtime-attempt-python-preparation.json',attempts,dict(
                variants=['metadata','fallback','dynamic-unapproved'],hostMarkerSha256=hashlib.sha256(raw).hexdigest(),
                hostReadControl=True,hostSocketControl=True,hostUnexpectedConnections=0,
                dependencyFiles=[dict(path=p.relative_to(dependencies).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                                 for p in sorted(dependencies.rglob('*')) if p.is_file()]))

    def test_sealed_launcher_ignores_environment_and_replaced_executable_path(self):
        import dataclasses
        import shutil
        original_directory=Path.cwd()
        controls=Path(self.directory.name)/'launcher-controls';controls.mkdir(mode=0o700)
        executable=controls/'approved-engine'
        shutil.copyfile(self.control.config.cli,executable);executable.chmod(0o500)
        settings=dataclasses.replace(self.control.config,cli=str(executable))
        sealed=controller.Controller(settings)
        marker=controls/'fake-was-executed'
        fake=b'#!/bin/sh\nprintf bad > '+str(marker).encode()+b'\nexit 99\n'
        try:
            # The owned original pathname changes AFTER trusted admission. The
            # actual executable remains the approved, sealed memfd, not this file.
            executable.chmod(0o700);executable.write_bytes(fake)
            (controls/'docker').write_bytes(fake);(controls/'docker').chmod(0o700)
            (self.root/'run.py').write_text("print('sealed launcher healthy')\n")
            (self.root/'run.py').chmod(0o644)
            with patch.dict(os.environ,{'PATH':str(controls),'DOCKER_HOST':'unix:///TEST-unapproved.sock',
                    'DOCKER_CONFIG':str(controls),'DOCKER_CONTEXT':'TEST-unapproved','LD_PRELOAD':'/TEST-not-a-library'}):
                os.chdir(controls)
                observation=sealed.run(self.root,expected_snapshot=controller.snapshot(self.root))
            self.assertIsNone(observation['failureType'],observation)
            self.assertTrue(observation['domainTerminated'])
            self.assertEqual(observation['candidateStdout'],b'sealed launcher healthy\n')
            self.assertEqual(observation['daemonId'],self.control.config.daemon_id)
            self.assertEqual(observation['engineCliSha256'],self.control.config.cli_sha256)
            self.assertFalse(marker.exists())
            # A new controller cannot approve changed bytes by reusing an old pin.
            with self.assertRaisesRegex(controller.ReferenceError,'digest differs'):
                controller.Controller(settings)
            self.keep_driver_evidence('runtime-sealed-launcher.json',[(None,observation)],dict(
                originalCliSha256=settings.cli_sha256,replacedPathSha256=controller.digest(fake),
                fakeExecuted=False,newAdmissionRefused=True,source='TEST owned executable copy'))
        finally:
            os.chdir(original_directory);sealed.close()

    def test_engine_parser_preserves_fixed_argv_and_rejects_mount_grammar_injection(self):
        """Real Docker parser and inspect; observers forward unchanged calls."""
        calls=[];inspections=[]
        actual_call=self.control._call;actual_inspect=self.control._inspect
        def observe(arguments,**options):
            calls.append(list(arguments));return actual_call(arguments,**options)
        def inspect(identifier):
            value=actual_inspect(identifier);inspections.append(value);return value
        original=self.root
        legal=original.parent/'--config=@response name;$(false) 中文'
        original.rename(legal);self.root=legal
        try:
            (legal/'run.py').write_text("print('TEST fixed engine parser healthy')\n")
            (legal/'run.py').chmod(0o644)
            with patch.object(self.control,'_call',side_effect=observe),patch.object(self.control,'_inspect',side_effect=inspect):
                result=self.control.run(legal,expected_snapshot=controller.snapshot(legal))
                self.assertIsNone(result['failureType'],result)
                self.assertTrue(result['domainTerminated'])
                self.assertEqual(result['candidateStdout'],b'TEST fixed engine parser healthy\n')
                count=len(calls)
                for suffix in (',readonly=false', '\n--privileged', '\x00--config=response.txt'):
                    with self.assertRaisesRegex(controller.ReferenceError,'elapsed/mount parameters'):
                        self.control.run(str(legal)+suffix,expected_snapshot=controller.snapshot(legal))
                    self.assertEqual(len(calls),count,'invalid mount grammar reached engine')
            creates=[args for args in calls if args[:2]==['container','create']]
            self.assertEqual(len(creates),1)
            argv=creates[0]
            self.assertEqual(argv[argv.index('--mount')+1],f'type=bind,src={legal},dst=/candidate,readonly,bind-recursive=disabled,bind-propagation=rprivate')
            self.assertEqual(argv[argv.index('--platform')+1],'linux/amd64')
            self.assertEqual(argv[argv.index('--entrypoint')+1:],['/usr/local/bin/python3',self.control.config.image_id,'-u','-I','-S','-c',controller.STAGE])
            self.assertEqual(inspections[0]['ImageManifestDescriptor']['digest'],result['selectedImageId'])
            self.assertNotIn('--privileged',argv)
            created=inspections[0]
            self.assertEqual(created['Mounts'][0]['Source'],str(legal))
            self.assertFalse(created['Mounts'][0]['RW'])
            self.assertFalse(created['HostConfig']['Privileged'])
            self.keep_driver_evidence('runtime-effective-engine-argv.json',[(None,result)],dict(
                engineCalls=calls,actualCreateInspection=created,legalPath=str(legal),
                refusedGrammar=['comma','newline','NUL'],unapprovedEngineCalls=0))
        finally:
            legal.rename(original);self.root=original

    def test_actual_native_control_drift_is_refused_before_candidate_start(self):
        (self.root/'run.py').write_text("print('candidate must not start under changed controls')\n")
        (self.root/'run.py').chmod(0o644)
        attempts=[];created=[]
        original=self.control._call
        for variant in ('network','writable-root','writable-input'):
            with self.subTest(variant=variant):
                def changed(arguments,**kwargs):
                    values=list(arguments)
                    if values[:2]==['container','create']:
                        if variant=='network':values[values.index('--network')+1]='host'
                        elif variant=='writable-root':values.remove('--read-only')
                        else:
                            index=values.index('--mount')+1
                            values[index]=values[index].replace(',readonly,',',')
                        code,out,err=original(values,**kwargs)
                        if code==0:created.append(out.strip().decode('ascii'))
                        return code,out,err
                    return original(values,**kwargs)
                with patch.object(self.control,'_call',side_effect=changed):
                    observation=self.control.run(self.root,expected_snapshot=controller.snapshot(self.root))
                self.assertEqual(observation['failureType'],'ReferenceError',observation)
                self.assertIn('native created controls differ',observation['failureReason'])
                self.assertEqual(observation['observed'],{})
                self.assertIsNone(observation['candidateStdout'])
                self.assertIsNone(observation['exitCode'])
                code,_,_=original(['container','inspect',created[-1]])
                self.assertNotEqual(code,0,'refused, never-started container must be removed')
                attempts.append((None,observation))
        healthy=self.run_candidate("print('fresh controls admitted')\n")
        self.assertEqual(healthy['exitCode'],0)
        attempts.append((None,healthy))
        self.keep_driver_evidence('runtime-native-control-drift.json',attempts,dict(
            changedControls=['network','writable-root','writable-input'],
            refusedBeforeStart=True,createdNativeIds=created,healthyFreshAdmission=True))

    def test_parent_exit_cannot_leave_output_writers_or_a_reusable_domain(self):
        source="""import os,time
r,w=os.pipe()
child=os.fork()
if child==0:
 os.close(r);os.setsid()
 with open('/tmp/legal-descendant','w') as stream:stream.write('allowed')
 print('child-ready',flush=True);os.write(w,b'1');os.close(w)
 time.sleep(3);print('LATE-CHILD-OUTPUT',flush=True);time.sleep(60)
os.close(w);assert os.read(r,1)==b'1';os.close(r)
print('parent-done',flush=True)
"""
        observation=self.run_candidate(source)
        self.assertIsNone(observation['failureType'],observation)
        self.assertEqual(observation['exitCode'],0)
        self.assertEqual(observation['candidateStdout'],b'child-ready\nparent-done\n')
        code,_,_=self.control._call(['container','inspect',observation['containerId']])
        self.assertNotEqual(code,0)
        cgroup=Path(observation['observed']['cgroupPath'])
        self.assertTrue(not cgroup.exists() or not (cgroup/'cgroup.procs').read_text().strip())
        healthy=self.run_candidate("from pathlib import Path\nassert not Path('/tmp/legal-descendant').exists()\nprint('fresh scratch')\n")
        self.assertNotEqual(healthy['containerId'],observation['containerId'])
        self.assertEqual(healthy['candidateStdout'],b'fresh scratch\n')
        self.keep_driver_evidence('runtime-parent-exit.json',[(None,observation),(None,healthy)],dict(
            descendantSession=True,heldStdout=True,lateOutputAbsent=True,
            originalDomainRemoved=True,freshDomainDifferent=True))

    def test_actual_mount_topology_and_kernel_boundary_preserve_legal_scratch(self):
        source="""import ctypes,json,os
from pathlib import Path
rows=[]
for line in Path('/proc/self/mountinfo').read_text().splitlines():
 fields=line.split();separator=fields.index('-')
 rows.append(dict(path=fields[4],options=fields[5].split(','),optional=fields[6:separator],
                  filesystem=fields[separator+1]))
root=[row for row in rows if row['path']=='/'];assert len(root)==1 and 'ro' in root[0]['options']
candidate=[row for row in rows if row['path']=='/candidate'];assert len(candidate)==1 and 'ro' in candidate[0]['options']
assert not any(row['path'].startswith('/candidate/') for row in rows)
assert not any(item.startswith(('shared:','master:','propagate_from:')) for row in rows for item in row['optional'])
scratch=Path('/tmp/legal-topology');scratch.mkdir();(scratch/'data').write_text('allowed')
assert (scratch/'data').read_text()=='allowed'
denied=[]
for name,path in [('input','/candidate/run.py'),('root','/TEST-root-write')]:
 try:Path(path).write_text('unapproved')
 except OSError as exc:denied.append(dict(name=name,errno=exc.errno))
 else:raise AssertionError('unexpected write '+name)
libc=ctypes.CDLL(None,use_errno=True)
result=libc.mount(b'none',str(scratch).encode(),b'tmpfs',0,None)
assert result==-1 and ctypes.get_errno() in (1,13)
denied.append(dict(name='new-mount',errno=ctypes.get_errno()))
print(json.dumps(dict(mounts=rows,denied=denied,uid=os.geteuid(),scratch='allowed'),sort_keys=True))
"""
        observation=self.run_candidate(source)
        self.assertIsNone(observation['failureType'],observation)
        self.assertEqual(observation['exitCode'],0,observation)
        topology=json.loads(observation['candidateStdout'])
        self.assertEqual(topology['uid'],65532)
        self.assertEqual([row['name'] for row in topology['denied']],['input','root','new-mount'])
        self.keep_driver_evidence('runtime-mount-topology.json',[(None,observation)],dict(
            topology=topology,nestedInputMountsObserved=False,inputPropagation='rprivate',
            recursiveBind='disabled',notificationAdapterUsed=False,
            boundary='finite actual namespace; hostile host nested mount/writer variants remain open'))

    def test_timeout_terminates_descendants_outside_the_original_process_group(self):
        result=self.run_candidate("import os,time\nif os.fork()==0:\n os.setsid();time.sleep(60)\ntime.sleep(60)\n",timeout=2)
        self.assertIsNotNone(result['failureType'])
        self.assertIsNone(result['exitCode'])
        self.assertTrue(result['domainTerminated'])

    def test_candidate_pass_json_does_not_grant_authority(self):
        result=self.run_candidate("print('{\\\"PASS\\\":true,\\\"authorityVerified\\\":true}')\n")
        self.assertEqual(result['exitCode'],0)
        self.assertFalse(result['authorityVerified'])
        self.assertFalse(result['qualificationEligible'])

    def test_guardian_stops_the_domain_after_real_host_controller_death(self):
        (self.root/'run.py').write_text('import time\ntime.sleep(60)\n');(self.root/'run.py').chmod(0o644)
        marker=Path(self.directory.name)/'admitted.json'
        source='''
import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('guardian_death_probe',sys.argv[1])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
control=module.Controller(module.EngineConfig(**json.loads(Path(sys.argv[2]).read_text())))
original_inspect=control._inspect
identifier=None
def inspect(value):
 global identifier
 identifier=value
 return original_inspect(value)
control._inspect=inspect
original_call=control._call
def call(arguments,**kwargs):
 ready=kwargs.get('ready')
 if ready:
  def admit(metadata):
   ready(metadata)
   Path(sys.argv[4]).write_text(json.dumps({'id':identifier}))
  kwargs['ready']=admit
 return original_call(arguments,**kwargs)
control._call=call
root=Path(sys.argv[3])
control.run(root,expected_snapshot=module.snapshot(root),timeout=30)
'''
        process=subprocess.Popen([sys.executable,'-B','-c',source,str(PATH),os.environ['CADENCE_DAS_V15_REFERENCE_CONFIG'],str(self.root),str(marker)],
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        identifier=None
        try:
            limit=controller.now()+10
            while not marker.exists() and controller.now()<limit:
                if process.poll() is not None:break
                time.sleep(.05)
            self.assertTrue(marker.exists(),'reference did not complete native admission')
            identifier=json.loads(marker.read_text())['id']
            native=self.control._inspect(identifier)
            pid=native['State']['Pid']
            self.assertTrue(native['State']['Running'])
            relative=Path(f'/proc/{pid}/cgroup').read_text().strip().split('0::',1)[1]
            cgroup=Path('/sys/fs/cgroup')/relative.lstrip('/')
            process.kill();process.wait(timeout=5)
            limit=controller.now()+30
            while controller.now()<limit:
                state=self.control._inspect(identifier)['State']
                if state['Running'] is False and state['Pid']==0:break
                time.sleep(.1)
            self.assertFalse(state['Running'])
            self.assertEqual(state['Pid'],0)
            self.assertTrue(not cgroup.exists() or not (cgroup/'cgroup.procs').read_text().strip())
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            if identifier:
                self.control._call(['container','kill',identifier])
                self.control._call(['container','rm',identifier])
