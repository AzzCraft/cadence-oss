"""Development Linux Docker reference controller; never a qualification signer.

Run this file from an independently installed control domain. EngineConfig is
installed configuration, not a candidate request. One bounded Python workload is
admitted only after daemon configuration and actual cgroup limits are observed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import tarfile
import time
import uuid

WORKER_UID=65532
MEMORY=128*1024*1024
PIDS=64
MAX_OUTPUT=1024*1024
READY=b'DAS_REFERENCE_STAGE_READY\n'
WORKER_READY=b'DAS_REFERENCE_WORKER_READY '
STAGE="""import os,time,json,signal
print('DAS_REFERENCE_STAGE_READY',flush=True)
with open('/proc/self/status') as stream:status={line.partition(':')[0]:line.partition(':')[2].strip() for line in stream if ':' in line}
print(json.dumps({'namespaces':{key:os.readlink('/proc/self/ns/'+key) for key in ('pid','mnt','net','ipc','uts','cgroup')},'uid':os.geteuid(),'pid':os.getpid(),'seccomp':status['Seccomp'],'capEff':status['CapEff'],'noNewPrivileges':status['NoNewPrivs']}),flush=True)
end=time.clock_gettime(time.CLOCK_BOOTTIME)+25
while not os.path.exists('/tmp/das-admitted'):
 if time.clock_gettime(time.CLOCK_BOOTTIME)>end:raise SystemExit(124)
 time.sleep(.02)
child=os.fork()
if child==0:
 os.setgroups([]);os.setresgid(65532,65532,65532);os.setresuid(65532,65532,65532)
 with open('/proc/self/status') as stream:status={line.partition(':')[0]:line.partition(':')[2].strip() for line in stream if ':' in line}
 worker={'uid':os.getresuid(),'gid':os.getresgid(),'groups':os.getgroups(),'capEff':status['CapEff'],'capPrm':status['CapPrm'],'capInh':status['CapInh'],'capAmb':status['CapAmb'],'noNewPrivileges':status['NoNewPrivs']}
 if any(int(worker[key],16)!=0 for key in ('capEff','capPrm','capInh','capAmb')) or os.getresuid()!=(65532,65532,65532):os._exit(126)
 print('DAS_REFERENCE_WORKER_READY '+json.dumps(worker),flush=True)
 os.execv('/usr/local/bin/python3',['python3','-I','-S','/candidate/run.py'])
while time.clock_gettime(time.CLOCK_BOOTTIME)<end:
 finished,status=os.waitpid(child,os.WNOHANG)
 if finished:
  result=os.waitstatus_to_exitcode(status)
  os._exit(result if result>=0 else 128-result)
 time.sleep(.02)
os.kill(child,signal.SIGKILL)
os._exit(124)
"""
ADMIT="import os;f=os.open('/tmp/das-admitted',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(f,b'1');os.close(f)"


class ReferenceError(RuntimeError):pass


class LocalStopRequested(ReferenceError):
    """Installed health policy failed; only the exact local domain may be stopped."""


@dataclass(frozen=True)
class LocalStop:
    # Installed bounded local predicates, never candidate-selected callbacks.
    check: object
    record: object


@dataclass(frozen=True)
class EngineConfig:
    cli: str
    cli_sha256: str
    socket_path: str
    image_id: str
    daemon_id: str


@dataclass(frozen=True)
class ImageMaterial:
    # Independently installed approval, never candidate-selected archive/digest.
    archive_path: str
    archive_sha256: str
    child_digest: str


def image_material_binding(material):
    """Read a bounded OCI-layout tar; never extract it or load it into Docker.

    Selected linux/amd64 manifest/config/layers are exact native bytes. Unselected
    extensions need not be understood or fetched. Engine applies layer transforms;
    this check binds compressed content and ordered uncompressed diff IDs.
    """
    if (not isinstance(material,ImageMaterial)
            or not re.fullmatch(r'[0-9a-f]{64}',material.archive_sha256)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',material.child_digest)):
        raise ReferenceError('independently installed image material required')
    path=Path(material.archive_path)
    if not path.is_absolute() or path.resolve()!=path:
        raise ReferenceError('image material must have a normalized protected path')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                or info.st_mode&0o022 or not 0<info.st_size<=192*1024*1024):
            raise ReferenceError('image material custody or archive bound differs')
        with os.fdopen(os.dup(descriptor),'rb') as stream:
            measured=hashlib.sha256();read_size=0
            while True:
                part=stream.read(65536)
                if not part:break
                read_size+=len(part)
                if read_size>info.st_size:raise ReferenceError('image material changed while hashing')
                measured.update(part)
            if read_size!=info.st_size or measured.hexdigest()!=material.archive_sha256:
                raise ReferenceError('image material archive digest differs')
        os.lseek(descriptor,0,os.SEEK_SET)
        with os.fdopen(os.dup(descriptor),'rb') as stream,tarfile.open(fileobj=stream,mode='r:') as archive:
            entries={};total=0
            for member in archive:
                name=member.name
                if (len(entries)>=4096 or name in entries or not name or len(name)>256
                        or name.startswith('/') or any(p in ('','..','.') for p in name.split('/'))
                        or not (member.isdir() or member.isfile()) or member.sparse is not None):
                    raise ReferenceError('unsupported or duplicate image archive member')
                total+=member.size
                if total>192*1024*1024:raise ReferenceError('image archive member budget exceeded')
                entries[name]=member
            def read(name,bound):
                member=entries.get(name)
                if member is None or not member.isfile() or not 0<=member.size<=bound:
                    raise ReferenceError('missing or oversized selected OCI material')
                with archive.extractfile(member) as content:raw=content.read(bound+1)
                if len(raw)!=member.size:raise ReferenceError('incomplete selected OCI material')
                return raw
            def object_json(raw):
                def pairs(values):
                    result={}
                    for key,value in values:
                        if key in result:raise ReferenceError('duplicate OCI JSON key')
                        result[key]=value
                    return result
                value=json.loads(raw,object_pairs_hook=pairs,
                    parse_constant=lambda _:(_ for _ in ()).throw(ReferenceError('nonfinite OCI JSON')))
                if not isinstance(value,dict):raise ReferenceError('OCI object required')
                return value
            def blob(item,bound):
                if (not isinstance(item,dict) or type(item.get('size')) is not int
                        or not 0<=item['size']<=bound or not isinstance(item.get('digest'),str)
                        or not re.fullmatch(r'sha256:[0-9a-f]{64}',item['digest'])):
                    raise ReferenceError('unsupported selected OCI descriptor')
                raw=read('blobs/sha256/'+item['digest'][7:],bound)
                if len(raw)!=item['size'] or 'sha256:'+digest(raw)!=item['digest']:
                    raise ReferenceError('selected OCI blob size or digest differs')
                return raw
            if object_json(read('oci-layout',4096))!={'imageLayoutVersion':'1.0.0'}:
                raise ReferenceError('unsupported OCI layout')
            index_raw=read('index.json',1024*1024);index=object_json(index_raw)
            if (type(index.get('schemaVersion')) is not int or index['schemaVersion']!=2
                    or index.get('mediaType','application/vnd.oci.image.index.v1+json')!='application/vnd.oci.image.index.v1+json'
                    or not isinstance(index.get('manifests'),list)):
                raise ReferenceError('invalid OCI image index')
            selected=[v for v in index['manifests'] if isinstance(v,dict)
                and v.get('platform')=={'os':'linux','architecture':'amd64'}]
            if len(selected)!=1 or selected[0].get('digest')!=material.child_digest:
                raise ReferenceError('approved platform child absent or ambiguous')
            child=selected[0]
            if child.get('mediaType')!='application/vnd.oci.image.manifest.v1+json':
                raise ReferenceError('unsupported selected OCI child media type')
            manifest=object_json(blob(child,1024*1024))
            if (type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion']!=2
                    or manifest.get('mediaType')!=child['mediaType']
                    or not isinstance(manifest.get('layers'),list) or len(manifest['layers'])>64
                    or manifest.get('config',{}).get('mediaType')!='application/vnd.oci.image.config.v1+json'):
                raise ReferenceError('unsupported selected OCI manifest')
            config=object_json(blob(manifest['config'],1024*1024));rootfs=config.get('rootfs',{})
            if (config.get('os')!='linux' or config.get('architecture')!='amd64'
                    or config.get('config',{}).get('Volumes') or rootfs.get('type')!='layers'
                    or not isinstance(rootfs.get('diff_ids'),list)
                    or len(rootfs['diff_ids'])!=len(manifest['layers'])):
                raise ReferenceError('OCI config/platform/diff-ID sequence differs')
            layers=[];expanded=0
            for item,expected in zip(manifest['layers'],rootfs['diff_ids']):
                if item.get('mediaType') not in ('application/vnd.oci.image.layer.v1.tar',
                        'application/vnd.oci.image.layer.v1.tar+gzip'):
                    raise ReferenceError('unsupported selected OCI layer media type')
                raw=blob(item,192*1024*1024)
                content=io.BytesIO(raw)
                if item['mediaType'].endswith('+gzip'):content=gzip.GzipFile(fileobj=content)
                measured=hashlib.sha256();size=0
                with content:
                    while True:
                        part=content.read(65536)
                        if not part:break
                        expanded+=len(part);size+=len(part)
                        if expanded>256*1024*1024:raise ReferenceError('OCI expanded layer budget exceeded')
                        measured.update(part)
                actual='sha256:'+measured.hexdigest()
                if actual!=expected:raise ReferenceError('OCI ordered diff-ID differs')
                layers.append(dict(digest=item['digest'],diffId=actual,bytes=item['size'],expandedBytes=size))
            after=os.fstat(descriptor)
            if (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise ReferenceError('image material changed while verifying closure')
            return dict(archiveSha256=material.archive_sha256,indexDigest='sha256:'+digest(index_raw),
                childDigest=material.child_digest,configDigest=manifest['config']['digest'],
                platform={'os':'linux','architecture':'amd64'},layers=layers)
    except (ValueError,KeyError,TypeError,AttributeError,EOFError,RecursionError,tarfile.TarError,OSError) as exc:
        raise ReferenceError('selected image material unreadable or unsupported') from exc
    finally:os.close(descriptor)


def digest(data):return hashlib.sha256(data).hexdigest()
def now():return time.clock_gettime(time.CLOCK_BOOTTIME)


def members(root):
    pending=[root];count=0
    while pending:
        member=pending.pop();count+=1
        if count>10000:raise ReferenceError('reference input member limit')
        yield member
        if stat.S_ISDIR(member.lstat().st_mode):
            children=[]
            with os.scandir(member) as entries:
                for entry in entries:
                    children.append(Path(entry.path))
                    if len(children)+count+len(pending)>10000:
                        raise ReferenceError('reference input member limit')
            pending.extend(reversed(sorted(children)))


def snapshot(root):
    root=Path(root)
    if not root.is_absolute() or root.resolve()!=root or not root.is_dir():
        raise ReferenceError('materialized input must be a normalized protected directory')
    records=[];total=0
    for member in members(root):
        info=member.lstat()
        if info.st_uid!=os.getuid() or info.st_mode & 0o022:
            raise ReferenceError('input custody is not controlled by this installed driver')
        relative=member.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            records.append([relative,'directory',stat.S_IMODE(info.st_mode)])
        elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
            if info.st_size>32*1024*1024:raise ReferenceError('input member exceeds bound')
            total+=info.st_size
            if total>64*1024*1024:raise ReferenceError('cumulative reference input exceeds bound')
            descriptor=os.open(member,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                opened=os.fstat(descriptor)
                if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):raise ReferenceError('input changed during open')
                data=bytearray()
                while len(data)<=info.st_size:
                    part=os.read(descriptor,min(65536,info.st_size+1-len(data)))
                    if not part:break
                    data.extend(part)
                after=os.fstat(descriptor)
                if (after.st_size,after.st_mtime_ns,len(data))!=(info.st_size,info.st_mtime_ns,info.st_size):
                    raise ReferenceError('input changed while binding bytes')
                records.append([relative,'file',stat.S_IMODE(info.st_mode),digest(data)])
            finally:os.close(descriptor)
        else:raise ReferenceError('links and special members are unsupported in this reference snapshot')
        if len(records)>10000:raise ReferenceError('reference input member limit')
    if not (root/'run.py').is_file():raise ReferenceError('fixed run.py workload is missing')
    return digest(json.dumps(records,ensure_ascii=False,separators=(',',':')).encode('utf-8'))


class Controller:
    def __init__(self, config: EngineConfig, *, local_stop=None, image_material=None):
        if local_stop is not None and (not isinstance(local_stop,LocalStop)
                or not callable(local_stop.check) or not callable(local_stop.record)):
            raise ReferenceError('installed bounded local-stop policy required')
        self.local_stop=local_stop
        self.image_material=image_material
        if image_material is not None and not isinstance(image_material,ImageMaterial):
            raise ReferenceError('installed image material binding required')
        self.stopped=False
        if (not isinstance(config,EngineConfig) or os.getuid()==WORKER_UID
                or not hasattr(os,'memfd_create') or not hasattr(time,'CLOCK_BOOTTIME')
                or not re.fullmatch(r'[0-9a-f]{64}',config.cli_sha256)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',config.image_id) or not config.daemon_id):
            raise ReferenceError('unsupported or incomplete installed reference configuration')
        cli=Path(config.cli)
        if not cli.is_absolute() or cli.resolve()!=cli:raise ReferenceError('engine CLI must be normalized and fixed')
        descriptor=os.open(cli,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022 or info.st_size>128*1024*1024:
                raise ReferenceError('engine CLI is not a bounded trusted executable')
            with os.fdopen(os.dup(descriptor),'rb') as stream:data=stream.read(128*1024*1024+1)
            if digest(data)!=config.cli_sha256:raise ReferenceError('engine CLI digest differs from installation')
        finally:os.close(descriptor)
        daemon=Path(config.socket_path)
        if (not daemon.is_absolute() or daemon.resolve()!=daemon or not stat.S_ISSOCK(daemon.stat().st_mode)
                or daemon.stat().st_uid not in (0,os.getuid())):
            raise ReferenceError('only a fixed local Unix daemon socket is supported')
        self.config=config
        self.executable=os.memfd_create('das-reference-engine',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            view=memoryview(data)
            while view:view=view[os.write(self.executable,view):]
            os.fchmod(self.executable,0o500)
            fcntl.fcntl(self.executable,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        except BaseException:
            os.close(self.executable);raise
        self.client_config=tempfile.TemporaryDirectory(prefix='das-reference-client-')

    def close(self):
        os.close(self.executable);self.client_config.cleanup()

    def _command(self,arguments):
        return [f'/proc/self/fd/{self.executable}','--config',self.client_config.name,'--host','unix://'+self.config.socket_path,*arguments]

    def _call(self, arguments, *, timeout=10, ready=None, health=None):
        process=subprocess.Popen(self._command(arguments),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'LANG':'C.UTF-8'},pass_fds=(self.executable,),start_new_session=True)
        buffers={'stdout':bytearray(),'stderr':bytearray()};admitted=False;limit=now()+timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ,'stdout');selector.register(process.stderr,selectors.EVENT_READ,'stderr')
                while selector.get_map():
                    if now()>=limit:raise ReferenceError('native engine call exceeded its elapsed budget')
                    if health is not None:
                        try:healthy=health() is True
                        except Exception:healthy=False
                        if not healthy:raise LocalStopRequested('installed authority/audit health unavailable')
                    for key,_ in selector.select(min(.1,limit-now())):
                        chunk=os.read(key.fileobj.fileno(),65536)
                        if not chunk:selector.unregister(key.fileobj);continue
                        buffers[key.data].extend(chunk)
                        if sum(map(len,buffers.values()))>MAX_OUTPUT:raise ReferenceError('native output limit exceeded')
                        if ready is not None and not admitted and buffers['stdout'].startswith(READY) and buffers['stdout'].count(b'\n')>=2:
                            metadata=bytes(buffers['stdout'])[len(READY):].partition(b'\n')[0]
                            if len(metadata)>8192:raise ReferenceError('fixed preparation metadata limit')
                            ready(json.loads(metadata));admitted=True
                code=process.wait(timeout=max(.01,limit-now()))
                if ready is not None and not admitted:raise ReferenceError('fixed reference preparation stage did not become ready')
                return code,bytes(buffers['stdout']),bytes(buffers['stderr'])
        except LocalStopRequested as exc:
            exc.stdout=bytes(buffers['stdout']);exc.stderr=bytes(buffers['stderr'])
            raise
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=5);process.stdout.close();process.stderr.close()

    def _json(self, arguments):
        code,out,_=self._call(arguments)
        if code!=0:raise ReferenceError('native engine control query failed')
        return json.loads(out)

    def _inspect(self,identifier):
        values=self._json(['container','inspect',identifier])
        if not isinstance(values,list) or len(values)!=1 or values[0].get('Id')!=identifier:
            raise ReferenceError('container identity differs from created native ID')
        return values[0]

    def verify_output(self, root, *, expected_snapshot, expected_stdout,
                      standard_version, repo_id, build_ref, repo_sha, gate_id,
                      timeout=10):
        """Collect one independently asserted native run, without signing it.

        The installed driver fixes the expected bytes, gate and metadata from
        its approved plan; these are never candidate-selected operands. Return
        the Standard's existing report shape and the COMPLETE original native
        observation. Custody, complete attempt history, signatures and current
        action qualification remain the separate installed collection boundary.
        A candidate's stdout is only data, including anything saying PASS.
        """
        metadata = (standard_version, repo_id, build_ref, repo_sha, gate_id)
        if (type(expected_stdout) is not bytes or len(expected_stdout) > MAX_OUTPUT
                or any(type(value) is not str or not 1 <= len(value.encode('utf-8')) <= 128
                       or any(ord(char) < 32 or ord(char) == 127 for char in value)
                       for value in metadata)):
            raise ReferenceError('bounded installed output assertion and report metadata required')
        started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        observation = self.run(root, expected_snapshot=expected_snapshot, timeout=timeout)
        # Snapshot and termination are independent observations. A correct
        # printed answer or exit code cannot substitute for either one.
        if (observation['failureType'] is not None
                or observation['domainTerminated'] is not True
                or observation['snapshotUnchanged'] is not True
                or type(observation['exitCode']) is not int
                or type(observation['candidateStdout']) is not bytes):
            outcome = 'error'
        elif observation['exitCode'] != 0 or observation['candidateStdout'] != expected_stdout:
            outcome = 'fail'
        else:
            outcome = 'pass'
        report = dict(schemaVersion='1.0.0', standardManifestVersion=standard_version,
            repoId=repo_id, mode='custom', buildRef=build_ref, repoSha=repo_sha,
            startedAt=started, endedAt=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            overallOutcome=outcome, gates=[dict(gateId=gate_id, cadence='pr_blocking',
                enforcementClass='blocking', expected=True, executed=True, outcome=outcome,
                artifactCount=1, failureOnNoResults=True)])
        return report, observation

    def run(self, root, *, expected_snapshot, timeout=10):
        if self.stopped:
            raise ReferenceError('local stop is latched; independent recovery and new admission required')
        if self.local_stop is not None:
            try:healthy=self.local_stop.check() is True
            except Exception:healthy=False
            if not healthy:raise ReferenceError('current authority/audit admission unavailable')
        root=Path(root)
        if type(timeout) not in (int,float) or not 0<timeout<=30 or any(char in str(root) for char in ',\n\x00'):
            raise ReferenceError('invalid reference elapsed/mount parameters')
        if snapshot(root)!=expected_snapshot:raise ReferenceError('input differs from protected snapshot')
        info=self._json(['info','--format','{{json .}}'])
        if info.get('ID')!=self.config.daemon_id or info.get('OSType')!='linux' or str(info.get('CgroupVersion'))!='2':
            raise ReferenceError('daemon identity or Linux cgroup-v2 platform differs')
        # The approved ID can be an index. Resolve an explicit platform and verify
        # the created container's actual manifest descriptor. A child blob need
        # not have its own Docker image-store name, so retain the approved ID.
        image=self._json(['image','inspect','--platform','linux/amd64',self.config.image_id])[0]
        selected=image.get('Descriptor',{})
        if (not re.fullmatch(r'sha256:[0-9a-f]{64}',image.get('Id',''))
                or selected.get('digest')!=image['Id']
                or selected.get('mediaType')!='application/vnd.oci.image.manifest.v1+json'
                or image.get('Os')!='linux' or image.get('Architecture')!='amd64'
                or image.get('Config',{}).get('Volumes')):
            raise ReferenceError('reference requires an exact local linux/amd64 OCI child without implicit volumes')
        image_binding=None
        if self.image_material is not None:
            image_binding=image_material_binding(self.image_material)
            if (image_binding['childDigest']!=image['Id']
                    or image.get('RootFS',{}).get('Layers')!=[v['diffId'] for v in image_binding['layers']]):
                raise ReferenceError('native selected image differs from installed OCI material')
        name='das-v15-'+uuid.uuid4().hex
        arguments=['container','create','--pull','never','--platform','linux/amd64','--name',name,'--label','das.v15.reference='+name,
            '--network','none','--ipc','private','--cgroupns','private','--read-only','--user','0:0',
            '--cap-drop','ALL','--cap-add','SETUID','--cap-add','SETGID','--cap-add','KILL','--security-opt','no-new-privileges:true','--pids-limit',str(PIDS),
            '--memory',str(MEMORY),'--memory-swap',str(MEMORY),'--cpus','1','--ulimit','nofile=256:256',
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
            '--mount',f'type=bind,src={root},dst=/candidate,readonly,bind-recursive=disabled,bind-propagation=rprivate',
            '--workdir','/tmp','--restart','no','--log-driver','none','--entrypoint','/usr/local/bin/python3',
            self.config.image_id,'-u','-I','-S','-c',STAGE]
        code,out,_=self._call(arguments)
        identifier=out.strip().decode('ascii')
        if code!=0 or not re.fullmatch(r'[0-9a-f]{64}',identifier):
            raise ReferenceError('container creation did not return its exact native identity')
        cgroup=None;observed={};run_code=None;stdout=b'';stderr=b'';candidate_stdout=None;failure=None;reason=None;terminated=False
        local_stopped=False;record_status='not_requested'
        try:
            created=self._inspect(identifier);host=created['HostConfig']
            mounts=created['Mounts']
            if (created['Image']!=self.config.image_id
                or created.get('ImageManifestDescriptor',{}).get('digest')!=image['Id']
                or created['Config']['User']!='0:0'
                or created['Config']['Entrypoint']!=['/usr/local/bin/python3']
                or created['Config']['Cmd']!=['-u','-I','-S','-c',STAGE] or created['Config']['WorkingDir']!='/tmp'
                or host['RestartPolicy']['Name']!='no'
                or host['NetworkMode']!='none' or host['IpcMode']!='private' or host['CgroupnsMode']!='private'
                or host.get('PidMode') or host.get('UTSMode') or host.get('Privileged') or not host['ReadonlyRootfs']
                or host['PidsLimit']!=PIDS or host['Memory']!=MEMORY or host['MemorySwap']!=MEMORY or host['NanoCpus']!=10**9
                or host['CapDrop']!=['ALL'] or set(host.get('CapAdd') or [])!={'CAP_SETUID','CAP_SETGID','CAP_KILL'} or 'no-new-privileges:true' not in host['SecurityOpt']
                or len(mounts)!=1 or mounts[0]['Type']!='bind' or mounts[0]['Source']!=str(root)
                or mounts[0]['Destination']!='/candidate' or mounts[0]['RW'] or mounts[0]['Propagation']!='rprivate'):
                raise ReferenceError('native created controls differ from the installed reference')
            def admit(preparation):
                nonlocal cgroup,observed
                live=self._inspect(identifier)
                pid=live['State']['Pid']
                if not live['State']['Running'] or type(pid) is not int or pid<1:
                    raise ReferenceError('reference preparation domain is not running')
                lines=Path(f'/proc/{pid}/cgroup').read_text().splitlines()
                selected=[line[3:] for line in lines if line.startswith('0::')]
                if len(selected)!=1 or '..' in Path(selected[0]).parts:
                    raise ReferenceError('actual worker cgroup unavailable')
                cgroup=Path('/sys/fs/cgroup')/selected[0].lstrip('/')
                if not cgroup.resolve().is_relative_to(Path('/sys/fs/cgroup')) or pid not in [int(x) for x in (cgroup/'cgroup.procs').read_text().split()]:
                    raise ReferenceError('native PID does not occupy its observed resource domain')
                if (cgroup/'memory.max').read_text().strip()!=str(MEMORY) or (cgroup/'pids.max').read_text().strip()!=str(PIDS):
                    raise ReferenceError('actual memory/PID limit differs from declared controls')
                quota,period=(cgroup/'cpu.max').read_text().split()
                if quota=='max' or int(quota)>int(period) or (cgroup/'memory.swap.max').read_text().strip()!='0':
                    raise ReferenceError('actual CPU/swap constraints differ')
                if snapshot(root)!=expected_snapshot:raise ReferenceError('input changed before candidate admission')
                # These bytes are emitted by the fixed -I -S stage in the pinned
                # image before run.py is imported and before the admission gate.
                # Output emitted after the gate is exclusively candidate output.
                if (set(preparation)!={'namespaces','uid','pid','seccomp','capEff','noNewPrivileges'}
                        or preparation['uid']!=0 or preparation['pid']!=1
                        or preparation['seccomp']!='2' or int(preparation['capEff'],16)!=0xe0
                        or preparation['noNewPrivileges']!='1'
                        or set(preparation['namespaces'])!={'pid','mnt','net','ipc','uts','cgroup'}):
                    raise ReferenceError('fixed preparation privilege/namespace observation differs')
                namespaces={}
                for key,guest in preparation['namespaces'].items():
                    driver=os.readlink('/proc/self/ns/'+key)
                    if not isinstance(guest,str) or not re.fullmatch(r'[a-z]+:\[[0-9]+\]',guest) or driver==guest:
                        raise ReferenceError('preparation shares a required namespace with the driver')
                    namespaces[key]={'driver':driver,'preparation':guest}
                observed={'nativePid':pid,'cgroupPath':str(cgroup),'memoryMax':MEMORY,'pidsMax':PIDS,'cpuMax':[quota,period],
                    'networkMode':host['NetworkMode'],'inputReadOnly':True,'rootReadOnly':True,'workerUid':WORKER_UID,
                    'namespaceObservations':namespaces,'seccompMode':2,'guardianUid':0,'guardianCapabilityMask':'00000000000000e0','noNewPrivileges':True,'guardianElapsedLimitSeconds':25}
                code,_,_=self._call(['container','exec','--user','0',identifier,'/usr/local/bin/python3','-I','-S','-c',ADMIT])
                if code!=0:raise ReferenceError('trusted reference admission failed')
            run_code,stdout,stderr=self._call(['container','start','--attach',identifier],timeout=timeout,ready=admit,
                health=self.local_stop.check if self.local_stop is not None else None)
            records=stdout.split(b'\n',3)
            if len(records)<4 or not records[2].startswith(WORKER_READY):
                raise ReferenceError('trusted worker credential preparation was not observed')
            worker=json.loads(records[2][len(WORKER_READY):])
            if (set(worker)!={'uid','gid','groups','capEff','capPrm','capInh','capAmb','noNewPrivileges'}
                    or worker['uid']!=[WORKER_UID]*3 or worker['gid']!=[WORKER_UID]*3 or worker['groups']!=[]
                    or worker['noNewPrivileges']!='1' or any(int(worker[key],16)!=0 for key in ('capEff','capPrm','capInh','capAmb'))):
                raise ReferenceError('trusted worker credential drop differs from the reference')
            observed['workerPreparation']=worker
            # Preserve complete raw stdout. This separate exact tail starts only
            # after the fixed guardian's three checked preparation records;
            # candidate-emitted lookalike records remain untrusted tail bytes.
            candidate_stdout=records[3]
        except (ReferenceError,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
            failure=type(exc).__name__
            reason=str(exc) if isinstance(exc,ReferenceError) else None
            if isinstance(exc,LocalStopRequested):
                self.stopped=local_stopped=True
                stdout=exc.stdout;stderr=exc.stderr
        finally:
            # Only this exact created ID is touched. Killing the CLI process or
            # seeing candidate exit is insufficient to claim whole-domain stop.
            try:
                self._call(['container','kill',identifier])
                stopped=self._inspect(identifier)['State']
                cgroup_empty=cgroup is not None and (not cgroup.exists() or not (cgroup/'cgroup.procs').read_text().strip())
                terminated=stopped['Running'] is False and stopped['Pid']==0 and cgroup_empty
                if stopped['Running'] is False and stopped['Pid']==0:
                    self._call(['container','rm',identifier])
            except (ReferenceError,OSError,ValueError,KeyError,subprocess.SubprocessError):
                failure=failure or 'TerminationUnconfirmed'
                reason=reason or 'exact local domain termination unconfirmed; retain original ID'
            # Stopping precedes independent recording; record failure cannot
            # undo isolation or grant compensation/resend/completion authority.
            if local_stopped:
                event={'event':'preapproved_local_stop','containerId':identifier,
                    'domainTerminated':terminated,'businessResumeAllowed':False,
                    'globalRevocationEstablished':False,'auditGap':True}
                try:self.local_stop.record(event);record_status='recorded'
                except Exception:record_status='failed'
        return {'recordUse':'reference_native_observation_not_qualification','qualificationEligible':False,'authorityVerified':False,
            'imageId':self.config.image_id,'daemonId':self.config.daemon_id,'engineCliSha256':self.config.cli_sha256,
            'selectedImageId':image['Id'],'selectedPlatform':{'os':'linux','architecture':'amd64'},
            'imageMaterialBinding':image_binding,
            'snapshotSha256':expected_snapshot,'snapshotUnchanged':snapshot(root)==expected_snapshot,'containerId':identifier,
            'observed':observed,'domainTerminated':terminated,'exitCode':run_code,'failureType':failure,'failureReason':reason,
            'localStopRequested':local_stopped,'localStopRecord':record_status,'businessResumeAllowed':False,
            'stdout':stdout,'stderr':stderr,'candidateStdout':candidate_stdout}
