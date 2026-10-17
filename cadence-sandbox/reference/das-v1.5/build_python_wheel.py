"""Fixed offline wheel recipe, run only inside the installed reference domain.

The installer snapshots /candidate with source/, wheelhouse/ and build-inputs.json.
Backend code is candidate execution. Stdout is bounded raw output, never approval.
The host must verify actual wheel bytes, termination and the complete snapshot.
"""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import zipfile


def main():
    root=Path('/candidate')
    inputs=json.loads((root/'build-inputs.json').read_bytes())
    if (set(inputs)!={'buildWheels','sourceDateEpoch'} or type(inputs['sourceDateEpoch']) is not int
            or not 315532800<=inputs['sourceDateEpoch']<=2147483647
            or not isinstance(inputs['buildWheels'],dict) or len(inputs['buildWheels'])!=3):
        raise RuntimeError('fixed build wheels and reproducible epoch required')
    dependencies=Path('/tmp/build-dependencies');dependencies.mkdir()
    prefixes=set()
    for name,expected in inputs['buildWheels'].items():
        if (Path(name).name!=name or not name.endswith('-py3-none-any.whl')
                or name.split('-')[0] not in {'setuptools','wheel','packaging'}):
            raise RuntimeError('unsupported build dependency')
        prefixes.add(name.split('-')[0]);raw=(root/'wheelhouse'/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('build wheel digest differs')
        with zipfile.ZipFile(root/'wheelhouse'/name) as archive:archive.extractall(dependencies)
    if prefixes!={'setuptools','wheel','packaging'}:raise RuntimeError('complete offline backend required')
    source=Path('/tmp/source');shutil.copytree(root/'source',source)
    output=Path('/tmp/wheels');output.mkdir()
    os.environ.update(SOURCE_DATE_EPOCH=str(inputs['sourceDateEpoch']),PYTHONDONTWRITEBYTECODE='1',
        PIP_NO_INDEX='1',PIP_DISABLE_PIP_VERSION_CHECK='1',LANG='C.UTF-8',TZ='UTC')
    sys.dont_write_bytecode=True;sys.path.insert(0,str(dependencies));os.chdir(source)
    # No dependency resolver, package index, install hook or host subprocess.
    # All backend imports and source processing occur under the candidate UID.
    with contextlib.redirect_stdout(sys.stderr):
        from setuptools.build_meta import build_wheel
        name=build_wheel(str(output))
    if Path(name).name!=name or not name.endswith('.whl'):raise RuntimeError('invalid build output')
    raw=(output/name).read_bytes()
    if len(raw)>512*1024:raise RuntimeError('wheel exceeds this finite reference output budget')
    print(json.dumps(dict(filename=name,sha256=hashlib.sha256(raw).hexdigest(),
        wheelBase64=base64.b64encode(raw).decode('ascii')),sort_keys=True,separators=(',',':')))


if __name__=='__main__':main()
