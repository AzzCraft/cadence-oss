from __future__ import annotations

import json
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = CORE_ROOT / "tests" / "fixtures" / "cad003"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _flatten_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))




def test_cad_003_clean_fixture_is_offline_and_has_relative_artifacts() -> None:
    report = _load_json(FIXTURES / "replay-clean" / "compare-report.json")

    assert report["task"] == "CAD-003"
    assert report["offline"] is True
    assert report["compare"]["same"] is True
    assert report["compare"]["diffs"] == []
    assert report["runManifestRef"] == "run-manifest.json"
    assert report["inputCassetteRef"] == "input-cassette.json"

    text = _flatten_text(report)
    for banned in ("/home/", "/Users/", "C:\\", "secret-token", "Bearer ", "ghp_"):
        assert banned not in text
    for artifact in report["artifacts"]:
        assert artifact["path"] == artifact["path"].lstrip("/")
        assert "://" not in artifact["path"]



def test_cad_003_sanitized_fixture_redacts_paths_tokens_and_names_leaks() -> None:
    leaky = _load_json(FIXTURES / "leaky-report" / "input-report.json")
    sanitized = _load_json(FIXTURES / "leaky-report" / "sanitized-report.json")
    leaky_text = _flatten_text(leaky)
    sanitized_text = _flatten_text(sanitized)

    for leaked in ("/home/alice", "/Users/bob", "C:\\\\Users\\\\carol", "secret-token-abc123", "ghp_private123"):
        assert leaked in leaky_text
        assert leaked not in sanitized_text

    assert sanitized["task"] == "CAD-003"
    assert sanitized["diagnostics"][0]["task"] == "CAD-003"
    assert sanitized["diagnostics"][0]["code"] == "PATH_OR_TOKEN_LEAK"
    assert sanitized["diagnostics"][0]["field"] == "artifacts[1].uri"
    assert "CAD-003" in sanitized["diagnostics"][0]["message"]
    assert "artifacts[1].uri" in sanitized["diagnostics"][0]["message"]

    for banned in ("/home/", "/Users/", "C:\\", "secret-token", "Bearer ", "ghp_"):
        assert banned not in sanitized_text


def test_hmac_scripts_keep_environment_key_out_of_child_arguments(tmp_path):
    import os
    import subprocess
    import sys
    key = 'synthetic-hmac-test-key-only'
    log = tmp_path / 'argv.jsonl'
    wrapper_dir = tmp_path / 'bin'; wrapper_dir.mkdir()
    wrapper = wrapper_dir / 'python3'
    wrapper.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                       'with open(' + repr(str(log)) + ',"a") as stream: stream.write(json.dumps(sys.argv)+"\\n")\n'
                       'os.execv(' + repr(sys.executable) + ',[' + repr(sys.executable) + ',*sys.argv[1:]])\n')
    wrapper.chmod(0o700)
    env = {**os.environ, 'PATH': str(wrapper_dir) + os.pathsep + os.environ['PATH'], 'CADENCE_SIGNING_KEY': key}
    payload = tmp_path / 'payload.json'; payload.write_text('{"test":true}')
    signature = tmp_path / 'signature.json'
    bundle = tmp_path / 'bundle'; bundle.mkdir()
    (bundle / 'run-manifest.json').write_bytes(payload.read_bytes())
    sign = CORE_ROOT / 'scripts/sign-evidence'
    verify = CORE_ROOT / 'scripts/verify-signature'
    for args in ([str(sign),'--input',str(payload),'--output',str(signature)],
                 [str(verify),'--input',str(signature),'--payload',str(payload)],
                 [str(sign),'--bundle',str(bundle)], [str(verify),'--bundle',str(bundle)]):
        proc = subprocess.run(['bash',*args],env=env,capture_output=True,text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert key not in proc.stdout + proc.stderr
    assert key not in log.read_text()
    for args in (['--input',str(signature),'--payload',str(payload)],['--bundle',str(bundle)]):
        bad = subprocess.run(['bash',str(verify),*args],env={**env,'CADENCE_SIGNING_KEY':'wrong-synthetic-key'},capture_output=True,text=True)
        assert bad.returncode != 0
