from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_root_verify_defaults_to_the_complete_release_surface() -> None:
    script = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
    all_units = (ROOT / "verify_all.sh").read_text(encoding="utf-8")

    assert 'mode="${1:---full}"' in script
    assert 'bash ./verify_all.sh' in script
    for unit in (
        "cadence-protocol",
        "cadence-core",
        "cadence-plugins",
        "cadence-policy-packs",
        "contracts-hub-template",
        "cadence-examples",
        "cadence-sandbox",
        "cadence-registry",
    ):
        assert unit in all_units


def test_root_verify_uses_a_disposable_cache_when_the_default_is_unusable() -> None:
    script = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")

    assert 'DEFAULT_GO_CACHE="$(go env GOCACHE)"' in script
    assert 'cadence-oss-go-cache.XXXXXX' in script
    assert 'trap cleanup_go_cache EXIT' in script
    assert 'rm -rf -- "$CADENCE_OSS_TEMP_GO_CACHE"' in script


def test_ci_uses_the_complete_verifier_and_audits_every_language_surface() -> None:
    workflow = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8")

    assert "bash ./scripts/verify --full" in workflow
    assert "find . -name go.mod -print0" in workflow
    assert "find . -name package-lock.json -print0" in workflow
    assert "pip-audit --progress-spinner off --strict -r requirements-verify.txt" in workflow
    assert "bandit -q -lll -r cadence-protocol cadence-plugins cadence-registry cadence-sandbox contracts-hub-template cadence-examples" in workflow
