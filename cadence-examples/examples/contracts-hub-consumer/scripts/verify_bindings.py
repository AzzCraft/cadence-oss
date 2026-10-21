#!/usr/bin/env python3
"""Validate the example's explicit local bindings, offline; no Core claim implied."""
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]


def local_file(raw):
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute() or ".." in Path(raw).parts:
        raise ValueError("binding paths must be relative local files")
    path = (ROOT / raw).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError(f"binding file is missing or outside the example: {raw}")
    return path


def main():
    payload = json.loads(local_file("contracts/bindings.json").read_text())
    if not isinstance(payload, dict) or payload.get("schemaVersion") != "1.0.0" or not isinstance(payload.get("bindings"), list) or not payload["bindings"]:
        raise ValueError("invalid or empty bindings document")
    for binding in payload["bindings"]:
        if not isinstance(binding, dict) or set(binding) != {"localPath", "contractId", "schemaRef", "validation"} or binding["validation"] != "strict" or not isinstance(binding["contractId"], str) or not binding["contractId"]:
            raise ValueError("invalid strict binding")
        schema_path = local_file(binding["schemaRef"])
        data_path = local_file(binding["localPath"])
        schema = json.loads(schema_path.read_text())
        Draft202012Validator.check_schema(schema)
        resources = []
        for candidate in schema_path.parent.glob("*.json"):
            if candidate.is_symlink():
                raise ValueError("schema resources must be ordinary local files")
            document = json.loads(candidate.read_text())
            resource = Resource.from_contents(document)
            resources.append((candidate.resolve().as_uri(), resource))
            if "$id" in document:
                resources.append((document["$id"], resource))
        validator = Draft202012Validator(schema, registry=Registry().with_resources(resources), format_checker=FormatChecker())
        try:
            validator.validate(json.loads(data_path.read_text()))
        except Exception as exc:
            raise ValueError(f"binding {binding['contractId']} ({binding['localPath']}): {exc}") from exc
    print(f"PASS: {len(payload['bindings'])} local data bindings validated; Core checks run separately")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
