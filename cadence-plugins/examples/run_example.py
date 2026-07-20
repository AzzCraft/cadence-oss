from __future__ import annotations

import json


def run() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "taskId": "DAS-03-020",
        "pluginId": "cadence-example-plugin",
        "ok": True,
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
