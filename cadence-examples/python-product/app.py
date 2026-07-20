from __future__ import annotations

import json


def run() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "taskId": "DAS-03-013",
        "product": "python-product",
        "verification": "python3 cadence-oss/cadence-examples/python-product/app.py",
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
