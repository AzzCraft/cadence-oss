from __future__ import annotations

from pathlib import Path
import runpy


def main() -> None:
    plugin_path = Path(__file__).resolve().parents[1] / "plugin.py"
    ns = runpy.run_path(str(plugin_path), run_name="cadence_plugin_python_plugin")
    fn = ns.get("main")
    if callable(fn):
        fn()

if __name__ == "__main__":
    main()
