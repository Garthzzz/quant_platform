from pathlib import Path
import sys

for parent in Path(__file__).resolve().parents:
    candidate = parent / "src"
    if (candidate / "quant_hub" / "__init__.py").is_file():
        sys.path.insert(0, str(candidate))
        break
    if (parent / "quant_hub" / "__init__.py").is_file():
        sys.path.insert(0, str(parent))
        break
from quant_hub.paper_lab.compat import entry

if __name__ == "__main__":
    print("[deprecated] 请改用：qrh paper-lab scan", file=sys.stderr)
    entry("scan")
