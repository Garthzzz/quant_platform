from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from quant_hub.paper_lab.compat import entry

if __name__ == "__main__":
    entry("legacy-import")
