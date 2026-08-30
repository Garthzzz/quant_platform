from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile

from quant_hub.ops.local_product_surface import validate_local_product_surface


CANCELLED_WHEEL_MEMBERS = {
    "quant_hub/ops/failure_domain.py",
    "quant_hub/ops/failure_domain_authority.py",
    "quant_hub/ops/operational_source_cli.py",
    "quant_hub/ops/publish_recovery_cli.py",
    "quant_hub/ops/recovery_bundle.py",
    "quant_hub/ops/state_only_backup.py",
}


class CleanWheelBuildTests(unittest.TestCase):
    def test_real_wheel_cannot_inherit_cancelled_stale_build_modules(self) -> None:
        project = Path(__file__).parents[1].resolve(strict=True)
        poisoned = project / "build" / "lib" / "quant_hub" / "ops"
        poisoned.mkdir(parents=True, exist_ok=True)
        for member in CANCELLED_WHEEL_MEMBERS:
            (poisoned / Path(member).name).write_text(
                "raise RuntimeError('stale cancelled module')\n",
                encoding="utf-8",
            )
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--disable-pip-version-check",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    temporary,
                    str(project),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            wheels = tuple(Path(temporary).glob("*.whl"))
            self.assertEqual(1, len(wheels))
            with zipfile.ZipFile(wheels[0]) as archive:
                entries = set(archive.namelist())
            self.assertFalse(CANCELLED_WHEEL_MEMBERS & entries)
            self.assertIn("quant_hub/ops/local_product_surface.py", entries)
            configuration = tomllib.loads(
                (project / "pyproject.toml").read_text(encoding="utf-8")
            )
            scripts = configuration["project"]["scripts"]
            repository = project.parent
            source_root = project / "src" / "quant_hub"
            report = validate_local_product_surface(
                root="src/quant_hub",
                inventory={
                    "source_tree": [
                        {
                            "path": path.relative_to(source_root).as_posix(),
                            "source": path.read_text(encoding="utf-8"),
                        }
                        for path in sorted(source_root.rglob("*.py"))
                    ],
                    "installed_wheel_entry_names": sorted(entries),
                    "console_entrypoints": [
                        {"name": name, "target": target}
                        for name, target in sorted(scripts.items())
                    ],
                    "config_schema_filenames": [],
                    "runbook_filenames": sorted(
                        path.name
                        for path in (repository / "docs" / "runbooks").glob("*.md")
                    ),
                    "scheduled_task_names": [],
                },
            )
            self.assertTrue(report.passed)


if __name__ == "__main__":
    unittest.main()
