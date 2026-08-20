from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.helpers import materialize_reviewed_archive_with_historical_bootstraps


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
GENERATED_ROOT = FORMAL_ROOT / "fixtures" / "archive_full" / "generated"
ARCHIVE_ROOT = WORKSPACE_ROOT / "reference" / "archive"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FullArchiveReplayTests(unittest.TestCase):
    def test_clean_replay_consumes_hash_bound_review_and_preserves_sources(self) -> None:
        index_path = GENERATED_ROOT / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        release_hashes = {
            row["research_slug"]: row["release_sha256"] for row in index["groups"]
        }
        release_hashes.update(
            {
                f"bootstrap:{row['release_key']}": row["sha256"]
                for row in index["bootstrap_releases"]
            }
        )
        current_paths = {
            str(document["source_path"])
            for group in index["groups"]
            for document in json.loads(
                (GENERATED_ROOT / str(group["release_file"])).read_text(
                    encoding="utf-8"
                )
            )["documents"]
        }
        historical_paths = {
            str(document["source_path"])
            for bootstrap in index["bootstrap_releases"]
            for document in json.loads(
                (WORKSPACE_ROOT / str(bootstrap["path"])).read_text(
                    encoding="utf-8"
                )
            )["documents"]
            if str(document["source_path"]) not in current_paths
        }
        expected_markdown = int(index["source"]["markdown_count"]) + len(
            historical_paths
        )
        expected_unmapped = int(index["coverage"]["excluded_count"]) + int(
            index["coverage"]["unassigned_count"]
        ) + int(index["coverage"].get("generic_count", 0))
        # This is deliberately a test-only review artifact. Production replay must
        # consume the separately persisted independent reviewer verdict.
        review = {
            "schema_version": "qrh-archive-full-mapping-review/v1",
            "status": "PASS",
            "candidate_index_sha256": sha256_file(index_path),
            "policy_sha256": index["policy_sha256"],
            "release_hashes": release_hashes,
            "reviewer_identity_hash": hashlib.sha256(
                b"test-only-independent-reviewer"
            ).hexdigest(),
            "review_set_hash": hashlib.sha256(
                b"test-only-full-archive-review-set"
            ).hexdigest(),
            "p0": [],
            "p1": [],
            "p2": [],
            "completion_approvals": [
                {
                    "research_slug": slug,
                    "approved": True,
                    "reason": "测试专用：验证审核证书消费链，不代表正式完成判定。",
                    "evidence_locators": ["tests/test_archive_full_replay.py"],
                }
                for slug in (
                    "q1-product-factor-evaluation",
                    "q3-training-method-reliability",
                    "q5-factor-history-sequence-compression",
                )
            ],
        }
        (FORMAL_ROOT / "var").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="full-archive-replay-", dir=FORMAL_ROOT / "var"
        ) as raw:
            temporary = Path(raw)
            review_path = temporary / "test-review.json"
            review_path.write_text(
                json.dumps(review, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            replay_archive = materialize_reviewed_archive_with_historical_bootstraps(
                workspace_root=WORKSPACE_ROOT,
                destination=temporary / "archive",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(FORMAL_ROOT / "src")
            environment["PYTHONUTF8"] = "1"
            command = [
                sys.executable,
                "-B",
                str(FORMAL_ROOT / "tools" / "replay_full_archive.py"),
                "--project-root",
                str(WORKSPACE_ROOT),
                "--archive-root",
                str(replay_archive),
                "--var-root",
                str(temporary / "var"),
                "--review-verdict",
                str(review_path),
            ]
            reports = []
            for _attempt in range(2):
                result = subprocess.run(
                    command,
                    cwd=WORKSPACE_ROOT,
                    env=environment,
                    capture_output=True,
                    timeout=300,
                    check=False,
                )
                self.assertEqual(
                    0,
                    result.returncode,
                    result.stderr.decode("utf-8", errors="replace"),
                )
                reports.append(json.loads(result.stdout.decode("utf-8")))
            report = reports[0]
            self.assertEqual(report["database"], reports[1]["database"])
            self.assertEqual(report["published"], reports[1]["published"])

        self.assertEqual("PASS", report["status"])
        self.assertEqual(0, report["source_integrity"]["changed"])
        self.assertEqual(
            expected_markdown,
            report["discovery"]["counts"]["markdown_candidates"],
        )
        self.assertEqual(0, report["discovery_before"]["counts"]["mapped"])
        self.assertEqual(
            expected_markdown,
            report["discovery_before"]["counts"]["unmapped"],
        )
        self.assertEqual(
            expected_markdown - expected_unmapped,
            report["discovery_after"]["counts"]["mapped"],
        )
        self.assertEqual(
            expected_unmapped,
            report["discovery_after"]["counts"]["unmapped"],
        )
        self.assertEqual(
            expected_unmapped,
            report["discovery_after"]["counts"]["pending_mapping"],
        )
        self.assertEqual(len(index["groups"]), len(report["published"]))
        self.assertEqual(
            sum(int(group["document_count"]) for group in index["groups"]),
            sum(row["documents"] for row in report["published"]),
        )
        self.assertEqual("ok", report["database"]["integrity_check"])
        self.assertEqual(0, report["database"]["foreign_key_violations"])
        self.assertEqual(
            3,
            report["database"]["counts"]["research_completion_review_consumption"],
        )


if __name__ == "__main__":
    unittest.main()
