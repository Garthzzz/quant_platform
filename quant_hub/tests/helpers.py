from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

from quant_hub.config import Settings
from quant_hub.archive.source_reader import archive_origin_uri
from quant_hub.ids import object_id_for_sha256, sha256_hex, stable_sha256
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.presentation import ArchivePresentation
from quant_hub.presentation.chapters import ArchiveChapterManifests


def public_test_archive_presentation() -> ArchivePresentation:
    """Return a synthetic presentation with no private research metadata."""

    return ArchivePresentation(
        {
            "schema_version": "qrh-archive-presentation/v1",
            "home": {
                "eyebrow": "Public test fixture",
                "title": "Synthetic archive",
                "introduction": "Public runtime contract fixture.",
            },
            "visibility": {"hidden_research_slugs": []},
            "search": {"excluded_line_markers": []},
            "research": {},
            "system_managed_topics": {
                "suppress_until_researcher_updates": [],
                "system_actor_names": [],
                "title_overrides": {},
            },
        }
    )


def install_public_archive_presentation(test_case: unittest.TestCase) -> None:
    """Keep public-checkout tests independent of ignored private resources."""

    presentation_patcher = mock.patch.object(
        ArchivePresentation,
        "default",
        return_value=public_test_archive_presentation(),
    )
    chapter_patcher = mock.patch.object(
        ArchiveChapterManifests,
        "default",
        return_value=mock.Mock(),
    )
    presentation_patcher.start()
    chapter_patcher.start()
    test_case.addCleanup(presentation_patcher.stop)
    test_case.addCleanup(chapter_patcher.stop)


def latest_activated_reviewed_delivery(
    workspace_root: Path,
    *,
    required_databases: tuple[str, ...] = (
        "platform.sqlite3",
        "archive.sqlite3",
        "research_papers.sqlite3",
        "paper_lab.sqlite3",
    ),
) -> Path:
    """Resolve the newest retained, activated delivery without naming an old version."""

    workspace_root = workspace_root.resolve(strict=True)
    candidates: list[tuple[str, int, Path]] = []
    for path in (workspace_root / "quant_hub" / "var").glob(
        "delivery-final-reviewed-*"
    ):
        match = re.search(r"-(\d{8})-v(\d+)$", path.name)
        assembly_seal = path / "ASSEMBLY_SEAL.json"
        activation_seal = path / "ACTIVATED_DELIVERY_SEAL.json"
        if (
            not match
            or not assembly_seal.is_file()
            or not activation_seal.is_file()
            or any(not (path / "db" / name).is_file() for name in required_databases)
        ):
            continue
        assembly = json.loads(assembly_seal.read_text(encoding="utf-8"))
        activation = json.loads(activation_seal.read_text(encoding="utf-8"))
        if assembly.get("status") != "PASS" or activation.get("status") != "PASS":
            continue
        candidates.append((match.group(1), int(match.group(2)), path))
    if not candidates:
        raise AssertionError("an activated reviewed delivery is required")
    return max(candidates)[2]


def _reviewed_object_roots(workspace_root: Path) -> tuple[Path, ...]:
    active = latest_activated_reviewed_delivery(workspace_root)
    roots = [active / "objects"]
    # A retained rollback may contain an object retired from the active release.
    # Only accept sealed, activated deliveries and always re-check blob identity.
    for path in sorted(
        (workspace_root / "quant_hub" / "var").glob("delivery-final-reviewed-*"),
        reverse=True,
    ):
        root = path / "objects"
        if (
            path != active
            and (path / "ACTIVATED_DELIVERY_SEAL.json").is_file()
            and (path / "ASSEMBLY_SEAL.json").is_file()
            and root.is_dir()
        ):
            roots.append(root)
    return tuple(roots)


def _reviewed_blob(object_roots: tuple[Path, ...], digest: str) -> Path:
    for object_root in object_roots:
        blob = object_root / digest[:2] / digest[2:4] / f"{digest}.blob"
        if blob.is_file():
            return blob
    raise AssertionError(f"reviewed historical object is unavailable: {digest}")


def materialize_reviewed_archive_with_historical_bootstraps(
    *,
    workspace_root: Path,
    destination: Path,
    restore_occurrence_snapshot: bool = False,
) -> Path:
    """Build a disposable replay source without writing to ``reference``.

    The user replaced Q2's old physical filenames with the current 12-document
    research package. Historical replay still needs the hash-bound Q2 bootstrap
    objects. They are resolved from retained activated deliveries so storage
    cleanup does not leave the suite coupled to a deleted V22 directory.
    """

    workspace_root = workspace_root.resolve(strict=True)
    source = workspace_root / "reference" / "archive"
    shutil.copytree(source, destination)
    formal_root = workspace_root / "quant_hub"
    object_roots = _reviewed_object_roots(workspace_root)
    fixture_names = ["q2-v2.json"]
    if restore_occurrence_snapshot:
        fixture_names.append("q2-v3.json")
    for fixture_name in fixture_names:
        release = json.loads(
            (formal_root / "fixtures" / "archive_b" / fixture_name).read_text(
                encoding="utf-8"
            )
        )
        for document in release["documents"]:
            relative = Path(str(document["source_path"]))
            digest = str(document["approved_content_sha256"])
            blob = _reviewed_blob(object_roots, digest)
            payload = blob.read_bytes()
            if (
                hashlib.sha256(payload).hexdigest() != digest
                or len(payload) != int(document["approved_bytes"])
            ):
                raise AssertionError("reviewed historical bootstrap object drifted")
            target = destination / relative
            if target.exists():
                if target.read_bytes() != payload:
                    raise AssertionError(
                        "historical bootstrap path conflicts with current source"
                    )
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

    # The reviewed evidence replay also binds exact duplicate aliases and
    # historical non-Markdown source occurrences that are no longer present in
    # the user's current Q2 package.  Reconstruct those paths only inside this
    # disposable test tree, from hash-addressed objects whenever possible and
    # otherwise from the independently reviewed remediation snapshot.
    if not restore_occurrence_snapshot:
        return destination

    occurrence_path = (
        workspace_root
        / "project_state"
        / "workers"
        / "archive_paper_clues"
        / "occurrences.jsonl"
    )
    reviewed_historical_archive = (
        workspace_root
        / "project_state"
        / "workers"
        / "d_independent_remediation_review"
        / "candidate_signed_final"
        / "reference"
        / "archive"
    ).resolve(strict=False)
    occurrence_sources: dict[str, str] = {}
    for line in occurrence_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if str(row.get("source_kind") or "") != "utf8_project_text":
            continue
        source_path = str(row.get("source_path") or "")
        digest = str(row.get("source_sha256") or "")
        if not source_path or len(digest) != 64:
            continue
        previous = occurrence_sources.setdefault(source_path, digest)
        if previous != digest:
            raise AssertionError("historical occurrence path has conflicting hashes")
    for source_path, digest in sorted(occurrence_sources.items()):
        relative = Path(source_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise AssertionError("historical occurrence source escapes archive root")
        target = destination / relative
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        try:
            blob = _reviewed_blob(object_roots, digest)
        except AssertionError:
            blob = object_roots[0] / "__missing__"
        fallback = reviewed_historical_archive / relative
        source_file = blob if blob.is_file() else fallback
        if not source_file.is_file():
            raise unittest.SkipTest(
                "retired historical occurrence fixture is not retained in the "
                f"compact workspace: {source_path}"
            )
        payload = source_file.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise AssertionError("reviewed historical occurrence source drifted")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return destination


class SettingsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "project"
        self.archive = self.project / "reference" / "archive"
        self.archive.mkdir(parents=True)
        self.var = self.project / "quant_hub" / "var"
        formal_root = Path(__file__).resolve().parents[1]
        self.settings = Settings(
            project_root=self.project,
            archive_root=self.archive,
            var_root=self.var,
            database_path=self.var / "db" / "platform.sqlite3",
            object_root=self.var / "objects",
            migration_root=formal_root / "migrations" / "platform",
        )
        self.settings.validate()

    def approved_source_fields(self, relative_path: str) -> dict[str, object]:
        payload = (self.archive / Path(relative_path)).read_bytes()
        digest = sha256_hex(payload)
        return {
            "approved_origin_uri": archive_origin_uri(relative_path),
            "approved_object_urn": f"qrh:object:{object_id_for_sha256(digest)}",
            "approved_content_sha256": digest,
            "approved_bytes": len(payload),
        }

    def publish_with_test_certificate(self, catalog, release, *, label: str):
        draft = release.model_copy(
            update={
                "activate": False,
                "release_snapshot_urn": None,
                "activation_decision_hash": None,
            }
        )
        spec = catalog.prepare_release_candidate(draft)
        authority = ReleaseAuthority(self.settings)
        candidate = authority.register_candidate(spec)
        decision = authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=stable_sha256(
                "test-deterministic-gate/v1", label, spec.artifact_manifest_hash
            ),
            review_set_hash=stable_sha256(
                "test-review-set/v1", label, spec.source_snapshot_hash
            ),
            reconciliation_hash=stable_sha256(
                "test-reconciliation/v1", label, spec.projection_revision
            ),
            verdict="pass",
        )
        certificate = authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=spec.requirements_manifest_hash,
            issuance_key=stable_sha256("test-release-issuance/v1", label),
        )
        approved = draft.model_copy(
            update={
                "activate": True,
                "release_snapshot_urn": certificate.snapshot_urn,
                "activation_decision_hash": certificate.decision_hash,
            }
        )
        return catalog.publish_release(approved)
