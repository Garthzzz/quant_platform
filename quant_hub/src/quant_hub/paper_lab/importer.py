from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
from typing import Any
from urllib.parse import quote
import uuid

from quant_hub.config import Settings, ensure_no_reparse_components, is_reparse_point
from quant_hub.platform.db import immediate_transaction, utc_now
from .assets import ManagedAssetError, verify_frozen_asset
from .database import paper_lab_connection
from .identity import normalized_relative_path, stable_public_id


_ID_PREFIX = re.compile(r"^(?P<id>[0-9]+)")
_PIPELINE_LAYERS = (
    "data_input",
    "data_preprocess",
    "method_model",
    "method_special",
    "loss_function",
    "training_config",
    "pipeline_output",
)
_LEGACY_FIELDS = (
    "id", "title", "link", "authors", "venue", "institution", "model_type",
    "asset_market", "start_year", "end_year", "study_period", "sample_length",
    "prediction_target", "input_features", "feature_count", "oos_method", "metrics",
    "performance", "special_tech", "source_type", "research_topic", "main_findings",
    "innovations_insights", "caveats_replication", "summary", "rating", "data_input",
    "data_preprocess", "method_model", "method_special", "loss_function",
    "training_config", "pipeline_output", "diagram", "pdf_path", "notes_path",
    "status", "phase", "updated_at",
)
_TARGET_NOTE_HEADINGS = {
    "解决什么问题",
    "方法与架构",
    "数据与训练",
    "核心结论",
    "核心创新与启发",
    "质疑与复现注意",
}
_VOCAB_SECTIONS = {
    "data_input tag": "data_input",
    "data_preprocess tag": "data_preprocess",
    "method_model tag": "method_model",
    "method_special tag": "method_special",
    "loss_function tag": "loss_function",
    "training_config tag": "training_config",
    "输出层tag": "pipeline_output",
}


@dataclass(frozen=True, slots=True)
class LegacyImportReport:
    status: str
    import_run_id: str
    source_manifest_sha256: str
    source_unchanged: bool
    source_counts: dict[str, int]
    imported_counts: dict[str, int]
    quarantine_counts: dict[str, int]
    unknown_tag_count: int
    local_pdf_routes_repaired: int
    snapshot_root: str
    database_path: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _JsonAsset:
    path: Path
    relative_path: str
    filename_id: str | None
    digest: str
    size: int
    has_bom: bool
    strict_error: str | None
    payload: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class _NoteAsset:
    path: Path
    relative_path: str
    filename_id: str | None
    digest: str
    size: int
    template_status: str


@dataclass(frozen=True, slots=True)
class _ManagedIntegrityFailure:
    asset_kind: str
    paper_id: str | None
    source_relative_path: str
    managed_relative_path: str
    expected_sha256: str
    expected_bytes: int
    error_code: str
    error_detail: str


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _source_urn(relative_path: str) -> str:
    return f"qrh:legacy-proj2:{quote(relative_path, safe='/')}"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_source_root(settings: Settings, source_root: Path) -> Path:
    ensure_no_reparse_components(source_root)
    resolved = source_root.resolve(strict=True)
    reference = (settings.project_root / "reference").resolve(strict=True)
    if not resolved.is_dir() or not _is_relative_to(resolved, reference):
        raise ValueError("legacy proj2 source must be an existing directory under reference/**")
    if is_reparse_point(resolved):
        raise ValueError("legacy proj2 source must not be a reparse point")
    return resolved


def _read_legacy_database(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or is_reparse_point(path):
        raise FileNotFoundError(f"legacy database missing or unsafe: {path}")
    uri = f"file:{quote(path.resolve().as_posix(), safe='/:')}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        quick = connection.execute("PRAGMA quick_check").fetchone()
        if quick is None or quick[0] != "ok":
            raise sqlite3.DatabaseError(f"legacy database quick_check failed: {quick}")
        return [dict(row) for row in connection.execute(
            "SELECT * FROM papers ORDER BY CAST(id AS INTEGER)"
        ).fetchall()]
    finally:
        connection.close()


def _copy_verified(source: Path, destination: Path, digest: str, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(destination.parent)
    if destination.exists():
        actual_digest, actual_size = _sha256_file(destination)
        if (actual_digest, actual_size) != (digest, size):
            raise RuntimeError(f"existing snapshot differs: {destination}")
        return
    temporary = destination.with_name(f".{destination.name}.tmp-{uuid.uuid4().hex}")
    try:
        with source.open("rb") as src, temporary.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        actual_digest, actual_size = _sha256_file(temporary)
        if (actual_digest, actual_size) != (digest, size):
            raise RuntimeError(f"snapshot verification failed: {source}")
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _relevant_source_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in ("papers/*.pdf", "research/json/*.json", "research/notes/*.md"):
        paths.extend(path for path in root.glob(pattern) if path.is_file())
    for relative in (
        "data/papers.db",
        "data/tag_components.json",
        "data/components.json",
        "data/concept_blocks.json",
        "data/compatibility_rules.json",
        "data/blueprints.json",
        "skills/vocab.md",
    ):
        path = root / relative
        if path.is_file():
            paths.append(path)
    return sorted(set(paths), key=lambda item: item.relative_to(root).as_posix())


def _source_manifest(root: Path) -> tuple[str, dict[str, tuple[int, int, str]]]:
    entries: dict[str, tuple[int, int, str]] = {}
    digest = hashlib.sha256()
    for path in _relevant_source_paths(root):
        relative = path.relative_to(root).as_posix()
        file_digest, size = _sha256_file(path)
        stat = path.stat()
        entries[relative] = (size, stat.st_mtime_ns, file_digest)
        digest.update(f"{relative}\0{size}\0{file_digest}\n".encode("utf-8"))
    return digest.hexdigest(), entries


def _json_assets(root: Path) -> list[_JsonAsset]:
    assets: list[_JsonAsset] = []
    for path in sorted((root / "research" / "json").glob("*.json"), key=lambda item: item.name):
        payload_bytes = path.read_bytes()
        digest = _sha256_bytes(payload_bytes)
        match = _ID_PREFIX.match(path.name)
        filename_id = str(int(match.group("id"))) if match else None
        has_bom = payload_bytes.startswith(b"\xef\xbb\xbf")
        strict_error: str | None = None
        try:
            decoded = payload_bytes.decode("utf-8")
            parsed = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            strict_error = f"{type(error).__name__}: {error}"
            try:
                parsed = json.loads(payload_bytes.decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
        assets.append(
            _JsonAsset(
                path=path,
                relative_path=path.relative_to(root).as_posix(),
                filename_id=filename_id,
                digest=digest,
                size=len(payload_bytes),
                has_bom=has_bom,
                strict_error=strict_error,
                payload=parsed if isinstance(parsed, dict) else None,
            )
        )
    return assets


def _note_assets(root: Path) -> list[_NoteAsset]:
    assets: list[_NoteAsset] = []
    for path in sorted((root / "research" / "notes").glob("*.md"), key=lambda item: item.name):
        payload = path.read_bytes()
        match = _ID_PREFIX.match(path.name)
        filename_id = str(int(match.group("id"))) if match else None
        try:
            text = payload.decode("utf-8-sig")
            headings = {
                line[3:].strip()
                for line in text.splitlines()
                if line.startswith("## ")
            }
            status = "six_section" if _TARGET_NOTE_HEADINGS.issubset(headings) else "legacy"
        except UnicodeDecodeError:
            status = "unparseable"
        assets.append(
            _NoteAsset(
                path=path,
                relative_path=path.relative_to(root).as_posix(),
                filename_id=filename_id,
                digest=_sha256_bytes(payload),
                size=len(payload),
                template_status=status,
            )
        )
    return assets


def _canonical_json_asset(assets: list[_JsonAsset]) -> _JsonAsset | None:
    valid = [item for item in assets if item.payload is not None]
    if not valid:
        return None
    return max(
        valid,
        key=lambda item: (
            item.payload.get("status") == "completed" if item.payload else False,
            not any(token in item.path.stem.casefold() for token in ("tmp", "skeleton")),
            len(item.payload or {}),
            item.size,
            item.path.name,
        ),
    )


def _canonical_note_asset(assets: list[_NoteAsset], declared: str | None, root: Path) -> _NoteAsset | None:
    if declared:
        try:
            declared_relative = normalized_relative_path(declared)
        except ValueError:
            declared_relative = ""
        for item in assets:
            if item.relative_path == declared_relative and (root / declared_relative).is_file():
                return item
    if not assets:
        return None
    return max(
        assets,
        key=lambda item: (
            item.template_status == "six_section",
            item.size,
            item.path.name,
        ),
    )


def _parse_vocab(path: Path) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    current_layer: str | None = None
    in_code = False
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line.startswith("###"):
            current_layer = next(
                (layer for marker, layer in _VOCAB_SECTIONS.items() if marker in line),
                None,
            )
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code and current_layer and line and not line.startswith("#"):
            result[(current_layer, line)] = "approved"
    return result


def _all_vocab_tags(path: Path) -> set[str]:
    """复刻旧 inventory 的兼容判定：任一受控 code block 出现即视为已知词。"""

    result: set[str] = set()
    in_code = False
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if (
            in_code
            and line
            and not line.startswith(("#", "{", "}"))
            and "|" not in line
        ):
            result.add(line)
    return result


def _extract_tags(payload: dict[str, Any]) -> list[tuple[str, str]]:
    tags: list[tuple[str, str]] = []
    for layer in _PIPELINE_LAYERS:
        value = payload.get(layer)
        if not isinstance(value, str):
            continue
        for raw in value.splitlines():
            line = raw.strip()
            if not line or line.startswith("→") or "|" not in line:
                continue
            tag = line.split("|", 1)[0].strip()
            if tag:
                tags.append((layer, tag))
    return sorted(set(tags))


class LegacyProj2Importer:
    """把 proj2 快照导入独立 Paper Lab；来源始终只读且 DB immutable。"""

    def __init__(self, settings: Settings, source_root: Path | None = None):
        self.settings = settings
        self.source_root = _safe_source_root(
            settings,
            source_root or settings.project_root / "reference" / "proj2",
        )
        self.snapshot_root = settings.paper_lab_asset_root.parent / "legacy_snapshot"

    def import_all(self) -> LegacyImportReport:
        before_hash, before_entries = _source_manifest(self.source_root)
        rows = _read_legacy_database(self.source_root / "data" / "papers.db")
        if len(rows) != 137:
            raise RuntimeError(f"expected 137 legacy DB rows, got {len(rows)}")
        pdfs = sorted((self.source_root / "papers").glob("*.pdf"), key=lambda item: item.name)
        json_assets = _json_assets(self.source_root)
        note_assets = _note_assets(self.source_root)
        if (len(pdfs), len(json_assets), len(note_assets)) != (137, 141, 161):
            raise RuntimeError(
                "legacy corpus count drift: "
                f"pdf={len(pdfs)}, json={len(json_assets)}, notes={len(note_assets)}"
            )

        import_run_id = stable_public_id("labimport", before_hash)
        with paper_lab_connection(self.settings) as connection:
            existing = connection.execute(
                "SELECT status,summary_json FROM legacy_import_run WHERE import_run_id=?",
                (import_run_id,),
            ).fetchone()
            if existing is not None and existing["status"] in {"completed", "failed"}:
                previous = json.loads(existing["summary_json"])
                failures = self._managed_integrity_failures(connection, import_run_id)
                after_hash, after_entries = _source_manifest(self.source_root)
                if before_hash != after_hash or before_entries != after_entries:
                    raise RuntimeError("reference/proj2 changed during repeated import verification")
                if failures:
                    return self._record_managed_integrity_failures(
                        connection,
                        import_run_id,
                        previous,
                        failures,
                    )
                if existing["status"] == "failed":
                    previous["status"] = "ERROR"
                return LegacyImportReport(**previous)

        self.snapshot_root.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(self.snapshot_root)
        for path in _relevant_source_paths(self.source_root):
            relative = path.relative_to(self.source_root).as_posix()
            size, _mtime, digest = before_entries[relative]
            _copy_verified(path, self.snapshot_root / Path(relative), digest, size)

        pdf_by_id: dict[str, Path] = {}
        pdf_meta: dict[str, tuple[str, int]] = {}
        for path in pdfs:
            match = _ID_PREFIX.match(path.name)
            if match is None:
                raise RuntimeError(f"legacy PDF has no numeric ID: {path.name}")
            legacy_id = str(int(match.group("id")))
            digest, size = _sha256_file(path)
            if legacy_id in pdf_by_id:
                raise RuntimeError(f"duplicate legacy PDF ID: {legacy_id}")
            pdf_by_id[legacy_id] = path
            pdf_meta[legacy_id] = (digest, size)
            object_path = self.settings.paper_lab_asset_root / digest[:2] / f"{digest}.pdf"
            _copy_verified(path, object_path, digest, size)

        json_by_id: dict[str, list[_JsonAsset]] = defaultdict(list)
        for item in json_assets:
            if item.filename_id is not None:
                json_by_id[item.filename_id].append(item)
        notes_by_id: dict[str, list[_NoteAsset]] = defaultdict(list)
        for item in note_assets:
            if item.filename_id is not None:
                notes_by_id[item.filename_id].append(item)

        imported = Counter()
        quarantines = Counter()
        unknown_tags: set[tuple[str, str]] = set()
        unknown_tag_occurrences = 0
        repaired_routes = 0
        now = utc_now()

        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                connection.execute(
                    """
                    INSERT OR REPLACE INTO legacy_import_run(
                        import_run_id,source_root,source_manifest_sha256,status,
                        started_at,finished_at,summary_json
                    ) VALUES(?,?,?,'running',?,NULL,'{}')
                    """,
                    (import_run_id, str(self.source_root), before_hash, now),
                )
                self._bootstrap_workflow(connection, now)
                vocab = _parse_vocab(self.source_root / "skills" / "vocab.md")
                all_vocab_tags = _all_vocab_tags(self.source_root / "skills" / "vocab.md")
                for (layer, tag_text), status in sorted(vocab.items()):
                    self._upsert_tag(connection, layer, tag_text, status, "legacy_vocab", now)

                for row in rows:
                    legacy_id = str(row["id"])
                    pdf_path = pdf_by_id.get(legacy_id)
                    if pdf_path is None:
                        raise RuntimeError(f"DB row {legacy_id} has no PDF")
                    pdf_digest, pdf_size = pdf_meta[legacy_id]
                    paper_id = stable_public_id("labpaper", "legacy_proj2", legacy_id)
                    version_id = stable_public_id("labver", paper_id, pdf_digest)
                    title = str(row.get("title") or pdf_path.stem)
                    connection.execute(
                        """
                        INSERT INTO lab_paper(
                            paper_id,legacy_id,canonical_title,lifecycle_status,
                            source_kind,created_at,updated_at
                        ) VALUES(?,?,?,'validated','legacy_proj2',?,?)
                        ON CONFLICT(paper_id) DO UPDATE SET
                            canonical_title=excluded.canonical_title,
                            updated_at=excluded.updated_at
                        """,
                        (paper_id, legacy_id, title, now, now),
                    )
                    asset_relative = f"{pdf_digest[:2]}/{pdf_digest}.pdf"
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO lab_paper_version(
                            paper_version_id,paper_id,content_sha256,bytes,media_type,
                            original_filename,source_location_urn,asset_relative_path,
                            discovery_status,created_at
                        ) VALUES(?,?,?,?,'application/pdf',?,?,?,'validated',?)
                        """,
                        (
                            version_id,
                            paper_id,
                            pdf_digest,
                            pdf_size,
                            pdf_path.name,
                            _source_urn(pdf_path.relative_to(self.source_root).as_posix()),
                            asset_relative,
                            now,
                        ),
                    )
                    imported["papers"] += 1
                    imported["paper_versions"] += 1
                    self._map(
                        connection, import_run_id, "db_row", legacy_id, None, None,
                        "lab_paper", paper_id, "imported", "equivalent", {}, now,
                    )
                    self._map(
                        connection,
                        import_run_id,
                        "pdf",
                        legacy_id,
                        pdf_path.relative_to(self.source_root).as_posix(),
                        pdf_digest,
                        "lab_paper_version",
                        version_id,
                        "imported",
                        "equivalent",
                        {"asset_relative_path": asset_relative},
                        now,
                    )

                    declared_pdf = row.get("pdf_path")
                    if not declared_pdf:
                        repaired_routes += 1
                        self._quarantine(
                            connection, import_run_id, paper_id, None,
                            "legacy_pdf_path_missing", "warning",
                            {"legacy_id": legacy_id, "repaired_from": pdf_path.name}, now,
                        )
                    elif not self._declared_exists(str(declared_pdf)):
                        repaired_routes += 1
                        self._quarantine(
                            connection, import_run_id, paper_id, str(declared_pdf),
                            "legacy_pdf_path_broken", "warning",
                            {"legacy_id": legacy_id, "repaired_from": pdf_path.name}, now,
                        )

                    candidates = json_by_id.get(legacy_id, [])
                    canonical_json = _canonical_json_asset(candidates)
                    for asset in candidates:
                        is_canonical = asset is canonical_json
                        status = "imported" if is_canonical and asset.payload is not None else (
                            "superseded" if asset.payload is not None else "quarantined"
                        )
                        self._map(
                            connection, import_run_id, "json", asset.relative_path,
                            asset.relative_path, asset.digest, "reading_result",
                            None, status,
                            "equivalent" if is_canonical else "legacy_defect_preserved",
                            {
                                "canonical": is_canonical,
                                "has_bom": asset.has_bom,
                                "strict_error": asset.strict_error,
                            },
                            now,
                        )
                        if asset.strict_error:
                            code = "legacy_json_utf8_bom" if asset.has_bom else "legacy_json_parse_error"
                            self._quarantine(
                                connection, import_run_id, paper_id, asset.relative_path,
                                code, "error", {"error": asset.strict_error}, now,
                            )
                        elif not is_canonical:
                            self._quarantine(
                                connection, import_run_id, paper_id, asset.relative_path,
                                "duplicate_legacy_json", "warning",
                                {"canonical": canonical_json.relative_path if canonical_json else None}, now,
                            )
                        if asset.payload is not None:
                            asset_missing = sorted(
                                field for field in _LEGACY_FIELDS if field not in asset.payload
                            )
                            if asset_missing:
                                self._quarantine(
                                    connection, import_run_id, paper_id, asset.relative_path,
                                    "legacy_json_missing_fields", "warning",
                                    {
                                        "missing_fields": asset_missing,
                                        "field_count": len(asset.payload),
                                        "canonical": is_canonical,
                                    },
                                    now,
                                )
                    if canonical_json is None or canonical_json.payload is None:
                        self._quarantine(
                            connection, import_run_id, paper_id, None,
                            "canonical_json_missing", "error", {"legacy_id": legacy_id}, now,
                        )
                        connection.execute(
                            "UPDATE lab_paper SET lifecycle_status='quarantined',updated_at=? WHERE paper_id=?",
                            (now, paper_id),
                        )
                    else:
                        payload = canonical_json.payload
                        missing = sorted(field for field in _LEGACY_FIELDS if field not in payload)
                        run_id = stable_public_id("labrun", version_id, "legacy-import-v1")
                        # A complete historical JSON record is still imported evidence,
                        # not an independent verification decision.
                        run_status = "awaiting_review"
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO reading_run(
                                run_id,paper_version_id,workflow_version,status,attempt,
                                resume_from_phase_key,input_revision_sha256,error_code,
                                error_detail,created_at,updated_at
                            ) VALUES(?,?,'paper-reading/v1',?,1,NULL,?,NULL,NULL,?,?)
                            """,
                            (run_id, version_id, run_status, canonical_json.digest, now, now),
                        )
                        artifact_status = "quarantined" if missing else "validated"
                        result_id = stable_public_id("labresult", run_id, canonical_json.digest)
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO reading_result(
                                result_id,run_id,phase_id,result_kind,schema_version,payload_json,
                                evidence_locator_json,artifact_sha256,artifact_status,created_at
                            ) VALUES(?, ?, NULL, 'legacy_record', 'proj2-json/v1', ?, ?, ?, ?, ?)
                            """,
                            (
                                result_id,
                                run_id,
                                _canonical_json(payload),
                                _canonical_json({"source": _source_urn(canonical_json.relative_path)}),
                                canonical_json.digest,
                                artifact_status,
                                now,
                            ),
                        )
                        connection.execute(
                            "UPDATE legacy_record_map SET target_id=? WHERE import_run_id=? AND legacy_kind='json' AND legacy_key=?",
                            (result_id, import_run_id, canonical_json.relative_path),
                        )
                        imported["reading_runs"] += 1
                        imported["reading_results"] += 1
                        if missing:
                            self._quarantine(
                                connection, import_run_id, paper_id, canonical_json.relative_path,
                                "legacy_json_missing_fields", "warning",
                                {"missing_fields": missing, "field_count": len(payload)}, now,
                            )
                        for layer, tag_text in _extract_tags(payload):
                            review_status = "approved" if tag_text in all_vocab_tags else "queued"
                            if review_status == "queued":
                                unknown_tags.add((layer, tag_text))
                                unknown_tag_occurrences += 1
                            tag_id = self._upsert_tag(
                                connection, layer, tag_text, review_status, "legacy_record", now,
                            )
                            connection.execute(
                                "INSERT OR IGNORE INTO paper_tag(paper_id,tag_id,provenance_urn,created_at) VALUES(?,?,?,?)",
                                (paper_id, tag_id, _source_urn(canonical_json.relative_path), now),
                            )

                    declared_note = str(row.get("notes_path") or "") or None
                    note_candidates = notes_by_id.get(legacy_id, [])
                    canonical_note = _canonical_note_asset(note_candidates, declared_note, self.source_root)
                    for asset in note_candidates:
                        is_canonical = asset is canonical_note
                        note_id = stable_public_id("labnote", paper_id, asset.digest)
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO lab_note(
                                note_id,paper_id,content_sha256,bytes,source_location_urn,
                                snapshot_relative_path,note_kind,template_status,is_canonical,created_at
                            ) VALUES(?,?,?,?,?,?,'legacy',?,?,?)
                            """,
                            (
                                note_id, paper_id, asset.digest, asset.size,
                                _source_urn(asset.relative_path), asset.relative_path,
                                asset.template_status, int(is_canonical), now,
                            ),
                        )
                        self._map(
                            connection, import_run_id, "note", asset.relative_path,
                            asset.relative_path, asset.digest, "lab_note", note_id,
                            "imported" if is_canonical else "superseded",
                            "equivalent" if is_canonical else "legacy_defect_preserved",
                            {"canonical": is_canonical, "template_status": asset.template_status}, now,
                        )
                        imported["notes"] += 1
                        if not is_canonical:
                            self._quarantine(
                                connection, import_run_id, paper_id, asset.relative_path,
                                "duplicate_legacy_note", "warning",
                                {"canonical": canonical_note.relative_path if canonical_note else None}, now,
                            )
                        if asset.template_status != "six_section":
                            self._quarantine(
                                connection, import_run_id, paper_id, asset.relative_path,
                                "legacy_note_template", "info",
                                {"template_status": asset.template_status}, now,
                            )
                    if canonical_note is None:
                        self._quarantine(
                            connection, import_run_id, paper_id, None,
                            "canonical_note_missing", "error", {"legacy_id": legacy_id}, now,
                        )
                    if not declared_note:
                        self._quarantine(
                            connection, import_run_id, paper_id, None,
                            "legacy_notes_path_missing", "warning",
                            {"legacy_id": legacy_id, "repaired_from": canonical_note.relative_path if canonical_note else None}, now,
                        )
                    elif not self._declared_exists(declared_note):
                        self._quarantine(
                            connection, import_run_id, paper_id, declared_note,
                            "legacy_notes_path_broken", "warning",
                            {"legacy_id": legacy_id, "repaired_from": canonical_note.relative_path if canonical_note else None}, now,
                        )

                self._record_unmapped_assets(
                    connection, import_run_id, json_assets, note_assets,
                    set(str(row["id"]) for row in rows), now,
                )
                component_counts = self._import_components(connection, import_run_id, now)
                imported.update(component_counts)
                imported["pdf_assets"] = len(pdfs)
                imported["json_assets"] = len(json_assets)
                imported["note_assets"] = len(note_assets)
                imported["unknown_unique_tags"] = len(unknown_tags)

                quarantine_rows = connection.execute(
                    "SELECT issue_code,count(*) AS n FROM quarantine_record WHERE import_run_id=? GROUP BY issue_code",
                    (import_run_id,),
                ).fetchall()
                quarantines.update({row["issue_code"]: int(row["n"]) for row in quarantine_rows})

                source_counts = {
                    "db_rows": len(rows),
                    "pdf": len(pdfs),
                    "json": len(json_assets),
                    "notes": len(note_assets),
                }
                report_values = {
                    "status": "PASS",
                    "import_run_id": import_run_id,
                    "source_manifest_sha256": before_hash,
                    "source_unchanged": True,
                    "source_counts": source_counts,
                    "imported_counts": dict(sorted(imported.items())),
                    "quarantine_counts": dict(sorted(quarantines.items())),
                    "unknown_tag_count": unknown_tag_occurrences,
                    "local_pdf_routes_repaired": repaired_routes,
                    "snapshot_root": str(self.snapshot_root),
                    "database_path": str(self.settings.paper_lab_database_path),
                }
                connection.execute(
                    "UPDATE legacy_import_run SET status='completed',finished_at=?,summary_json=? WHERE import_run_id=?",
                    (utc_now(), _canonical_json(report_values), import_run_id),
                )

        after_hash, after_entries = _source_manifest(self.source_root)
        unchanged = before_hash == after_hash and before_entries == after_entries
        if not unchanged:
            raise RuntimeError("reference/proj2 changed during import")

        report_values["source_unchanged"] = unchanged
        with paper_lab_connection(self.settings) as connection:
            failures = self._managed_integrity_failures(connection, import_run_id)
            if failures:
                return self._record_managed_integrity_failures(
                    connection,
                    import_run_id,
                    report_values,
                    failures,
                )
            with immediate_transaction(connection):
                connection.execute(
                    "UPDATE legacy_import_run SET summary_json=? WHERE import_run_id=?",
                    (_canonical_json(report_values), import_run_id),
                )
        return LegacyImportReport(**report_values)

    def _managed_integrity_failures(
        self,
        connection: sqlite3.Connection,
        import_run_id: str,
    ) -> list[_ManagedIntegrityFailure]:
        assets: list[tuple[str, Path, sqlite3.Row]] = []
        pdf_rows = connection.execute(
            """
            SELECT paper.paper_id,map.source_relative_path,
                   version.asset_relative_path AS managed_relative_path,
                   version.content_sha256,version.bytes
            FROM legacy_record_map AS map
            JOIN lab_paper_version AS version ON version.paper_version_id=map.target_id
            JOIN lab_paper AS paper ON paper.paper_id=version.paper_id
            WHERE map.import_run_id=? AND map.legacy_kind='pdf'
              AND map.target_kind='lab_paper_version' AND map.target_id IS NOT NULL
            ORDER BY map.source_relative_path
            """,
            (import_run_id,),
        ).fetchall()
        assets.extend(("pdf", self.settings.paper_lab_asset_root, row) for row in pdf_rows)
        note_rows = connection.execute(
            """
            SELECT note.paper_id,map.source_relative_path,
                   note.snapshot_relative_path AS managed_relative_path,
                   note.content_sha256,note.bytes
            FROM legacy_record_map AS map
            JOIN lab_note AS note ON note.note_id=map.target_id
            WHERE map.import_run_id=? AND map.legacy_kind='note'
              AND map.target_kind='lab_note' AND map.target_id IS NOT NULL
            ORDER BY map.source_relative_path
            """,
            (import_run_id,),
        ).fetchall()
        assets.extend(("note", self.snapshot_root, row) for row in note_rows)

        failures: list[_ManagedIntegrityFailure] = []
        for asset_kind, root, row in assets:
            try:
                verify_frozen_asset(
                    root,
                    row["managed_relative_path"],
                    expected_sha256=row["content_sha256"],
                    expected_bytes=int(row["bytes"]),
                    label=f"legacy {asset_kind} {row['source_relative_path']}",
                )
            except ManagedAssetError as error:
                failures.append(
                    _ManagedIntegrityFailure(
                        asset_kind=asset_kind,
                        paper_id=row["paper_id"],
                        source_relative_path=row["source_relative_path"],
                        managed_relative_path=row["managed_relative_path"],
                        expected_sha256=row["content_sha256"],
                        expected_bytes=int(row["bytes"]),
                        error_code=error.code,
                        error_detail=str(error)[:1000],
                    )
                )
        return failures

    def _record_managed_integrity_failures(
        self,
        connection: sqlite3.Connection,
        import_run_id: str,
        previous_report: dict[str, object],
        failures: list[_ManagedIntegrityFailure],
    ) -> LegacyImportReport:
        now = utc_now()
        report_values = dict(previous_report)
        with immediate_transaction(connection):
            for failure in failures:
                issue_code = f"managed_{failure.asset_kind}_asset_integrity_error"
                self._quarantine(
                    connection,
                    import_run_id,
                    failure.paper_id,
                    failure.source_relative_path,
                    issue_code,
                    "error",
                    {
                        "managed_relative_path": failure.managed_relative_path,
                        "expected_sha256": failure.expected_sha256,
                        "expected_bytes": failure.expected_bytes,
                        "integrity_error_code": failure.error_code,
                        "integrity_error_detail": failure.error_detail,
                    },
                    now,
                )
                if failure.paper_id is not None:
                    connection.execute(
                        """
                        UPDATE lab_paper SET lifecycle_status='quarantined',updated_at=?
                        WHERE paper_id=?
                        """,
                        (now, failure.paper_id),
                    )
            quarantine_rows = connection.execute(
                """
                SELECT issue_code,count(*) AS n FROM quarantine_record
                WHERE import_run_id=? GROUP BY issue_code
                """,
                (import_run_id,),
            ).fetchall()
            report_values["status"] = "ERROR"
            report_values["quarantine_counts"] = {
                row["issue_code"]: int(row["n"]) for row in quarantine_rows
            }
            report_values["source_unchanged"] = True
            connection.execute(
                """
                UPDATE legacy_import_run
                SET status='failed',finished_at=?,summary_json=?
                WHERE import_run_id=?
                """,
                (now, _canonical_json(report_values), import_run_id),
            )
        return LegacyImportReport(**report_values)

    def _declared_exists(self, declared: str) -> bool:
        try:
            relative = normalized_relative_path(declared)
        except ValueError:
            return False
        candidate = self.source_root / Path(relative)
        return candidate.is_file() and _is_relative_to(candidate.resolve(), self.source_root)

    @staticmethod
    def _bootstrap_workflow(connection: sqlite3.Connection, now: str) -> None:
        phases = (
            ("problem", "问题与定位"),
            ("method", "方法与架构"),
            ("experiment", "实验、偏差与复现"),
            ("synthesis", "综合结论与批判"),
        )
        contract = {"phases": [key for key, _name in phases], "evidence_required": True}
        connection.execute(
            """
            INSERT OR IGNORE INTO reading_workflow(
                workflow_version,description,phase_contract_json,active,created_at
            ) VALUES('paper-reading/v1','四阶段量化论文精读协议',?,1,?)
            """,
            (_canonical_json(contract), now),
        )
        for ordinal, (key, name) in enumerate(phases, start=1):
            phase_id = stable_public_id("labphase", "paper-reading/v1", key)
            connection.execute(
                """
                INSERT OR IGNORE INTO reading_phase(
                    phase_id,workflow_version,phase_key,ordinal,display_name,required
                ) VALUES(?,'paper-reading/v1',?,?,?,1)
                """,
                (phase_id, key, ordinal, name),
            )

    @staticmethod
    def _upsert_tag(
        connection: sqlite3.Connection,
        layer: str,
        tag_text: str,
        review_status: str,
        source_kind: str,
        now: str,
    ) -> str:
        tag_id = stable_public_id("labtag", layer, tag_text)
        connection.execute(
            """
            INSERT INTO tag_vocabulary(
                tag_id,layer,tag_text,review_status,canonical_tag_id,source_kind,created_at
            ) VALUES(?,?,?,?,NULL,?,?)
            ON CONFLICT(layer,tag_text) DO UPDATE SET
                review_status=CASE
                    WHEN tag_vocabulary.review_status='approved' THEN 'approved'
                    ELSE excluded.review_status
                END
            """,
            (tag_id, layer, tag_text, review_status, source_kind, now),
        )
        return tag_id

    @staticmethod
    def _map(
        connection: sqlite3.Connection,
        import_run_id: str,
        legacy_kind: str,
        legacy_key: str,
        source_relative_path: str | None,
        source_sha256: str | None,
        target_kind: str,
        target_id: str | None,
        import_status: str,
        difference_kind: str,
        difference: object,
        now: str,
    ) -> None:
        map_id = stable_public_id(
            "labmap", import_run_id, legacy_kind, legacy_key, source_relative_path or "",
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO legacy_record_map(
                legacy_record_map_id,import_run_id,legacy_kind,legacy_key,
                source_relative_path,source_sha256,target_kind,target_id,import_status,
                difference_kind,difference_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                map_id, import_run_id, legacy_kind, legacy_key, source_relative_path,
                source_sha256, target_kind, target_id, import_status, difference_kind,
                _canonical_json(difference), now,
            ),
        )

    @staticmethod
    def _quarantine(
        connection: sqlite3.Connection,
        import_run_id: str,
        paper_id: str | None,
        source_relative_path: str | None,
        issue_code: str,
        severity: str,
        evidence: object,
        now: str,
    ) -> None:
        quarantine_id = stable_public_id(
            "labq", import_run_id, paper_id or "", source_relative_path or "", issue_code,
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO quarantine_record(
                quarantine_id,import_run_id,paper_id,source_relative_path,issue_code,
                severity,evidence_json,disposition_status,created_at
            ) VALUES(?,?,?,?,?,?,?,'accepted_legacy',?)
            """,
            (
                quarantine_id, import_run_id, paper_id, source_relative_path,
                issue_code, severity, _canonical_json(evidence), now,
            ),
        )

    def _record_unmapped_assets(
        self,
        connection: sqlite3.Connection,
        import_run_id: str,
        json_assets: list[_JsonAsset],
        note_assets: list[_NoteAsset],
        db_ids: set[str],
        now: str,
    ) -> None:
        for kind, assets in (("json", json_assets), ("note", note_assets)):
            for item in assets:
                if item.filename_id in db_ids:
                    continue
                self._map(
                    connection, import_run_id, kind, item.relative_path,
                    item.relative_path, item.digest, "quarantine_record", None,
                    "unmapped", "legacy_defect_preserved",
                    {"filename_id": item.filename_id, "reason": "no_legacy_db_row"}, now,
                )
                self._quarantine(
                    connection, import_run_id, None, item.relative_path,
                    f"unmapped_legacy_{kind}", "warning",
                    {"filename_id": item.filename_id}, now,
                )
                if kind == "json" and item.payload is not None:
                    missing = sorted(field for field in _LEGACY_FIELDS if field not in item.payload)
                    if missing:
                        self._quarantine(
                            connection, import_run_id, None, item.relative_path,
                            "legacy_json_missing_fields", "warning",
                            {
                                "missing_fields": missing,
                                "field_count": len(item.payload),
                                "canonical": False,
                            },
                            now,
                        )

    def _import_components(
        self,
        connection: sqlite3.Connection,
        import_run_id: str,
        now: str,
    ) -> Counter[str]:
        counts: Counter[str] = Counter()
        tag_path = self.source_root / "data" / "tag_components.json"
        tag_payload_bytes = tag_path.read_bytes()
        tag_digest = _sha256_bytes(tag_payload_bytes)
        tag_payload = json.loads(tag_payload_bytes.decode("utf-8-sig"))
        for raw in tag_payload.get("components", []):
            legacy_component_id = str(raw["component_id"])
            component_id = stable_public_id("labcomponent", "tag", legacy_component_id)
            connection.execute(
                """
                INSERT OR IGNORE INTO concept_component(
                    component_id,component_kind,legacy_component_id,layer,display_name,
                    version,automatic_payload_json,curated_payload_json,
                    source_revision_sha256,status,created_at
                ) VALUES(?,'tag_component',?,?,?,1,?,'{}',?,'imported',?)
                """,
                (
                    component_id, legacy_component_id, str(raw.get("layer") or "unknown"),
                    str(raw.get("display_name") or legacy_component_id),
                    _canonical_json(raw), tag_digest, now,
                ),
            )
            self._map(
                connection, import_run_id, "tag_component", legacy_component_id,
                "data/tag_components.json", tag_digest, "concept_component", component_id,
                "imported", "legacy_defect_preserved",
                {"legacy_coverage_max_id": 86, "rebuild_required": True}, now,
            )
            counts["tag_components"] += 1
            for reference in raw.get("references", []):
                legacy_id = str(reference.get("paper_id") or "")
                paper = connection.execute(
                    "SELECT paper_id FROM lab_paper WHERE legacy_id=?", (legacy_id,)
                ).fetchone()
                if paper is None:
                    continue
                evidence_id = stable_public_id(
                    "labevidence", component_id, paper["paper_id"], "legacy_reference",
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO component_evidence(
                        component_evidence_id,component_id,paper_id,result_id,evidence_kind,
                        evidence_locator_json,provenance_urn,created_at
                    ) VALUES(?,?,?,NULL,'legacy_reference',?,?,?)
                    """,
                    (
                        evidence_id, component_id, paper["paper_id"],
                        _canonical_json(reference), _source_urn("data/tag_components.json"), now,
                    ),
                )
                counts["component_evidence"] += 1

        block_path = self.source_root / "data" / "concept_blocks.json"
        block_bytes = block_path.read_bytes()
        block_digest = _sha256_bytes(block_bytes)
        block_payload = json.loads(block_bytes.decode("utf-8-sig"))
        for raw in block_payload.get("blocks", []):
            legacy_component_id = str(raw["block_id"])
            component_id = stable_public_id("labcomponent", "block", legacy_component_id)
            curated = {
                key: raw.get(key)
                for key in ("one_liner", "my_comment", "notes")
                if raw.get(key) not in (None, "")
            }
            automatic = {
                key: value
                for key, value in raw.items()
                if key not in {"one_liner", "my_comment", "notes"}
            }
            status = "stub" if raw.get("status") == "stub" else "imported"
            connection.execute(
                """
                INSERT OR IGNORE INTO concept_component(
                    component_id,component_kind,legacy_component_id,layer,display_name,
                    version,automatic_payload_json,curated_payload_json,
                    source_revision_sha256,status,created_at
                ) VALUES(?,'concept_block',?,?,?,1,?,?,?,?,?)
                """,
                (
                    component_id, legacy_component_id, str(raw.get("layer") or "unknown"),
                    str(raw.get("display_name") or legacy_component_id),
                    _canonical_json(automatic), _canonical_json(curated),
                    block_digest, status, now,
                ),
            )
            self._map(
                connection, import_run_id, "concept_block", legacy_component_id,
                "data/concept_blocks.json", block_digest, "concept_component", component_id,
                "imported", "legacy_defect_preserved",
                {"curation_separated": True, "builder_overwrite_prevented": True}, now,
            )
            counts["concept_blocks"] += 1

        rules_path = self.source_root / "data" / "compatibility_rules.json"
        rules_bytes = rules_path.read_bytes()
        rules_digest = _sha256_bytes(rules_bytes)
        rules = json.loads(rules_bytes.decode("utf-8-sig"))
        for output_type, allowed in sorted(rules.get("type_compatibility", {}).items()):
            legacy_rule_id = f"type::{output_type}"
            rule_id = stable_public_id("labrule", "legacy-v1", legacy_rule_id)
            connection.execute(
                """
                INSERT OR IGNORE INTO compatibility_rule(
                    compatibility_rule_id,rule_set_version,legacy_rule_id,severity,
                    rule_json,source_revision_sha256,active,created_at
                ) VALUES(?,'legacy-v1',?,'mapping',?,?,1,?)
                """,
                (rule_id, legacy_rule_id, _canonical_json({"output": output_type, "allowed": allowed}), rules_digest, now),
            )
            self._map(
                connection, import_run_id, "compatibility_rule", legacy_rule_id,
                "data/compatibility_rules.json", rules_digest, "compatibility_rule", rule_id,
                "imported", "equivalent", {}, now,
            )
            counts["compatibility_rules"] += 1
        for raw in rules.get("constraints", []):
            legacy_rule_id = str(raw["id"])
            rule_id = stable_public_id("labrule", "legacy-v1", legacy_rule_id)
            connection.execute(
                """
                INSERT OR IGNORE INTO compatibility_rule(
                    compatibility_rule_id,rule_set_version,legacy_rule_id,severity,
                    rule_json,source_revision_sha256,active,created_at
                ) VALUES(?,'legacy-v1',?,?,?,?,1,?)
                """,
                (rule_id, legacy_rule_id, str(raw.get("severity") or "soft"), _canonical_json(raw), rules_digest, now),
            )
            self._map(
                connection, import_run_id, "compatibility_rule", legacy_rule_id,
                "data/compatibility_rules.json", rules_digest, "compatibility_rule", rule_id,
                "imported", "intentional_improvement",
                {"frontend_and_backend_share_rule": True}, now,
            )
            counts["compatibility_rules"] += 1
        return counts
